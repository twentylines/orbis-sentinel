"""On-demand, bounded Linux machine telemetry; no collection thread is started.

A null value means the observation is unavailable or needs another sample. Rates
are bytes per second; memory and filesystem values are bytes; temperature is °C.
"""

import copy
import math
import os
from pathlib import Path
import re
import sys
import threading
import time

_LIMIT = 1024 * 1024
_COUNTER_MAX = 2 ** 64 - 1
_SAFE_INTEGER = 2 ** 53 - 1
_MAX_LOGICAL_CPUS = 256


def _finite(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _read(path):
    try:
        with open(path, "r", encoding="ascii") as stream:
            data = stream.read(_LIMIT + 1)
        return data if len(data) <= _LIMIT else None
    except (OSError, UnicodeError, ValueError):
        return None


def _cpu_fields(fields):
    selected = fields[:8]
    if len(selected) < 4 or any(not re.fullmatch(r"[0-9]{1,20}", field) for field in selected):
        return None
    values = tuple(int(value) for value in selected)
    if any(value > _COUNTER_MAX for value in values):
        return None
    return values, sum(values[3:5])


def _cpu(text):
    try:
        fields = text.splitlines()[0].split()
        if fields[0] != "cpu" or len(fields) < 5:
            return None
        values = [int(v) for v in fields[1:]]
        if any(not field.isdigit() for field in fields[1:]) or any(not 0 <= v <= _COUNTER_MAX for v in values):
            return None
        # guest counters are already included in user and nice.
        values = values[:8]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return tuple(values), idle
    except (AttributeError, IndexError, ValueError):
        return None


def _cpu_percent(before, current):
    if before is None or current is None:
        return None
    previous, previous_idle = before
    values, current_idle = current
    elapsed = sum(values) - sum(previous)
    idle = current_idle - previous_idle
    if len(values) == len(previous) and all(a >= b for a, b in zip(values, previous)) and elapsed > 0 and 0 <= idle <= elapsed:
        return 100.0 * ((elapsed - idle) / elapsed)
    return None


def _logical_cpus(text):
    if text is None:
        return {}
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r"cpu[0-9]+", fields[0]):
            continue
        if len(fields[0]) > 10:
            return {}
        index = int(fields[0][3:])
        counter = _cpu_fields(fields[1:])
        if counter is None or index in result or len(result) >= _MAX_LOGICAL_CPUS:
            return {}
        result[index] = counter
    return result


def _swap(text):
    if text is None:
        return None
    values = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("SwapTotal:", "SwapFree:"):
            continue
        if len(parts) != 3 or parts[2] != "kB" or parts[0] in values or not re.fullmatch(r"[0-9]{1,16}", parts[1]):
            return None
        values[parts[0]] = int(parts[1]) * 1024
    total, free = values.get("SwapTotal:"), values.get("SwapFree:")
    return ({"swapTotalBytes": total, "swapFreeBytes": free}
            if total is not None and free is not None and 0 <= free <= total <= _SAFE_INTEGER else None)


def _cpu_information(text):
    if text is None:
        return None
    model_line = re.search(r"^(?:model name|Processor)[ \t]*:[ \t]*(\S[^\r\n]*)", text, re.MULTILINE)
    labels = re.findall(r"^cpu MHz[ \t]*:[ \t]*([^\r\n]*)", text, re.MULTILINE)
    if not model_line or not labels:
        return None
    model = " ".join(model_line[1].split())[:200]
    if (not model or any(ord(character) < 32 or ord(character) == 127 for character in model)
            or any(not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,12})?", value.strip()) for value in labels)):
        return None
    clocks = [float(value) for value in labels]
    if len(clocks) > _MAX_LOGICAL_CPUS or any(not 0 < value <= 100_000 for value in clocks):
        return None
    return {"model": model, "reportedClockGHz": sum(clocks) / len(clocks) / 1000}


def _uptime(text):
    raw = (text or "").split()
    if not raw or not re.fullmatch(r"[0-9]{1,16}(?:\.[0-9]{1,12})?", raw[0]):
        return None
    value = float(raw[0])
    return value if value <= _SAFE_INTEGER else None


def _memory(text):
    try:
        values = {}
        for line in text.splitlines():
            parts = line.split()
            if parts and parts[0] in ("MemTotal:", "MemAvailable:"):
                if len(parts) != 3 or parts[2] != "kB" or parts[0] in values or not parts[1].isdigit():
                    return None
                values[parts[0]] = int(parts[1]) * 1024
        total, available = values["MemTotal:"], values["MemAvailable:"]
        if not 0 < total <= _COUNTER_MAX or not 0 <= available <= total:
            return None
        return {"totalBytes": total, "availableBytes": available}
    except (AttributeError, KeyError, ValueError):
        return None


def _network(text):
    try:
        lines = text.splitlines()
        if len(lines) < 2 or "Inter-" not in lines[0] or "bytes" not in lines[1]:
            return None
        result = {}
        for line in lines[2:]:
            name, values = line.rsplit(":", 1)
            name = name.strip()
            fields = values.split()
            if not name or len(name) > 256 or '\x00' in name or name in result or len(result) >= 4096 or len(fields) < 16:
                return None
            if any(not field.isdigit() or int(field) > _COUNTER_MAX for field in fields[:16]):
                return None
            rx, tx = int(fields[0]), int(fields[8])
            if rx < 0 or tx < 0:
                return None
            result[name] = (rx, tx)
        return result
    except (AttributeError, ValueError, IndexError):
        return None


class TelemetrySampler:
    """Collect once per interval and share a snapshot among concurrent readers.

    proc_root and thermal_root enable isolated fixtures. statvfs and monotonic
    are injectable providers. Linux collection is disabled on other platforms.
    """

    def __init__(self, paths=("/",), interval=1.0, *, proc_root="/proc",
                 thermal_root="/sys/class/thermal", max_thermal=16,
                 monotonic=time.monotonic, statvfs=os.statvfs, wall_time=time.time, platform=None):
        if not _finite(interval) or not 0.1 <= interval <= 3600:
            raise ValueError("interval must be between 0.1 and 3600 seconds")
        if type(max_thermal) is not int or not 0 <= max_thermal <= 256:
            raise ValueError("max_thermal must be between 0 and 256")
        self.paths = tuple(os.fspath(path) for path in paths)
        if len(self.paths) > 64 or len(set(self.paths)) != len(self.paths) or any(
                not isinstance(path, str) or not os.path.isabs(path) or len(path) > 4096 or '\x00' in path for path in self.paths):
            raise ValueError("paths must be at most 64 distinct absolute paths")
        self.interval, self.proc, self.thermal = interval, Path(proc_root), Path(thermal_root)
        self.max_thermal, self.clock, self.statvfs = max_thermal, monotonic, statvfs
        self.wall_time = wall_time
        self.linux = (sys.platform if platform is None else platform).startswith("linux")
        self.lock = threading.Lock()
        self.last_time = self.cache = self.cpu_base = self.net_base = None
        self.system_cache = self.system_cpu_base = None
        self.logical_base = {}

    def sample(self):
        return self.samples()[0]

    def samples(self):
        """Return paired coarse and complete whole-host snapshots of one observation."""
        with self.lock:
            now = self.clock()
            if not _finite(now):
                raise ValueError("monotonic clock must return a finite number")
            if self.last_time is not None and now >= self.last_time and now - self.last_time < self.interval:
                return copy.deepcopy((self.cache, self.system_cache))
            # A backwards clock cannot produce a valid interval against old baselines.
            if self.last_time is not None and now < self.last_time:
                self.cpu_base = self.net_base = None
            wall_time = self.wall_time()
            if not _finite(wall_time) or not 0 <= wall_time <= (2 ** 53 - 1) / 1000:
                raise ValueError("wall clock must return a valid timestamp")
            result, system = self._collect(now)
            result["sampledAt"] = int(wall_time * 1000)
            if system is not None:
                system["sampledAt"] = result["sampledAt"]
            self.last_time, self.cache, self.system_cache = now, result, system
            return copy.deepcopy((result, system))

    def _host_system(self, now, stat, meminfo, current, memory):
        logical = _logical_cpus(stat)
        previous, self.logical_base = self.logical_base, logical
        before, self.system_cpu_base = self.system_cpu_base, current
        aggregate = _cpu_percent(before, current)
        if (self.last_time is None or not 0 < now - self.last_time <= 30
                or not logical or logical.keys() != previous.keys() or aggregate is None or not memory
                or memory["totalBytes"] > _SAFE_INTEGER):
            return None
        cores = [_cpu_percent(previous[index], logical[index]) for index in sorted(logical)]
        if any(value is None for value in cores):
            return None
        swap = _swap(meminfo)
        info = _cpu_information(_read(self.proc / "cpuinfo"))
        uptime = _uptime(_read(self.proc / "uptime"))
        if swap is None or info is None or uptime is None:
            return None
        return {"cpu": {**info, "totalPercent": aggregate, "perCorePercent": cores, "uptimeSeconds": uptime},
                "memory": {**memory, **swap}}

    def _collect(self, now):
        result = {"schema": "orbis-sentinel.telemetry.v1", "cpuPercent": None,
                  "memory": None, "network": None, "filesystems": {path: None for path in self.paths},
                  "thermal": None, "perAppCpu": None, "gpu": None}
        if not self.linux:
            return result, None
        stat = _read(self.proc / "stat")
        current = _cpu(stat)
        if current is not None:
            result["cpuPercent"] = _cpu_percent(self.cpu_base, current)
            self.cpu_base = current
        meminfo = _read(self.proc / "meminfo")
        result["memory"] = _memory(meminfo)
        system = self._host_system(now, stat, meminfo, current, result["memory"])
        network = _network(_read(self.proc / "net/dev"))
        if network is not None:
            result["network"] = {}
            for name, (rx, tx) in network.items():
                item = {"receivedBytes": rx, "transmittedBytes": tx,
                        "receiveBytesPerSecond": None, "transmitBytesPerSecond": None}
                if self.net_base is not None:
                    old_time, old = self.net_base
                    if name in old and now > old_time and rx >= old[name][0] and tx >= old[name][1]:
                        try:
                            rates = ((rx - old[name][0]) / (now - old_time), (tx - old[name][1]) / (now - old_time))
                            if all(math.isfinite(rate) for rate in rates):
                                item["receiveBytesPerSecond"], item["transmitBytesPerSecond"] = rates
                        except OverflowError:
                            pass
                result["network"][name] = item
            self.net_base = (now, network)
        for path in self.paths:
            try:
                stat = self.statvfs(path)
                size, free, available = (stat.f_blocks * stat.f_frsize, stat.f_bfree * stat.f_frsize, stat.f_bavail * stat.f_frsize)
                result["filesystems"][path] = ({"totalBytes": size, "freeBytes": free, "availableBytes": available}
                    if all(type(v) is int and 0 <= v <= _COUNTER_MAX for v in (size, free, available)) and available <= free <= size else None)
            except (OSError, ValueError, OverflowError, TypeError, AttributeError):
                result["filesystems"][path] = None
        if self.max_thermal:
            try:
                zones = []
                with os.scandir(self.thermal) as entries:
                    for index, entry in enumerate(entries):
                        if index >= 4096:
                            raise OSError("thermal directory exceeds scan limit")
                        if entry.name.startswith("thermal_zone") and entry.name[12:].isdigit():
                            zones.append(entry.name)
                            if len(zones) >= self.max_thermal:
                                break
                result["thermal"] = {}
                for zone in sorted(zones):
                    try:
                        raw = _read(self.thermal / zone / "temp")
                        value = int(raw.strip()) / 1000
                        result["thermal"][zone] = value if math.isfinite(value) else None
                    except (AttributeError, ValueError, OverflowError):
                        result["thermal"][zone] = None
            except OSError:
                pass
        return result, system
