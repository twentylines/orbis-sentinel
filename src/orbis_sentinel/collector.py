"""Keep filesystem and hardware reads out of the API process."""

import copy
import json
import math
import multiprocessing
import socket
import threading
import time

from .telemetry import TelemetrySampler

_MAX_MESSAGE = 64 * 1024
_MAX_SAFE_INTEGER = 2 ** 53 - 1


def _valid_system(sample, sampled_at):
    if (type(sample) is not dict or set(sample) != {"sampledAt", "cpu", "memory"}
            or type(sample["sampledAt"]) is not int or not 0 < sample["sampledAt"] <= _MAX_SAFE_INTEGER
            or type(sampled_at) is not int or sample["sampledAt"] != sampled_at):
        return False
    cpu, memory = sample["cpu"], sample["memory"]
    if (type(cpu) is not dict or set(cpu) != {"model", "reportedClockGHz", "totalPercent", "perCorePercent", "uptimeSeconds"}
            or type(memory) is not dict or set(memory) != {"totalBytes", "availableBytes", "swapTotalBytes", "swapFreeBytes"}):
        return False

    def number(value, limit):
        return type(value) in (int, float) and 0 <= value <= limit

    model, cores, clock = cpu["model"], cpu["perCorePercent"], cpu["reportedClockGHz"]
    return (type(model) is str and 0 < len(model) <= 200 and model == model.strip()
            and all(ord(character) >= 32 and ord(character) != 127 for character in model)
            and number(clock, 100) and clock > 0 and number(cpu["totalPercent"], 100)
            and number(cpu["uptimeSeconds"], _MAX_SAFE_INTEGER)
            and type(cores) is list and 0 < len(cores) <= 256 and all(number(core, 100) for core in cores)
            and all(type(value) is int and 0 <= value <= _MAX_SAFE_INTEGER for value in memory.values())
            and 0 < memory["totalBytes"] and memory["availableBytes"] <= memory["totalBytes"]
            and memory["swapFreeBytes"] <= memory["swapTotalBytes"])


def _sample_worker(output, paths, interval):
    sampler = TelemetrySampler(paths, interval)
    output.setblocking(False)
    try:
        while True:
            started = time.monotonic()
            try:
                coarse, system = sampler.samples()
                # Cache hits retain the underlying monotonic observation time.
                packet = {"observed": sampler.last_time, "sample": coarse}
                if system is not None:
                    packet["system"] = system
                encoded = json.dumps(packet, allow_nan=False, separators=(",", ":")).encode("utf-8")
                if len(encoded) > _MAX_MESSAGE and system is not None:
                    # A large rich record must never crowd the existing feed out of its frame.
                    del packet["system"]
                    encoded = json.dumps(packet, allow_nan=False, separators=(",", ":")).encode("utf-8")
                if len(encoded) <= _MAX_MESSAGE:
                    output.send(encoded)
            except (OSError, ValueError, TypeError):
                # Dropped observations expire; readers never wait for the worker.
                pass
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
    finally:
        output.close()


class TelemetryCollector:
    """An owned read-only child with a nonblocking, freshness-labelled cache.

    maintain() is called by the service loop, never by HTTP request handlers.
    A stalled child is terminated before replacement; repeated failures stop
    automatic restarts. No privileged job or lifecycle command runs here.
    """

    schema = "orbis-sentinel.telemetry.v1"

    def __init__(self, paths=("/",), interval=1.0, *, max_age=5.0,
                 context=None, worker=_sample_worker, monotonic=time.monotonic):
        checked = TelemetrySampler(paths, interval)
        if isinstance(max_age, bool) or not isinstance(max_age, (int, float)) or not math.isfinite(max_age) or not interval * 2 <= max_age <= 3600:
            raise ValueError("max_age must be between twice the interval and 3600 seconds")
        self.paths, self.interval, self.max_age = checked.paths, interval, max_age
        self.context = context or multiprocessing.get_context("spawn")
        self.worker, self.clock = worker, monotonic
        self.lock = threading.Lock()
        self.process = self.receiver = None
        self.sample = self.system_sample = self.observed = self.started = None
        self.attempts = []
        self.closed = False
        self.failed = False
        self.stopping_at = None

    def start(self):
        with self.lock:
            if self.closed or self.process is not None:
                raise RuntimeError("collector is already started or closed")
            self._start(self.clock())

    def _start(self, now):
        receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        receiver.setblocking(False)
        process = self.context.Process(target=self.worker, args=(sender, self.paths, self.interval),
                                       name="orbis-sentinel-telemetry", daemon=True)
        try:
            process.start()
        except BaseException:
            receiver.close()
            sender.close()
            process.close()
            raise
        sender.close()
        self.receiver, self.process = receiver, process
        self.started = now
        self.stopping_at = None
        self.observed = self.sample = self.system_sample = None
        self.attempts.append(now)

    def _receive(self, now):
        if self.receiver is None:
            return
        # The socket queue is bounded; one noisy worker cannot monopolise a reader.
        for _ in range(8):
            try:
                message = self.receiver.recv(_MAX_MESSAGE + 1)
            except (BlockingIOError, OSError):
                break
            if len(message) > _MAX_MESSAGE:
                continue
            try:
                value = json.loads(message)
                observed, sample = value["observed"], value["sample"]
                if (type(observed) not in (int, float) or not math.isfinite(observed)
                        or not 0 <= observed <= now or (self.observed is not None and observed <= self.observed)
                        or type(sample) is not dict or sample.get("schema") != self.schema):
                    continue
                # Reject non-finite JSON accepted by Python's decoder as extensions.
                json.dumps(sample, allow_nan=False)
                self.observed, self.sample = observed, sample
                system = value.get("system")
                self.system_sample = system if _valid_system(system, sample.get("sampledAt")) else None
            except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
                continue

    def _observation(self):
        now = self.clock()
        self._receive(now)
        age = max(0.0, now - self.observed) if self.observed is not None else None
        if self.closed or self.failed or self.stopping_at is not None or self.process is None or not self.process.is_alive():
            state = "unavailable"
        elif age is None:
            state = "starting" if now - self.started <= self.max_age else "stale"
        else:
            state = "ready" if age <= self.max_age else "stale"
        return state, int(age * 1000) if age is not None else None

    def snapshot(self):
        with self.lock:
            state, age_ms = self._observation()
            return {"schema": "orbis-sentinel.telemetry-envelope.v1", "state": state,
                    "ageMs": age_ms, "sample": copy.deepcopy(self.sample)}

    def system_snapshot(self):
        with self.lock:
            state, age_ms = self._observation()
            if state == "ready" and self.system_sample is None:
                state = "unavailable"
            return {"schema": "orbis-sentinel.system-readings.v1", "state": state, "ageMs": age_ms,
                    "sample": copy.deepcopy(self.system_sample) if state == "ready" else None}

    def maintain(self):
        with self.lock:
            if self.closed or self.failed or self.process is None:
                return
            now = self.clock()
            self._receive(now)
            last = self.observed if self.observed is not None else self.started
            if self.process.is_alive() and self.stopping_at is None and now - last <= self.max_age:
                return
            if self.process.is_alive():
                if self.stopping_at is None:
                    self.process.terminate()
                    self.stopping_at = now
                elif now - self.stopping_at >= 2:
                    self.process.kill()
                # Reaping is performed in later ticks. API reads never join.
                return
            self.process.join(timeout=0)
            self.process.close()
            self.receiver.close()
            self.process = self.receiver = None
            self.attempts = [stamp for stamp in self.attempts if now - stamp < 60]
            if len(self.attempts) >= 5:
                self.failed = True
                return
            self._start(now)

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            process = self.process
            if self.receiver is not None:
                self.receiver.close()
                self.receiver = None
        if process is not None:
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.5)
            if process.is_alive():
                process.kill()
                process.join(timeout=0.5)
            if not process.is_alive():
                process.close()
                with self.lock:
                    self.process = None
