"""Read sanitized update progress without access to the privileged host socket."""

import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

from .collector import TelemetryCollector
from .status import ComponentStatus

_SAFE = 2 ** 53 - 1
_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", re.ASCII)
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?", re.ASCII)
_CAPABILITY = {"schema": "orbis.sentinel-observer.v1", "protocolVersion": 1, "kind": "core-update-progress"}
_CAPTURE_CAPABILITY = {"schema": "orbis.sentinel-observer.capture.v1", "protocolVersion": 1, "kind": "core-capture-progress"}
_COMPONENT_CAPABILITY = {"schema": "orbis.sentinel-observer.component.v1", "protocolVersion": 1, "kind": "core-component-status"}


HANDOFF_SCHEMA = "orbis-sentinel.handoff-status.v1"
HANDOFF_MAX_AGE_MS = 5000
_HANDOFF_STATES = ("accepted", "stopping", "held", "returning", "complete", "attention")
_HASH = re.compile(r"[a-f0-9]{64}", re.ASCII)
_HANDOFF_ROUTE = "/v4/controller-handoff/status"


def validate_handoff(value):
    if (type(value) is not dict or set(value) != {"version", "handoff"}
            or type(value["version"]) is not int or value["version"] != 1):
        raise ValueError("Handoff status is unavailable")
    handoff = value["handoff"]
    if handoff is None:
        return {"version": 1, "handoff": None}
    if (type(handoff) is not dict or type(handoff.get("state")) is not str
            or handoff["state"] not in _HANDOFF_STATES
            or type(handoff.get("planId")) is not str or not _ID.fullmatch(handoff["planId"])):
        raise ValueError("Handoff status is unavailable")
    held = handoff["state"] == "held"
    if set(handoff) != ({"planId", "state", "returnScope"} if held else {"planId", "state"}):
        raise ValueError("Handoff status is unavailable")
    public = dict(handoff)
    if held:
        scope = handoff["returnScope"]
        if (type(scope) is not dict or set(scope) != {"planId", "installationId", "handoffSha256"}
                or scope["planId"] != handoff["planId"]
                or any(type(scope[key]) is not str or not _HASH.fullmatch(scope[key])
                       for key in ("installationId", "handoffSha256"))):
            raise ValueError("Handoff status is unavailable")
        public["returnScope"] = dict(scope)
    return {"version": 1, "handoff": public}


def unavailable_handoff():
    return {"schema": HANDOFF_SCHEMA, "status": None, "ageMs": None}


def validate_handoff_envelope(value):
    if (type(value) is not dict or set(value) != {"schema", "status", "ageMs"}
            or value["schema"] != HANDOFF_SCHEMA):
        raise ValueError("Handoff status is unavailable")
    if value["status"] is None:
        if value["ageMs"] is not None:
            raise ValueError("Handoff status is unavailable")
        return unavailable_handoff()
    if type(value["ageMs"]) is not int or not 0 <= value["ageMs"] <= HANDOFF_MAX_AGE_MS:
        raise ValueError("Handoff status is unavailable")
    return {"schema": HANDOFF_SCHEMA, "status": validate_handoff(value["status"]), "ageMs": value["ageMs"]}


def validate_component(value):
    if not _exact(value, {"installedVersion", "availableVersion", "state"}) or value["availableVersion"] is not None:
        raise ValueError("component observation is unavailable")
    return ComponentStatus(value["installedVersion"], None, value["state"])


def validate_capture(value, point):
    fields = {"version", "id", "state", "phase", "completedBytes", "totalBytes", "restartVerified"}
    phases = {"preparing", "stopping-orbis", "saving-orbis", "starting-orbis", "stopping-apps",
              "saving-apps", "starting-apps", "sealing", "complete"}
    if (not _exact(value, fields) or type(value["version"]) is not int or value["version"] != 1
            or type(point) is not str or not _ID.fullmatch(point) or value["id"] != point
            or type(value["state"]) is not str or value["state"] not in {"waiting", "running", "recovery-required", "complete"}
            or type(value["phase"]) is not str or value["phase"] not in phases
            or not _count(value["completedBytes"]) or not (value["totalBytes"] is None or _count(value["totalBytes"]))
            or value["totalBytes"] is not None and value["completedBytes"] > value["totalBytes"]
            or type(value["restartVerified"]) is not bool
            or (value["state"] == "complete") != (value["phase"] == "complete")
            or value["restartVerified"] != (value["state"] == "complete")):
        raise ValueError("capture progress is unavailable")
    return dict(value)


def _exact(value, keys):
    return type(value) is dict and set(value) == set(keys)


def _count(value):
    return type(value) is int and 0 <= value <= _SAFE


def validate_progress(value):
    if not _exact(value, {"version", "job"}) or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("progress is unavailable")
    job = value["job"]
    if job is None:
        return value
    if (type(job) is not dict or set(job) not in ({"id", "state", "targetTag", "phase"}, {"id", "state", "targetTag", "phase", "download"})
            or type(job["id"]) is not str or not _ID.fullmatch(job["id"])
            or type(job["targetTag"]) is not str or len(job["targetTag"]) > 100 or not _TAG.fullmatch(job["targetTag"])
            or type(job["state"]) is not str or job["state"] not in {"queued", "running", "recovering", "complete", "failed", "interrupted"}
            or job["phase"] not in (None, "downloading", "installing", "restarting", "verifying", "recovering")):
        raise ValueError("progress is unavailable")
    if "download" in job:
        item = job["download"]
        if (not _exact(item, {"schema", "phase", "currentBytes", "totalBytes", "totalKnown", "alreadyCached", "layersComplete", "layersTotal", "updatedAt"})
                or item["schema"] != "orbis.download-progress.v1" or item["phase"] not in ("downloading", "extracting", "complete")
                or not _count(item["currentBytes"]) or not (item["totalBytes"] is None or _count(item["totalBytes"]))
                or type(item["totalKnown"]) is not bool or item["totalKnown"] != (item["totalBytes"] is not None)
                or (item["totalBytes"] is not None and item["currentBytes"] > item["totalBytes"])
                or type(item["alreadyCached"]) is not bool
                or (item["alreadyCached"] and (item["phase"] != "complete" or item["currentBytes"] != 0 or item["totalBytes"] != 0))
                or not _count(item["layersComplete"]) or not _count(item["layersTotal"]) or not item["layersComplete"] <= item["layersTotal"] <= 4096
                or type(item["updatedAt"]) not in (float, int) or not 0 < item["updatedAt"] <= _SAFE or not math.isfinite(item["updatedAt"])):
            raise ValueError("progress is unavailable")
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


class ObserverClient:
    def __init__(self, socket_path, *, group_id=None):
        self.path = os.fspath(socket_path)
        self.gid = os.getgid() if group_id is None else group_id
        if (not isinstance(self.path, str) or not os.path.isabs(self.path) or "\0" in self.path
                or len(os.fsencode(self.path)) > 107 or type(self.gid) is not int or self.gid < 0):
            raise ValueError("invalid observer configuration")

    def _identity(self):
        path = Path(self.path)
        if str(path) != self.path or str(path.resolve(strict=True)) != self.path:
            raise ValueError("observer identity is unavailable")
        values = []
        for parent in reversed(path.parents):
            info = os.lstat(parent)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("observer identity is unavailable")
            values.append((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode))
            if parent == path.parent:
                values[-1] += (info.st_ctime_ns,)
        info = os.lstat(path)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != self.gid
                or stat.S_IMODE(info.st_mode) != 0o660 or info.st_nlink != 1):
            raise ValueError("observer identity is unavailable")
        values.append((info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_ctime_ns))
        return tuple(values)

    @staticmethod
    def _peer_uid(connection):
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError("observer peer is unavailable")
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]

    def _exchange(self, route, deadline):
        before = self._identity()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            def timeout():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError
                connection.settimeout(remaining)
            timeout()
            connection.connect(self.path)
            if self._peer_uid(connection) != 0:
                raise ValueError("observer peer is unavailable")
            timeout()
            connection.sendall(("GET " + route + " HTTP/1.1\r\nHost: observer\r\nConnection: close\r\n\r\n").encode("ascii"))
            data = b""
            while b"\r\n\r\n" not in data:
                timeout()
                chunk = connection.recv(4096)
                if not chunk:
                    raise ValueError("incomplete response")
                data += chunk
                if b"\r\n\r\n" not in data and len(data) > 4096:
                    raise ValueError("headers exceed limit")
            header, body = data.split(b"\r\n\r\n", 1)
            lines = header.split(b"\r\n")
            if len(header) > 4096 or lines[0] not in (b"HTTP/1.1 200 OK", b"HTTP/1.0 200 OK"):
                raise ValueError("observer is unavailable")
            headers = {}
            for line in lines[1:]:
                name, value = line.split(b":", 1)
                name, value = name.lower(), value.strip()
                if name in headers:
                    raise ValueError("duplicate header")
                headers[name] = value
            length = headers.get(b"content-length", b"")
            if b"transfer-encoding" in headers or not length.isdigit() or not 0 < int(length) <= 16384:
                raise ValueError("invalid response length")
            length = int(length)
            while len(body) < length:
                timeout()
                chunk = connection.recv(length + 1 - len(body))
                if not chunk:
                    raise ValueError("incomplete response")
                body += chunk
            if len(body) != length or self._identity() != before:
                raise ValueError("observer identity or response changed")
        return json.loads(body.decode("utf-8"), object_pairs_hook=_pairs)

    def read(self, *, deadline=None):
        deadline = time.monotonic() + 2 if deadline is None else deadline
        capability = self._exchange("/v1/capability", deadline)
        if capability != _CAPABILITY or type(capability.get("protocolVersion")) is not int:
            raise ValueError("observer capability is unavailable")
        return validate_progress(self._exchange("/v1/core-operation/progress", deadline))

    def read_capture(self, point, *, deadline=None):
        if type(point) is not str or not _ID.fullmatch(point):
            raise ValueError("invalid capture identity")
        deadline = time.monotonic() + 2 if deadline is None else deadline
        capability = self._exchange("/v2/capture-capability", deadline)
        if capability != _CAPTURE_CAPABILITY or type(capability.get("protocolVersion")) is not int:
            raise ValueError("capture observer is unavailable")
        return validate_capture(self._exchange("/v2/core-captures/" + point + "/progress", deadline), point)

    def read_component(self, *, deadline=None):
        deadline = time.monotonic() + 2 if deadline is None else deadline
        capability = self._exchange("/v3/component-capability", deadline)
        if capability != _COMPONENT_CAPABILITY or type(capability.get("protocolVersion")) is not int:
            raise ValueError("component observer is unavailable")
        value = self._exchange("/v3/orbis/status", deadline)
        validate_component(value)
        return value


    def read_handoff(self, *, deadline=None):
        deadline = time.monotonic() + 2 if deadline is None else deadline
        return validate_handoff(self._exchange(_HANDOFF_ROUTE, deadline))


def _observer_worker(output, paths, interval):
    client = ObserverClient(paths[0])
    output.setblocking(False)
    point = None
    interested_until = 0
    try:
        while True:
            started = time.monotonic()
            # One active capture per installation; viewers share one observation.
            # Interest expires after the last viewer leaves, including tab close.
            for _ in range(8):
                try:
                    request = json.loads(output.recv(1024), object_pairs_hook=_pairs)
                    if (_exact(request, {"capture"}) and type(request["capture"]) is str
                            and _ID.fullmatch(request["capture"])):
                        point = request["capture"]
                        interested_until = started + 15
                except (OSError, ValueError, TypeError, RecursionError):
                    break
            if started >= interested_until:
                point = None
            sample = {"schema": "orbis-sentinel.progress-sample.v1", "available": False,
                      "progress": None, "capture": None}
            deadline = started + 2
            if point is not None:
                try:
                    sample["capture"] = client.read_capture(point, deadline=deadline)
                except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                    pass
            try:
                sample.update(available=True, progress=client.read(deadline=deadline))
            except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                pass
            try:
                output.send(json.dumps({"observed": started, "sample": sample}, allow_nan=False, separators=(",", ":")).encode())
            except (OSError, ValueError):
                pass
            time.sleep(max(0, interval - (time.monotonic() - started)))
    finally:
        output.close()


def _component_worker(output, paths, interval):
    client = ObserverClient(paths[0])
    output.setblocking(False)
    try:
        while True:
            started = time.monotonic()
            sample = {"schema": "orbis-sentinel.component-sample.v1", "component": None}
            try:
                sample["component"] = client.read_component(deadline=started + 2)
            except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                pass
            try:
                output.send(json.dumps({"observed": started, "sample": sample}, allow_nan=False, separators=(",", ":")).encode())
            except (OSError, ValueError):
                pass
            time.sleep(max(0, interval - (time.monotonic() - started)))
    finally:
        output.close()


class _ComponentCollector(TelemetryCollector):
    schema = "orbis-sentinel.component-sample.v1"

    def __init__(self, socket_path):
        super().__init__((socket_path,), 1.0, max_age=5.0, worker=_component_worker)


def _handoff_worker(output, paths, interval):
    client = ObserverClient(paths[0])
    output.setblocking(False)
    try:
        while True:
            started = time.monotonic()
            sample = {"schema": _HandoffCollector.schema, "status": None}
            try:
                sample["status"] = client.read_handoff(deadline=started + 2)
            except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                pass
            try:
                output.send(json.dumps({"observed": started, "sample": sample}, allow_nan=False, separators=(",", ":")).encode())
            except (OSError, ValueError):
                pass
            time.sleep(max(0, interval - (time.monotonic() - started)))
    finally:
        output.close()


class _HandoffCollector(TelemetryCollector):
    schema = "orbis-sentinel.handoff-sample.v1"

    def __init__(self, socket_path):
        super().__init__((socket_path,), 2.0, max_age=HANDOFF_MAX_AGE_MS / 1000, worker=_handoff_worker)


def _upgrade_worker(output, paths, interval):
    """Read only progress from the independent Root update supervisor."""
    client = ObserverClient(paths[0])
    output.setblocking(False)
    try:
        while True:
            started = time.monotonic()
            sample = {'schema': 'orbis-sentinel.progress-sample.v1', 'available': False, 'progress': None}
            try:
                sample.update(available=True, progress=client.read(deadline=started + 2))
            except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                pass
            try:
                output.send(json.dumps({'observed': started, 'sample': sample}, allow_nan=False,
                                       separators=(',', ':')).encode())
            except (OSError, ValueError):
                pass
            time.sleep(max(0, interval - (time.monotonic() - started)))
    finally:
        output.close()


class _UpgradeCollector(TelemetryCollector):
    schema = 'orbis-sentinel.progress-sample.v1'

    def __init__(self, socket_path):
        super().__init__((socket_path,), 1.0, max_age=5.0, worker=_upgrade_worker)


def _progress_snapshot(value):
    sample = value['sample']
    available = value['state'] == 'ready' and type(sample) is dict and sample.get('available') is True
    progress = None
    if available:
        try:
            progress = validate_progress(sample.get('progress'))
        except (ValueError, TypeError):
            available = False
    return {'schema': 'orbis-sentinel.progress.v1', 'available': available,
            'progress': progress if available else None, 'ageMs': value['ageMs'], 'sourceState': value['state']}


class ObserverCollector(TelemetryCollector):
    schema = "orbis-sentinel.progress-sample.v1"

    def __init__(self, socket_path, *, upgrade_socket=None):
        checked = ObserverClient(socket_path)
        upgrade = ObserverClient(upgrade_socket) if upgrade_socket is not None else None
        if upgrade is not None and os.path.normpath(upgrade.path) == os.path.normpath(checked.path):
            raise ValueError('The independent upgrade observer must use a separate socket')
        super().__init__((checked.path,), 1.0, max_age=5.0, worker=_observer_worker)
        self.components = _ComponentCollector(checked.path)
        self.handoffs = _HandoffCollector(checked.path)
        self.upgrade = _UpgradeCollector(upgrade.path) if upgrade is not None else None

    def start(self):
        try:
            super().start()
            self.components.start()
            self.handoffs.start()
            if self.upgrade is not None:
                self.upgrade.start()
        except BaseException:
            self.close()
            raise

    def maintain(self):
        super().maintain()
        self.components.maintain()
        self.handoffs.maintain()
        if self.upgrade is not None:
            self.upgrade.maintain()

    def close(self):
        try:
            if self.upgrade is not None:
                self.upgrade.close()
        finally:
            try:
                self.handoffs.close()
            finally:
                try:
                    self.components.close()
                finally:
                    super().close()

    def snapshot(self):
        host = _progress_snapshot(super().snapshot())
        if self.upgrade is None:
            return host
        upgrade = _progress_snapshot(self.upgrade.snapshot())
        selected = upgrade['progress']['job'] if upgrade['available'] else None
        previous = host['progress']['job'] if host['available'] else None
        if selected is None:
            return host
        if previous is not None:
            active = {'queued', 'running', 'recovering', 'interrupted'}
            if selected['id'] == previous['id']:
                if selected['targetTag'] != previous['targetTag']:
                    return {'schema': 'orbis-sentinel.progress.v1', 'available': False,
                            'progress': None, 'ageMs': None, 'sourceState': 'unavailable'}
            elif previous['state'] in active:
                if selected['state'] not in active:
                    return host
                # Two different active identities are not one verified update.
                return {'schema': 'orbis-sentinel.progress.v1', 'available': False,
                        'progress': None, 'ageMs': None, 'sourceState': 'unavailable'}
        return upgrade

    def component_snapshot(self):
        # Component observation has its own owned worker and freshness budget.
        # A stalled update/capture reader cannot consume its next opportunity.
        value = self.components.snapshot()
        if value["state"] == "ready" and type(value["sample"]) is dict:
            try:
                return validate_component(value["sample"].get("component"))
            except (ValueError, TypeError):
                pass
        return ComponentStatus(None, None, "unknown")

    def handoff_snapshot(self):
        value = self.handoffs.snapshot()
        sample = value["sample"]
        if (value["state"] == "ready" and type(sample) is dict
                and set(sample) == {"schema", "status"} and sample["schema"] == _HandoffCollector.schema):
            try:
                return validate_handoff_envelope(
                    {"schema": HANDOFF_SCHEMA, "status": sample["status"], "ageMs": value["ageMs"]})
            except (ValueError, TypeError):
                pass
        return unavailable_handoff()

    def capture_snapshot(self, point):
        if type(point) is not str or not _ID.fullmatch(point):
            raise ValueError("invalid capture identity")
        with self.lock:
            if not self.closed and self.receiver is not None:
                try:
                    self.receiver.send(json.dumps({"capture": point}, separators=(",", ":")).encode())
                except (OSError, ValueError):
                    pass
        value = super().snapshot()
        progress = value["sample"].get("capture") if type(value["sample"]) is dict else None
        available = False
        if value["state"] == "ready":
            try:
                progress = validate_capture(progress, point)
                available = True
            except (ValueError, TypeError):
                progress = None
        return {"schema": "orbis-sentinel.capture-progress.v1", "id": point,
                "available": available, "progress": progress if available else None,
                "ageMs": value["ageMs"], "sourceState": value["state"]}
