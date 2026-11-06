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

_SAFE = 2 ** 53 - 1
_ID = re.compile(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", re.ASCII)
_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?", re.ASCII)
_CAPABILITY = {"schema": "orbis.sentinel-observer.v1", "protocolVersion": 1, "kind": "core-update-progress"}


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

    def read(self):
        deadline = time.monotonic() + 2
        capability = self._exchange("/v1/capability", deadline)
        if capability != _CAPABILITY or type(capability.get("protocolVersion")) is not int:
            raise ValueError("observer capability is unavailable")
        return validate_progress(self._exchange("/v1/core-operation/progress", deadline))


def _observer_worker(output, paths, interval):
    client = ObserverClient(paths[0])
    output.setblocking(False)
    try:
        while True:
            started = time.monotonic()
            sample = {"schema": "orbis-sentinel.progress-sample.v1", "available": False, "progress": None}
            try:
                sample.update(available=True, progress=client.read())
            except (OSError, ValueError, TypeError, OverflowError, RecursionError):
                pass
            try:
                output.send(json.dumps({"observed": started, "sample": sample}, allow_nan=False, separators=(",", ":")).encode())
            except (OSError, ValueError):
                pass
            time.sleep(max(0, interval - (time.monotonic() - started)))
    finally:
        output.close()


class ObserverCollector(TelemetryCollector):
    schema = "orbis-sentinel.progress-sample.v1"

    def __init__(self, socket_path):
        checked = ObserverClient(socket_path)
        super().__init__((checked.path,), 1.0, max_age=5.0, worker=_observer_worker)

    def snapshot(self):
        value = super().snapshot()
        sample = value["sample"]
        available = value["state"] == "ready" and type(sample) is dict and sample.get("available") is True
        return {"schema": "orbis-sentinel.progress.v1", "available": available,
                "progress": sample["progress"] if available else None, "ageMs": value["ageMs"], "sourceState": value["state"]}
