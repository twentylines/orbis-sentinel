"""Bounded, read-only HTTP over an authenticated local Unix socket.

Providers must return already-cached JSON values without blocking. An inherited
listener is duplicated: closing this server never closes or unlinks the original.
"""

import json
import math
import os
import re
import select
import socket
import stat
import struct
import threading
import time

from .contracts import API_PREFIX

_ROUTES = frozenset(API_PREFIX + "/" + name for name in ("health", "status", "telemetry", "progress"))
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_MAX_HEADERS = 16384
_MAX_LINE = 8192
_MAX_BODY = 1048576


class SentinelServer:
    def __init__(self, socket_path, providers, *, listener=None, allowed_uids=None,
                 max_connections=8, request_timeout=2.0):
        if not hasattr(providers, "items"):
            raise TypeError("providers must be a mapping")
        self.providers = dict(providers)
        if not set(self.providers) <= _ROUTES or any(not callable(v) for v in self.providers.values()):
            raise ValueError("providers must map supported routes to callbacks")
        if type(max_connections) is not int or not 1 <= max_connections <= 64:
            raise ValueError("max_connections must be between 1 and 64")
        if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or not math.isfinite(request_timeout) or not 0.05 <= request_timeout <= 30:
            raise ValueError("request_timeout must be between 0.05 and 30 seconds")
        uids = {0, os.geteuid()} if allowed_uids is None else set(allowed_uids)
        if any(type(uid) is not int or uid < 0 for uid in uids):
            raise ValueError("allowed_uids must contain nonnegative integers")
        self.allowed_uids = frozenset(uids)
        self.request_timeout = float(request_timeout)
        self._slots = threading.BoundedSemaphore(max_connections)
        self._stopping = threading.Event()
        self._closed = False
        self._created = None
        self._path = None
        if listener is not None:
            try:
                valid = (listener.family == socket.AF_UNIX and
                         listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM and
                         listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN))
            except OSError:
                valid = False
            if not valid:
                raise ValueError("listener must be a listening Unix stream socket")
            self._listener = listener.dup()
        else:
            path = os.path.abspath(os.fspath(socket_path))
            parent = os.path.dirname(path)
            if os.path.realpath(parent) != parent:
                raise ValueError("socket parent must be canonical and contain no symlinks")
            info = os.stat(parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("socket parent must be owned by the service user and mode 0700")
            if os.path.lexists(path):
                raise FileExistsError(path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.bind(os.fspath(socket_path))
                info = os.lstat(path)
                self._created = (info.st_dev, info.st_ino)
                self._path = path
                os.chmod(path, 0o600, follow_symlinks=False)
                sock.listen(max_connections)
            except BaseException:
                sock.close()
                self._unlink_created()
                raise
            self._listener = sock

    @staticmethod
    def _peer_uid(conn):
        if hasattr(socket, "SO_PEERCRED"):
            return struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        if hasattr(conn, "getpeereid"):
            return conn.getpeereid()[0]
        raise OSError("peer credentials unavailable")

    def serve_forever(self):
        while not self._stopping.is_set():
            try:
                readable, _, _ = select.select([self._listener], [], [], 0.2)
                if not readable:
                    continue
                conn, _ = self._listener.accept()
            except (OSError, ValueError):
                if self._stopping.is_set():
                    break
                raise
            deadline = time.monotonic() + self.request_timeout
            try:
                uid = self._peer_uid(conn)
            except (OSError, ValueError, struct.error):
                conn.close()
                continue
            if uid not in self.allowed_uids or not self._slots.acquire(blocking=False):
                conn.close()
                continue
            try:
                threading.Thread(target=self._handle, args=(conn, deadline), daemon=True).start()
            except BaseException:
                self._slots.release()
                conn.close()
                raise

    def shutdown(self):
        self._stopping.set()

    def _unlink_created(self):
        if self._created is None:
            return
        try:
            info = os.lstat(self._path)
            if (info.st_dev, info.st_ino) == self._created and stat.S_ISSOCK(info.st_mode):
                os.unlink(self._path)
        except FileNotFoundError:
            pass
        self._created = None

    def server_close(self):
        if not self._closed:
            self._closed = True
            self.shutdown()
            self._listener.close()
            self._unlink_created()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.server_close()

    def _handle(self, conn, deadline):
        try:
            status, body = self._request(conn, deadline)
            response = (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\n"
                        "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n").encode("ascii") + body
            remaining = deadline - time.monotonic()
            if remaining > 0:
                conn.settimeout(remaining)
                conn.sendall(response)
        except (OSError, TimeoutError):
            pass
        finally:
            conn.close()
            self._slots.release()

    def _request(self, conn, deadline):
        def error(status):
            return status, b'{"error":"request failed"}'
        data = b""
        while b"\r\n\r\n" not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn.settimeout(remaining)
            chunk = conn.recv(min(4096, _MAX_HEADERS + 1 - len(data)))
            if not chunk:
                return error("400 Bad Request")
            data += chunk
            if len(data) > _MAX_HEADERS or (b"\r\n" not in data and len(data) > _MAX_LINE):
                return error("431 Request Header Fields Too Large")
        head, extra = data.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        if extra or len(lines[0]) > _MAX_LINE:
            return error("400 Bad Request")
        parts = lines[0].split(b" ")
        if len(parts) != 3 or not _TOKEN.fullmatch(parts[0]) or parts[2] not in (b"HTTP/1.0", b"HTTP/1.1"):
            return error("400 Bad Request")
        headers = {}
        for line in lines[1:]:
            if b":" not in line:
                return error("400 Bad Request")
            name, value = line.split(b":", 1)
            if not _TOKEN.fullmatch(name) or any(c < 32 and c != 9 or c == 127 for c in value):
                return error("400 Bad Request")
            name = name.lower()
            if name in headers:
                return error("400 Bad Request")
            headers[name] = value.strip(b" \t")
        if b"transfer-encoding" in headers or (b"content-length" in headers and headers[b"content-length"] != b"0"):
            return error("400 Bad Request")
        if parts[0] != b"GET":
            return error("405 Method Not Allowed")
        try:
            path = parts[1].decode("ascii")
        except UnicodeDecodeError:
            return error("400 Bad Request")
        if path not in self.providers:
            return error("404 Not Found")
        try:
            body = json.dumps(self.providers[path](), allow_nan=False, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(body) > _MAX_BODY:
                raise ValueError("response too large")
        except Exception:
            return error("503 Service Unavailable")
        return "200 OK", body
