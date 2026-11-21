"""The recovery listener's fixed Host return request; no generic Host relay."""

from contextlib import contextmanager
import json
import os
import re
import select
import socket
import stat
import struct
import sys
import time
from urllib.parse import urlsplit

from .recovery_config import _pairs, _seal

HOST_SOCKET = '/run/orbis/host.sock'
RETURN_PATH = '/v1/sentinel/controller-handoff/return-approved'
READINESS_PATH = '/v1/sentinel/controller-handoff/return-readiness'
_UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}')
_HASH = re.compile(r'[a-f0-9]{64}')
_PHASES = {'planned', 'accepted', 'stopping', 'held', 'return-accepted', 'returning', 'complete', 'cancelled'}


class ReturnTransportError(RuntimeError):
    def __init__(self):
        super().__init__('Controller return could not be confirmed. Check Sentinel status before retrying.')


def _origin(origin):
    if type(origin) is not str or not 1 <= len(origin) <= 512:
        raise ValueError('An enrolled HTTPS origin is required.')
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment or parsed.port == 0
            or any(ord(character) <= 32 or ord(character) == 127 for character in origin)):
        raise ValueError('An enrolled HTTPS origin is required.')
    return origin


def validate_return_reply(value, *, plan_id, origin):
    if (type(value) is not dict or set(value) != {'version', 'planId', 'state', 'phase', 'portalUrl', 'expiresAtMs'}
            or type(value['version']) is not int or value['version'] != 1 or value['planId'] != plan_id
            or type(value['phase']) is not str or value['phase'] not in _PHASES
            or value['state'] not in (value['phase'], 'attention')
            or value['portalUrl'] != origin + '/sentinel/recovery/'
            or type(value['expiresAtMs']) is not int or not 0 < value['expiresAtMs'] <= 2 ** 53 - 1):
        raise ReturnTransportError()
    return dict(value)


def _response(data, *, statuses):
    header, separator, body = data.partition(b'\r\n\r\n')
    lines = header.split(b'\r\n')
    match = re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3}) [^\r\n]{1,64}', lines[0])
    if (not separator or len(header) > 16384 or len(body) > 4096
            or match is None or int(match[1]) not in statuses):
        raise ReturnTransportError()
    fields = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        name = name.lower()
        if not colon or name in fields:
            raise ReturnTransportError()
        fields[name] = value.strip()
    if (fields.get(b'content-length') != str(len(body)).encode()
            or b'transfer-encoding' in fields or b'content-encoding' in fields):
        raise ReturnTransportError()
    return json.loads(body, object_pairs_hook=_pairs)


def _reply(data, *, plan_id, origin):
    return validate_return_reply(_response(data, statuses=(200, 202)), plan_id=plan_id, origin=origin)


def _directory_identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


class ControllerReturnTransport:
    """Run inside the paired listener process so Host can verify that actor.

    Host independently verifies its peer, floor, held controller and approval.
    This client supplies only two public identifiers and never retries an
    uncertain request. No browser input can select its socket or route.
    """

    def __init__(self, *, origin):
        self.origin = _origin(origin)

    @contextmanager
    def _connection(self):
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise ReturnTransportError()
        directories = []
        try:
            path = '/'
            for part in ('', 'run', 'orbis'):
                if part:
                    path = os.path.join(path, part)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                directories.append((path, fd, _directory_identity(info)))
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ReturnTransportError()
            endpoint = os.stat('host.sock', dir_fd=directories[-1][1], follow_symlinks=False)
            if (not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or endpoint.st_nlink != 1
                    or stat.S_IMODE(endpoint.st_mode) != 0o600):
                raise ReturnTransportError()
            deadline = time.monotonic() + 45
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(HOST_SOCKET)
                pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != 0 or pid <= 0:
                    raise ReturnTransportError()
                yield connection, deadline
            if _seal(endpoint) != _seal(os.stat('host.sock', dir_fd=directories[-1][1], follow_symlinks=False)):
                raise ReturnTransportError()
            for path, fd, expected in directories:
                if _directory_identity(os.fstat(fd)) != expected or _directory_identity(os.lstat(path)) != expected:
                    raise ReturnTransportError()
        finally:
            for _, fd, _ in reversed(directories):
                os.close(fd)

    def apply(self, *, plan_id, approval_id):
        if (type(plan_id) is not str or not _UUID.fullmatch(plan_id)
                or type(approval_id) is not str or not _HASH.fullmatch(approval_id)):
            raise ValueError('One exact controller return approval is required.')
        return self._exchange(RETURN_PATH, {'planId': plan_id, 'approvalId': approval_id}, 45,
                              lambda data: _reply(data, plan_id=plan_id, origin=self.origin))

    def readiness(self, request):
        from .controller_return_readiness import readiness_reply, readiness_request

        value = readiness_request(request)
        result = self._exchange(READINESS_PATH, value, 3, lambda data: _response(data, statuses=(200,)))
        if result != readiness_reply(value):
            raise ReturnTransportError()
        return result

    def _exchange(self, path, data, timeout, decode):
        started = time.monotonic()
        body = json.dumps(data, separators=(',', ':')).encode('ascii')
        request = (f'POST {path} HTTP/1.1\r\nHost: orbis\r\nContent-Type: application/json\r\n'
                   f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii') + body
        try:
            with self._connection() as (connection, deadline):
                deadline = min(deadline, started + timeout)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReturnTransportError()
                connection.settimeout(min(3, remaining))
                connection.sendall(request)
                received = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
                        raise ReturnTransportError()
                    block = connection.recv(min(4096, 20481 - len(received)))
                    if not block:
                        break
                    received.extend(block)
                    if len(received) > 20480:
                        raise ReturnTransportError()
                result = decode(bytes(received))
            return result
        except Exception:
            raise ReturnTransportError() from None
