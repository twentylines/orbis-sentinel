"""Launch recovery from supervisor-owned configuration, without enrollment."""

import json
import os
import select
import signal
import socket
import subprocess
import stat
import struct
import sys
import threading
import time

from .observer import unavailable_handoff
from .recovery_config import RecoveryConfig, _absolute, _pairs, _seal
from .recovery_runtime import run_recovery, _require_root


def read_status(path):
    """Read only the bounded status route over the enrolled root socket."""
    return _read_observation(path, '/sentinel/api/v1/status')


def read_progress(path):
    """Read only the existing bounded progress route over the same enrolled socket."""
    return _read_observation(path, '/sentinel/api/v1/progress')


def read_handoff_status(path):
    """Read only the fixed handoff route on the enrolled status socket."""
    try:
        return _read_observation(path, '/sentinel/api/v1/handoff-status')
    except (OSError, ValueError):
        return unavailable_handoff()


def _read_observation(path, route):
    if route not in ('/sentinel/api/v1/status', '/sentinel/api/v1/progress', '/sentinel/api/v1/handoff-status'):
        raise ValueError('Invalid recovery observation route.')
    if not _absolute(path) or len(os.fsencode(path)) > 107:
        raise ValueError('Invalid recovery status socket.')
    current = '/'
    for part in os.path.dirname(path).strip('/').split('/'):
        current = os.path.join(current, part)
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Recovery status socket directory is not protected.')
    before = os.lstat(path)
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError('Recovery status socket is not protected.')
    deadline = time.monotonic() + 2
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(path)
        if struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1] != 0:
            raise ValueError('Recovery status peer is not root.')
        connection.sendall(('GET ' + route + ' HTTP/1.1\r\nHost: sentinel\r\nConnection: close\r\n\r\n').encode('ascii'))
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
                raise TimeoutError('Recovery status read expired.')
            block = connection.recv(8192)
            if not block:
                break
            body.extend(block)
            if len(body) > 81920:
                raise ValueError('Recovery status response is too large.')
    if _seal(before) != _seal(os.lstat(path)):
        raise ValueError('Recovery status socket changed.')
    return _status_response(bytes(body))


def _status_response(body):
    header, separator, payload = body.partition(b'\r\n\r\n')
    lines = header.split(b'\r\n')
    if not separator or len(header) > 16384 or lines[0] != b'HTTP/1.1 200 OK' or len(payload) > 65536:
        raise ValueError('Invalid recovery status response.')
    headers = {}
    for line in lines[1:]:
        name, colon, value = line.partition(b':')
        name = name.lower()
        if not colon or name in headers:
            raise ValueError('Invalid recovery status headers.')
        headers[name] = value.strip()
    if (headers.get(b'content-length') != str(len(payload)).encode()
            or b'transfer-encoding' in headers or b'content-encoding' in headers):
        raise ValueError('Invalid recovery status body.')
    return json.loads(payload, object_pairs_hook=_pairs)


def main(path):
    from .credential_floor import RECOVERY_ROOT
    from .recovery_listener_install import setup_profile
    original = {}
    stop = threading.Event()
    try:
        _require_root()
        with RecoveryConfig(path) as config, setup_profile(config, path) as setup:
            for signum in (signal.SIGTERM, signal.SIGINT):
                original[signum] = signal.signal(signum, lambda *_: stop.set())
            value = config.data
            run_recovery(directory=value['directory'], image_id=value['imageId'], origin=value['origin'],
                         address=('127.0.0.1', value['listenPort']), status=lambda: read_status(value['statusSocket']),
                         progress=lambda: read_progress(value['statusSocket']),
                         handoff_status=lambda: read_handoff_status(value['statusSocket']),
                         stop=stop, check=setup.verify if setup is not None else config.verify, control=True, setup=setup,
                         installed_listener=value['directory'] == str(RECOVERY_ROOT),
                         backend=setup.backend if setup is not None else None)
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        print('Sentinel recovery could not start or continue. Its protected configuration needs review.', file=sys.stderr)
        return 1
    finally:
        for signum, handler in original.items():
            signal.signal(signum, handler)
