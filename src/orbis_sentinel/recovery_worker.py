"""Bounded, owned crypto children of a supervisor-approved retained runtime."""

import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import time

from .recovery_sessions import _token

_HASH = re.compile(r'[0-9a-f]{64}\Z')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
_LABEL = 'orbis.sentinel.credential-worker'
_SCRIPT = '/app/sentinel-recovery-auth.mjs'
_OWNER_UID = 0


class RecoveryWorkerError(RuntimeError):
    """Credential verification is unavailable; no result conveys authority."""


class RecoveryWorkerCleanupRequired(RecoveryWorkerError):
    """An owned child or indeterminate creation requires supervisor reconciliation."""


def _fail():
    raise RecoveryWorkerError('The recovery credential worker is unavailable.') from None


def _hold():
    raise RecoveryWorkerCleanupRequired('Recovery worker cleanup requires reconciliation.') from None


def _json(body):
    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            _fail()
        return result
    return json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: _fail())


def _seal(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _Docker:
    def __init__(self, config):
        self.config = config

    def run(self, arguments, *, body=b'', limit=8192, timeout=10):
        """No credentials in arguments, environment, journal, Docker logs or errors."""
        process = subprocess.Popen(
            ['/usr/bin/docker', '--config', self.config, '--host', 'unix:///var/run/docker.sock', *arguments],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, close_fds=True, start_new_session=True)
        streams = selectors.DefaultSelector()
        output = bytearray()
        error_bytes = 0
        pending = memoryview(body)
        deadline = time.monotonic() + timeout
        try:
            for stream, kind in ((process.stdout, 'out'), (process.stderr, 'err')):
                os.set_blocking(stream.fileno(), False)
                streams.register(stream, selectors.EVENT_READ, kind)
            if pending:
                os.set_blocking(process.stdin.fileno(), False)
                streams.register(process.stdin, selectors.EVENT_WRITE, 'in')
            else:
                process.stdin.close()
            while streams.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _fail()
                for event, _ in streams.select(min(remaining, 0.1)):
                    if event.data == 'in':
                        try:
                            pending = pending[os.write(event.fd, pending[:4096]):]
                        except BrokenPipeError:
                            pending = pending[len(pending):]
                        if not pending:
                            streams.unregister(event.fileobj)
                            event.fileobj.close()
                        continue
                    block = os.read(event.fd, 4096)
                    if not block:
                        streams.unregister(event.fileobj)
                        event.fileobj.close()
                    elif event.data == 'out':
                        if len(output) + len(block) > limit:
                            _fail()
                        output.extend(block)
                    else:
                        error_bytes += len(block)
                        if error_bytes > 4096:
                            _fail()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail()
            code = process.wait(timeout=remaining)
            return code, bytes(output)
        except Exception:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=3)
            _fail()
        finally:
            streams.close()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


class RecoveryWorker:
    """Root dependency for RecoveryProfiles.inspect/verify, never a browser API.

    Installation must approve storage and retain the immutable image independently
    of Main. It must contain the published standalone worker and no declared Docker
    volumes. This class neither selects that image nor establishes host admission.
    A failed/ambiguous create stays held even when a later listing is empty.
    """

    def __init__(self, store, *, image_id, runner=None):
        if type(image_id) is not str or not _IMAGE.fullmatch(image_id):
            _fail()
        self._store, self._image, self._runner = store, image_id, runner
        self._fd = None
        self._identity = None
        self._closed = False
        self._path = os.path.join(store._directory, 'credential-worker')

    def _directory(self):
        if sys.platform != 'linux' or os.geteuid() != _OWNER_UID or self._closed:
            _fail()
        self._store._verify_resource()
        parent = self._store._directories[-1][1]
        if self._fd is None:
            try:
                os.mkdir('credential-worker', mode=0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
            self._fd = os.open('credential-worker', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(self._fd)
            self._identity = (info.st_dev, info.st_ino)
        for info in (os.fstat(self._fd), os.stat('credential-worker', dir_fd=parent, follow_symlinks=False)):
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != self._identity):
                _fail()
        if self._runner is None:
            try:
                os.mkdir('docker-config', mode=0o700, dir_fd=self._fd)
                os.fsync(self._fd)
            except FileExistsError:
                pass
            config = os.stat('docker-config', dir_fd=self._fd, follow_symlinks=False)
            if not stat.S_ISDIR(config.st_mode) or config.st_uid != _OWNER_UID or stat.S_IMODE(config.st_mode) != 0o700:
                _fail()
            self._runner = _Docker(os.path.join(self._path, 'docker-config'))
        return self._fd

    def _read(self):
        directory = self._directory()
        if 'pending.json' in os.listdir(directory):
            _hold()
        try:
            fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_nlink != 1 or not 0 < info.st_size <= 1024):
                _hold()
            body = os.read(fd, 1025)
            if len(body) != info.st_size:
                _hold()
            os.fsync(fd)
            os.fsync(directory)
            os.fsync(self._store._directories[-1][1])
            if _seal(info) != _seal(os.fstat(fd)) or _seal(info) != _seal(os.stat('state.json', dir_fd=directory, follow_symlinks=False)):
                _hold()
            value = _json(body)
            if (type(value) is not dict or set(value) != {'schema', 'name', 'nonce', 'image', 'container', 'phase'}
                    or value['schema'] != 'orbis.sentinel-credential-worker.v1'
                    or not isinstance(value['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', value['nonce'])
                    or value['name'] != 'orbis-sentinel-credential-' + value['nonce']
                    or not isinstance(value['image'], str) or not _IMAGE.fullmatch(value['image'])
                    or value['phase'] not in ('intent', 'created', 'clean')
                    or (value['container'] is not None and (not isinstance(value['container'], str) or not _HASH.fullmatch(value['container'])))
                    or (value['phase'] == 'created' and value['container'] is None)):
                _hold()
            return value
        finally:
            os.close(fd)

    def _write(self, value):
        directory = self._directory()
        fd = os.open('pending.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(json.dumps(value, separators=(',', ':')).encode('ascii'))
            stream.flush()
            os.fsync(stream.fileno())
        os.rename('pending.json', 'state.json', src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)

    def _call(self, args, **options):
        code, body = self._runner.run(args, **options)
        if code != 0:
            _fail()
        return body

    def _owned(self, record):
        projection = '{{json .Id}}\n{{json .Name}}\n{{json .Image}}\n{{json (index .Config.Labels "' + _LABEL + '")}}\n{{json .State.Running}}\n{{json .State.ExitCode}}'
        lines = self._call(['inspect', '--type', 'container', '--format', projection, record['container']]).splitlines()
        if len(lines) != 6:
            _hold()
        identity, name, image, nonce, running, code = [_json(line) for line in lines]
        if (identity != record['container'] or name != '/' + record['name'] or image != record['image']
                or nonce != record['nonce'] or type(running) is not bool or type(code) is not int):
            _hold()
        return running, code

    def _find(self, record, *, by_id=False):
        args = ['ps', '-a', '--no-trunc']
        if by_id:
            args += ['--filter', 'id=' + record['container']]
        else:
            args += ['--filter', 'name=^/' + record['name'] + '$']
        lines = self._call(args + ['--format', '{{.ID}}']).decode('ascii').splitlines()
        if len(lines) > 1 or any(not _HASH.fullmatch(item) for item in lines):
            _hold()
        if by_id and lines and lines != [record['container']]:
            _hold()
        return lines

    def _cleanup(self, record):
        try:
            if record['container'] is None or record['phase'] == 'intent':
                _hold()
            if self._find(record, by_id=True):
                self._owned(record)
                self._call(['rm', '--force', record['container']], timeout=10)
            if self._find(record, by_id=True) or self._find(record):
                _hold()
            self._write({**record, 'phase': 'clean'})
        except Exception:
            _hold()

    def _execute(self, directory, digest, challenge=None, credentials=None):
        if type(digest) is not str or not _HASH.fullmatch(digest):
            _fail()
        expected = os.path.join(self._store._directory, 'profiles', digest)
        if directory != expected or ',' in directory or any(ord(c) < 32 or ord(c) == 127 for c in directory):
            _fail()
        body = b''
        if challenge is not None:
            _token(challenge)
            if type(credentials) is not dict:
                _fail()
            body = json.dumps(credentials, separators=(',', ':'), allow_nan=False).encode('ascii')
            if not 0 < len(body) <= 32768:
                _fail()
        with self._store._worker_mutex, self._store._borrow():
            record = self._read()
            if record is not None and record['phase'] != 'clean':
                self._cleanup(record)
            image = self._call(['image', 'inspect', '--format', '{{json .Id}}\n{{json (index .Config "Volumes")}}', self._image]).splitlines()
            if len(image) != 2 or _json(image[0]) != self._image or _json(image[1]) not in (None, {}):
                _fail()
            nonce = secrets.token_hex(16)
            record = {'schema': 'orbis.sentinel-credential-worker.v1', 'name': 'orbis-sentinel-credential-' + nonce,
                      'nonce': nonce, 'image': self._image, 'container': None, 'phase': 'intent'}
            self._write(record)
            result = None
            failed = False
            try:
                args = ['create', '--pull=never', '--name', record['name'], '--label', _LABEL + '=' + nonce,
                        '--log-driver=none', '--network=none', '--ipc=none', '--no-healthcheck', '--restart=no',
                        '--read-only', '--user=0:0', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                        '--pids-limit=64', '--memory=512m', '--cpus=1', '--interactive',
                        '--mount', 'type=bind,src=' + directory + ',dst=/run/orbis-recovery,readonly',
                        '--entrypoint', '/usr/local/bin/node', self._image, _SCRIPT]
                args += ['--describe-identity', digest] if challenge is None else ['--verify', digest, challenge]
                identity = self._call(args).decode('ascii').strip()
                if not _HASH.fullmatch(identity):
                    _hold()
                record = {**record, 'container': identity, 'phase': 'created'}
                self._write(record)
                self._owned(record)
                output = self._call(['start', '--attach', '--interactive', identity], body=body,
                                    limit=32768 if challenge is None else 8192, timeout=15)
                if self._owned(record) != (False, 0):
                    _fail()
                result = _json(output)
                if type(result) is not dict:
                    _fail()
            except Exception:
                failed = True
            self._cleanup(record)
            if failed:
                _fail()
            return result

    def inspect(self, directory, digest):
        try:
            return self._execute(directory, digest)
        except RecoveryWorkerCleanupRequired:
            raise RecoveryWorkerCleanupRequired('Recovery worker cleanup requires reconciliation.') from None
        except Exception:
            _fail()

    def verify(self, directory, digest, challenge, credentials):
        try:
            return self._execute(directory, digest, challenge, credentials)
        except RecoveryWorkerCleanupRequired:
            raise RecoveryWorkerCleanupRequired('Recovery worker cleanup requires reconciliation.') from None
        except Exception:
            _fail()

    def close(self):
        with self._store._worker_mutex:
            self._closed = True
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
