"""Fixed-purpose, root-authenticated recovery control client for the host broker."""
import os
import socket
import stat
import struct
import time

from .writer_journal import _OWNER_UID, decoded, encoded, mount_id, directory_seal, seal

_OPERATIONS = {'operator-status', 'operator-writer-eligibility', 'operator-capability', 'operator-prepare-writer', 'operator-complete-incarnation',
               'main-passkey-challenge', 'main-passkey-complete', 'main-passkey-floors'}
_SCHEMA = 'orbis.sentinel-recovery-control.v1'


class WriterControlError(RuntimeError):
    def __init__(self):
        super().__init__('Recovery control is unavailable; keep the credential operation held.')


class WriterControlClient:
    def __init__(self, path, *, timeout=180):
        if (type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path
                or os.path.realpath(os.path.dirname(path)) != os.path.dirname(path) or len(os.fsencode(path)) > 107
                or type(timeout) not in (int, float) or not 1 <= timeout <= 300):
            raise WriterControlError()
        self.path, self.timeout = path, timeout

    @staticmethod
    def _peer(connection):
        if hasattr(socket, 'SO_PEERCRED'):
            pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return pid > 0 and uid == _OWNER_UID
        if hasattr(connection, 'getpeereid'):
            return connection.getpeereid()[0] == _OWNER_UID
        return False

    def call(self, operation, arguments):
        directories = []
        try:
            if operation not in _OPERATIONS or type(arguments) is not dict:
                raise WriterControlError()
            body = encoded({'schema': _SCHEMA, 'operation': operation, 'arguments': arguments})
            if not 1 <= len(body) <= 196608:
                raise WriterControlError()
            current = '/'
            for part in ('', *os.path.dirname(self.path).strip('/').split('/')):
                if part:
                    current = os.path.join(current, part)
                fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                directories.append((current, fd, directory_seal(info), mount_id(fd)))
                if info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022:
                    raise WriterControlError()
            if stat.S_IMODE(os.fstat(directories[-1][1]).st_mode) != 0o700:
                raise WriterControlError()
            name = os.path.basename(self.path)
            before = os.stat(name, dir_fd=directories[-1][1], follow_symlinks=False)
            if not stat.S_ISSOCK(before.st_mode) or before.st_uid != _OWNER_UID or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
                raise WriterControlError()
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(3, self.timeout))
                connection.connect(self.path)
                if not self._peer(connection):
                    raise WriterControlError()
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection.sendall(struct.pack('!I', len(body)) + body)
                connection.shutdown(socket.SHUT_WR)
                def read(count):
                    output = bytearray()
                    while len(output) < count:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise WriterControlError()
                        connection.settimeout(remaining)
                        chunk = connection.recv(count - len(output))
                        if not chunk:
                            raise WriterControlError()
                        output.extend(chunk)
                    return bytes(output)
                size = struct.unpack('!I', read(4))[0]
                if not 0 < size <= 98304:
                    raise WriterControlError()
                value = decoded(read(size))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WriterControlError()
                connection.settimeout(remaining)
                if connection.recv(1):
                    raise WriterControlError()
            if seal(before) != seal(os.stat(name, dir_fd=directories[-1][1], follow_symlinks=False)):
                raise WriterControlError()
            for path, fd, expected, mounted in directories:
                fresh = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if (directory_seal(os.fstat(fd)) != expected or directory_seal(os.fstat(fresh)) != expected
                            or mount_id(fd) != mounted or mount_id(fresh) != mounted):
                        raise WriterControlError()
                finally:
                    os.close(fresh)
            if (type(value) is not dict or set(value) != {'schema', 'ok', 'result'} or value['schema'] != _SCHEMA
                    or value['ok'] is not True or type(value['result']) is not dict):
                raise WriterControlError()
            return value['result']
        except Exception:
            raise WriterControlError() from None
        finally:
            for _, fd, _, _ in reversed(directories):
                os.close(fd)
