"""Private host-supervisor journal, separate from recovery authentication SQLite.

The installation supervisor supplies admitted storage and excludes other writers.
No constructor infers an unmanaged installation from an absent file or service.
Incomplete writes are retained as a reconciliation hold, never silently deleted.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import threading

_OWNER_UID = 0
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_MAX_STATE = 2 * 1024 * 1024
_MAX_RECORDS = 1024
_MAX_SOURCES = 2048


class WriterJournalError(RuntimeError):
    def __init__(self):
        super().__init__('The host credential journal requires recovery.')


def fail():
    raise WriterJournalError() from None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail()
        result[key] = value
    return result


def decoded(body):
    return json.loads(body, object_pairs_hook=pairs, parse_constant=lambda _: fail())


def hash_value(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def seal(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def mount_id(fd):
    if sys.platform != 'linux':
        return None
    with open('/proc/self/fdinfo/' + str(fd), 'rb') as stream:
        body = stream.read(4097)
    matches = re.findall(rb'(?m)^mnt_id:\s*([0-9]+)$', body)
    if len(body) > 4096 or len(matches) != 1:
        fail()
    return int(matches[0])


def directory_seal(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


class WriterJournal:
    def __init__(self, directory, *, create=False, validate_record):
        self.directory = os.fspath(directory)
        self._directories, self._lock = [], None
        self._sources = None
        self._mutex = threading.RLock()
        self._closed, self._uncertain = False, False
        self._pid = os.getpid()
        self._state_seal = None
        self._validate_record = validate_record
        try:
            if (type(create) is not bool or not callable(validate_record) or os.geteuid() != _OWNER_UID
                    or not os.path.isabs(self.directory) or os.path.normpath(self.directory) != self.directory
                    or os.path.realpath(self.directory) != self.directory):
                fail()
            current = '/'
            for part in ('', *self.directory.strip('/').split('/')):
                if part:
                    current = os.path.join(current, part)
                fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                self._directories.append((current, fd, directory_seal(info), mount_id(fd)))
                if (info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022
                        or (current == self.directory and (info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o700))):
                    fail()
            root = self._directories[-1][1]
            empty = not os.listdir(root)
            self._lock = os.open('writer.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=root)
            self._lock_seal = seal(os.fstat(self._lock))
            self._regular(self._lock, 'writer.lock', 1)
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if create and empty:
                os.mkdir('sources', 0o700, dir_fd=root)
                os.fsync(root)
            self._sources = os.open('sources', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            self._source_seal = directory_seal(os.fstat(self._sources))
            self._source_mount = mount_id(self._sources)
            if create and empty:
                self._write({'schema': 'orbis.sentinel-writer-journal.v1', 'generation': 0, 'active': None, 'operations': {}})
            with self.operation():
                self.read()
        except BaseException:
            self.close()
            raise

    def _regular(self, fd, name, maximum, *, directory=None):
        info = os.fstat(fd)
        current = os.stat(name, dir_fd=directory if directory is not None else self._directories[-1][1], follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size > maximum or seal(info) != seal(current)):
            fail()
        return info

    def _check(self):
        if self._closed or self._uncertain or os.getpid() != self._pid:
            fail()
        for path, fd, identity, mounted in self._directories:
            current = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if (directory_seal(os.fstat(fd)) != identity or directory_seal(os.fstat(current)) != identity
                        or mount_id(fd) != mounted or mount_id(current) != mounted):
                    fail()
            finally:
                os.close(current)
        root = self._directories[-1][1]
        if set(os.listdir(root)) != {'writer.lock', 'sources', 'state.json'}:
            fail()
        if seal(self._regular(self._lock, 'writer.lock', 1)) != self._lock_seal:
            fail()
        current = os.open('sources', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        try:
            if (directory_seal(os.fstat(current)) != self._source_seal or directory_seal(os.fstat(self._sources)) != self._source_seal
                    or stat.S_IMODE(os.fstat(current).st_mode) != 0o700 or os.fstat(current).st_uid != _OWNER_UID
                    or mount_id(current) != self._source_mount or mount_id(self._sources) != self._source_mount):
                fail()
        finally:
            os.close(current)
        names = os.listdir(self._sources)
        if len(names) > _MAX_SOURCES or any(not hash_value(name) for name in names):
            fail()

    @contextmanager
    def operation(self):
        with self._mutex:
            try:
                self._check()
                yield self
                self._check()
            except Exception:
                fail()

    def read(self):
        self._check()
        root = self._directories[-1][1]
        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root)
        try:
            before = self._regular(fd, 'state.json', _MAX_STATE)
            if self._state_seal is not None and seal(before) != self._state_seal:
                fail()
            body = bytearray()
            while len(body) <= _MAX_STATE:
                chunk = os.read(fd, min(8192, _MAX_STATE + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if len(body) != before.st_size or seal(before) != seal(self._regular(fd, 'state.json', _MAX_STATE)):
                fail()
            value = decoded(body)
            self._validate(value)
            self._state_seal = seal(before)
            return value
        finally:
            os.close(fd)

    def _validate(self, value):
        if (type(value) is not dict or set(value) != {'schema', 'generation', 'active', 'operations'}
                or value['schema'] != 'orbis.sentinel-writer-journal.v1' or type(value['generation']) is not int
                or not 0 <= value['generation'] < 9_007_199_254_740_991
                or type(value['operations']) is not dict or len(value['operations']) > _MAX_RECORDS
                or (value['active'] is not None and not hash_value(value['active']))):
            fail()
        pending = []
        requests = set()
        for key, record in value['operations'].items():
            if not hash_value(key):
                fail()
            self._validate_record(key, record)
            if record['requestId'] in requests:
                fail()
            requests.add(record['requestId'])
            if record['phase'] != 'completed':
                pending.append(key)
        if pending != ([] if value['active'] is None else [value['active']]):
            fail()

    def _write(self, value):
        self._validate(value)
        body = encoded(value)
        if len(body) > _MAX_STATE:
            fail()
        root = self._directories[-1][1]
        fd = os.open('pending.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace('pending.json', 'state.json', src_dir_fd=root, dst_dir_fd=root)
            os.fsync(root)
            self._state_seal = seal(os.stat('state.json', dir_fd=root, follow_symlinks=False))
        except BaseException:
            self._uncertain = True
            raise

    def save(self, value):
        self._check()
        current = self.read()
        if current['generation'] + 1 != value['generation']:
            fail()
        self._write(value)
        self._check()

    def retain(self, body):
        self._check()
        if type(body) is not bytes or not 1 <= len(body) <= 65536:
            fail()
        name = digest(body)
        names = os.listdir(self._sources)
        if any(not hash_value(item) for item in names):
            fail()
        if name not in names:
            if len(names) >= _MAX_SOURCES:
                fail()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self._sources)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(self._sources)
            os.fsync(self._directories[-1][1])
        if self.source(name) != body:
            fail()
        return name

    def source(self, name):
        self._check()
        if not hash_value(name):
            fail()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self._sources)
        try:
            before = self._regular(fd, name, 65536, directory=self._sources)
            body = bytearray()
            while len(body) <= 65536:
                chunk = os.read(fd, min(8192, 65537 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            if (not body or len(body) != before.st_size or digest(body) != name
                    or seal(before) != seal(self._regular(fd, name, 65536, directory=self._sources))):
                fail()
            return bytes(body)
        finally:
            os.close(fd)

    def close(self):
        with self._mutex:
            self._closed = True
            if self._sources is not None:
                os.close(self._sources)
                self._sources = None
            if self._lock is not None:
                os.close(self._lock)
                self._lock = None
            for _, fd, _, _ in reversed(self._directories):
                os.close(fd)
            self._directories.clear()
