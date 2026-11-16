"""Protected credential material for the independently enrolled recovery worker."""

from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat

from . import recovery_sessions as sessions

_MAX_BYTES = 65536
_MAX_PROFILES = 1024
_DIGEST = re.compile(r'[a-f0-9]{64}\Z')


class RecoveryProfileError(RuntimeError):
    """Protected profile custody or its enrolled worker is unavailable."""


def _fail():
    raise RecoveryProfileError('The protected recovery profile is unavailable.') from None


def _seal(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class PreparedProfile:
    """Process-local reference, never browser-supplied enrollment authority."""
    digest: str
    _owner: object
    _metadata: str


class RecoveryProfiles:
    """Immutable profiles in the supervisor-approved root session directory.

    The host supervisor must approve the session directory's storage, mounts and
    writers before enrollment. These file checks do not provide that approval or
    serialize main-account mutations. Both worker callbacks must be bounded and
    establish container/process cleanup before returning, including on failure.
    """

    def __init__(self, store, *, inspect, verify):
        if not callable(inspect) or not callable(verify):
            _fail()
        self._store, self._inspect, self._verify_worker = store, inspect, verify
        self._fd = None
        self._identity = None
        self._closed = False
        self._path = os.path.join(store._directory, 'profiles')

    def _directory(self, *, create=False):
        self._store._verify()
        if self._closed:
            _fail()
        root = self._store._directories[-1][1]
        if self._fd is None:
            if create:
                try:
                    os.mkdir('profiles', mode=0o700, dir_fd=root)
                    os.fsync(root)
                except FileExistsError:
                    pass
            fd = os.open('profiles', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            self._fd = fd
            self._identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        for info in (os.fstat(self._fd), os.stat('profiles', dir_fd=root, follow_symlinks=False)):
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != sessions._OWNER_UID
                    or stat.S_IMODE(info.st_mode) != 0o700 or (info.st_dev, info.st_ino) != self._identity):
                _fail()
        return self._fd

    def _contents(self, directory, digest):
        if set(os.listdir(directory)) != {'identity.json'}:
            _fail()
        fd = os.open('identity.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != sessions._OWNER_UID
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= _MAX_BYTES):
                _fail()
            body = bytearray()
            while len(body) <= _MAX_BYTES:
                block = os.read(fd, min(8192, _MAX_BYTES + 1 - len(body)))
                if not block:
                    break
                body.extend(block)
            if (len(body) != before.st_size or hashlib.sha256(body).hexdigest() != digest
                    or _seal(before) != _seal(os.fstat(fd))
                    or _seal(before) != _seal(os.stat('identity.json', dir_fd=directory, follow_symlinks=False))):
                _fail()
            return _seal(before)
        finally:
            os.close(fd)

    def _run(self, digest, action):
        if type(digest) is not str or not _DIGEST.fullmatch(digest):
            _fail()
        base = self._directory()
        fd = os.open(digest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
        try:
            before = os.fstat(fd)
            if (before.st_uid != sessions._OWNER_UID or stat.S_IMODE(before.st_mode) != 0o700
                    or _seal(before) != _seal(os.stat(digest, dir_fd=base, follow_symlinks=False))):
                _fail()
            content = self._contents(fd, digest)
            result = action(os.path.join(self._path, digest), digest)
            if (content != self._contents(fd, digest) or _seal(before) != _seal(os.fstat(fd))
                    or _seal(before) != _seal(os.stat(digest, dir_fd=base, follow_symlinks=False))):
                _fail()
            self._directory()
            return result
        finally:
            os.close(fd)

    def _description(self, directory, digest):
        value = self._inspect(directory, digest)
        fields = {'schema', 'identitySha256', 'revision', 'accountId', 'origin',
                  'totpEnabled', 'requireTotpAfterPasskey', 'credentials'}
        if (type(value) is not dict or set(value) != fields
                or value['schema'] != 'orbis.sentinel-identity-description.v1' or value['identitySha256'] != digest):
            _fail()
        return sessions._enrollment({key: item for key, item in value.items() if key != 'schema'})

    def _prepared(self, value):
        if type(value) is not PreparedProfile or value._owner is not self:
            _fail()
        return value.digest

    def prepare(self, identity_bytes):
        """Durably retain and inspect bytes before changing any operator authority.

        Failed or incomplete candidates are retained for supervised reconciliation;
        neither a working profile nor an incomplete file is overwritten.
        """
        if type(identity_bytes) is not bytes or not 1 <= len(identity_bytes) <= _MAX_BYTES:
            _fail()
        digest = hashlib.sha256(identity_bytes).hexdigest()
        with self._store._mutex:
            try:
                base = self._directory(create=True)
                names = os.listdir(base)
                if any(not _DIGEST.fullmatch(name) for name in names):
                    _fail()
                if digest not in names:
                    if len(names) >= _MAX_PROFILES:
                        _fail()
                    os.mkdir(digest, mode=0o700, dir_fd=base)
                    directory = os.open(digest, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=base)
                    try:
                        fd = os.open('identity.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     0o600, dir_fd=directory)
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(identity_bytes)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.fsync(directory)
                        os.fsync(base)
                    finally:
                        os.close(directory)
                metadata = self._run(digest, self._description)
                return PreparedProfile(digest, self, json.dumps(metadata, sort_keys=True, separators=(',', ':')))
            except Exception:
                _fail()

    def inspect_retained(self, digest):
        """Inspect retained material without a producer or automatic activation."""
        with self._store._mutex:
            try:
                metadata = self._run(digest, self._description)
                return PreparedProfile(digest, self, json.dumps(metadata, sort_keys=True, separators=(',', ':')))
            except Exception:
                _fail()

    def begin(self, prepared, *, expected_generation, expected_revision):
        with self._store._mutex:
            try:
                digest = self._prepared(prepared)
                metadata = self._run(digest, self._description)
                if json.dumps(metadata, sort_keys=True, separators=(',', ':')) != prepared._metadata:
                    _fail()
                return self._store.begin_operator_enrollment(expected_generation=expected_generation,
                                                              expected_revision=expected_revision,
                                                              identity_sha256=digest, origin=metadata['origin'])
            except Exception:
                _fail()

    def complete(self, prepared, *, change_token, expected_generation):
        with self._store._mutex:
            try:
                digest = self._prepared(prepared)
                def inspected(target):
                    if target != digest:
                        _fail()
                    value = self._run(target, self._description)
                    if json.dumps(value, sort_keys=True, separators=(',', ':')) != prepared._metadata:
                        _fail()
                    return {'schema': 'orbis.sentinel-identity-description.v1', **value}
                return self._store.inspect_operator_enrollment(change_token=change_token,
                                                               expected_generation=expected_generation, inspector=inspected)
            except Exception:
                _fail()

    def verify(self, digest, challenge, credentials):
        """The session store, not a browser field, selects the active digest."""
        with self._store._mutex:
            try:
                return self._run(digest, lambda directory, expected: self._verify_worker(directory, expected, challenge, credentials))
            except Exception:
                _fail()

    def close(self):
        with self._store._mutex:
            self._closed = True
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
