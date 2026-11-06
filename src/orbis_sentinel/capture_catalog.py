"""Durable capture data catalog; it grants no lifecycle authority."""
import fcntl
import hashlib
import os
import re
import secrets
import stat
import sys
import threading
import time
from contextlib import contextmanager, ExitStack

from . import verification as v

_OWNER_UID = 0
_REQUIRED = {'point.json', 'metadata.orbis', 'core.orbis'}
_ALLOWED = _REQUIRED | {'capture-draft.orbis', 'wallpaper.orbis', 'icons.orbis'}
_DRAFT_REQUIRED = {'point.json', 'capture-draft.orbis'}
_DRAFT_ALLOWED = _DRAFT_REQUIRED | {'wallpaper.orbis', 'icons.orbis'}
_STAGE = re.compile(r'(?:stage|catalog)-[0-9a-f]{32}\Z')
_JOB = re.compile(r'[0-9a-f]{32}\Z')
_MAX_RECORD = 131072
_MAX_ENTRIES = 10000
_LIMITS = {'point.json': 32768, 'metadata.orbis': 524340,
           'capture-draft.orbis': 524340, 'wallpaper.orbis': 32 * 1024 * 1024 + 52,
           'icons.orbis': 24 * 1024 * 1024 + 52, 'core.orbis': v._LIMIT}


class CatalogError(ValueError):
    """Catalog state is unavailable or failed integrity checks."""


def _fail():
    raise CatalogError('Capture catalog operation failed')


def _persistent(fd):
    mount_id = v._mount_id(fd)
    lines = v._kernel_read('/proc/self/mountinfo', 4 * 1024 * 1024).splitlines()
    matches = [line for line in lines if line.split(' ', 1)[0] == str(mount_id)]
    if len(matches) != 1 or ' - ' not in matches[0]:
        _fail()
    fs = matches[0].split(' - ', 1)[1].split(' ', 1)[0]
    if fs in {'tmpfs', 'ramfs', 'overlay', 'proc', 'sysfs', 'devtmpfs', 'squashfs'}:
        _fail()


def _nested_mounts(directory):
    body = v._kernel_read('/proc/self/mountinfo', 4 * 1024 * 1024)
    paths = []
    for line in body.splitlines():
        fields = line.split(' ')
        if len(fields) < 10 or ' - ' not in line:
            _fail()
        mount = v._mount_path(fields[4])
        if mount != directory and os.path.commonpath((directory, mount)) == directory:
            paths.append(mount)
    return sorted(set(paths))


def _regular(fd, limit, exact=None):
    s = os.fstat(fd)
    if (not stat.S_ISREG(s.st_mode) or s.st_uid != _OWNER_UID or s.st_nlink != 1
            or stat.S_IMODE(s.st_mode) not in (0o400, 0o600)
            or s.st_size < 1 or s.st_size > limit or (exact is not None and s.st_size != exact)):
        _fail()
    return s


def _read_fd(fd, limit, exact=None, collect=True):
    before = _regular(fd, limit, exact)
    digest = hashlib.sha256()
    body = bytearray()
    offset = 0
    while offset < before.st_size:
        block = os.pread(fd, min(65536, before.st_size - offset), offset)
        if not block:
            _fail()
        digest.update(block)
        if collect:
            body.extend(block)
        offset += len(block)
    if os.pread(fd, 1, offset) or v._seal(before) != v._seal(os.fstat(fd)):
        _fail()
    return bytes(body), digest.hexdigest(), before


def _read(parent, name, limit, exact=None, collect=True):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        body, digest, before = _read_fd(fd, limit, exact, collect)
        if v._seal(before) != v._seal(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            _fail()
        return body, digest, before
    finally:
        os.close(fd)


def _write(parent, name, body):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(body)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                _fail()
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _json_read(parent, name):
    body, _, _ = _read(parent, name, _MAX_RECORD)
    value = v._json(body)
    if v._canonical(value).encode() != body:
        _fail()
    return value


def _reservation(value):
    if not v._exact(value, ('version', 'id', 'ownerId', 'createdAt', 'envelope')) or type(value['version']) is not int or value['version'] != 3 or not isinstance(value['id'], str) or not v._UUID.fullmatch(value['id']) or not v._integer(value['ownerId'], 1, v._SAFE) or not v._integer(value['createdAt'], 1, v._SAFE):
        _fail()
    e = value['envelope']
    if not v._exact(e, ('version', 'keyId', 'nonce', 'tag', 'value')) or type(e['version']) is not int or e['version'] != 1:
        _fail()
    for k, n in (('keyId', 64), ('nonce', 24), ('tag', 32), ('value', 86)):
        if not isinstance(e[k], str) or not re.fullmatch('[0-9a-f]{%d}' % n, e[k]):
            _fail()
    return v._json(v._canonical(value))


def _dir(parent, name):
    fd, s = v._directory(parent, name, _OWNER_UID)
    return fd, v._dirseal(s)


def _names(fd):
    names = os.listdir(fd)
    if len(names) > _MAX_ENTRIES:
        _fail()
    return set(names)


class CaptureCatalog:
    def __init__(self, directory):
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._fds = []
        self._closed = False
        try:
            if sys.platform != 'linux' or os.geteuid() != _OWNER_UID:
                _fail()
            v._secure_scratch(directory, _OWNER_UID)
            self._path = directory
            self._root = v._open_absolute(directory)
            self._fds.append(self._root)
            s = os.fstat(self._root)
            if s.st_uid != _OWNER_UID or stat.S_IMODE(s.st_mode) != 0o700:
                _fail()
            self._root_seal = v._dirseal(s)
            _persistent(self._root)
            self._mount = v._mount_id(self._root)
            lock = os.open('catalog.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self._root)
            self._fds.append(lock)
            ls = os.fstat(lock)
            if not stat.S_ISREG(ls.st_mode) or ls.st_uid != _OWNER_UID or ls.st_nlink != 1 or stat.S_IMODE(ls.st_mode) != 0o600:
                _fail()
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.fsync(lock)
            os.fsync(self._root)
            self._lock = lock
            self._lock_identity = (ls.st_dev, ls.st_ino, ls.st_mode, ls.st_uid, ls.st_gid, ls.st_nlink)
            self._children = {}
            for name in ('reservations', 'objects', 'prepared', 'work'):
                try:
                    os.mkdir(name, 0o700, dir_fd=self._root)
                    os.fsync(self._root)
                except FileExistsError:
                    pass
                fd, seal = _dir(self._root, name)
                self._fds.append(fd)
                if os.fstat(fd).st_dev != s.st_dev or v._mount_id(fd) != self._mount:
                    _fail()
                self._children[name] = (fd, seal)
            self._check()
        except Exception:
            for fd in reversed(self._fds):
                os.close(fd)
            self._closed = True
            raise CatalogError('Capture catalog operation failed') from None

    def _check(self):
        if self._closed or os.getpid() != self._pid:
            _fail()
        v._secure_scratch(self._path, _OWNER_UID)
        if v._dirseal(os.fstat(self._root)) != self._root_seal or v._dirseal(os.stat(self._path, follow_symlinks=False)) != self._root_seal or v._mount_id(self._root) != self._mount:
            _fail()
        ls = os.fstat(self._lock)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink)
        if identity(ls) != self._lock_identity or identity(os.stat('catalog.lock', dir_fd=self._root, follow_symlinks=False)) != self._lock_identity:
            _fail()
        for name, (fd, seal) in self._children.items():
            if v._dirseal(os.fstat(fd)) != seal or v._dirseal(os.stat(name, dir_fd=self._root, follow_symlinks=False)) != seal or v._mount_id(fd) != self._mount:
                _fail()

    @contextmanager
    def _operation(self):
        if os.getpid() != self._pid:
            _fail()
        with self._mutex:
            try:
                self._check()
                yield
                self._check()
            except v.CleanupIndeterminate:
                raise
            except Exception:
                raise CatalogError('Capture catalog operation failed') from None

    def __enter__(self):
        with self._operation():
            return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if os.getpid() != self._pid:
            _fail()
        with self._mutex:
            if not self._closed:
                try:
                    self._check()
                finally:
                    self._closed = True
                    for fd in reversed(self._fds):
                        os.close(fd)

    def _stage(self):
        work = self._children['work'][0]
        name = 'stage-' + secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=work)
        os.fsync(work)
        fd, _ = _dir(work, name)
        return name, fd

    def _record(self, point):
        if not isinstance(point, str) or not v._UUID.fullmatch(point):
            _fail()
        parent = self._children['reservations'][0]
        fd, seal = _dir(parent, point)
        try:
            if _names(fd) != {'record.json', 'master-v1.key'}:
                _fail()
            record = _json_read(fd, 'record.json')
            if not v._exact(record, ('schema', 'jobId', 'installationId', 'sourceSha256', 'recoveryImageId', 'reservation')) or record['schema'] != 'orbis-sentinel.capture-reservation.v1':
                _fail()
            self._validate_binding(record)
            if record['reservation']['id'] != point:
                _fail()
            _, digest, _ = _read(fd, 'master-v1.key', 32, 32)
            if digest != record['reservation']['envelope']['keyId'] or v._dirseal(os.fstat(fd)) != seal or v._dirseal(os.stat(point, dir_fd=parent, follow_symlinks=False)) != seal:
                _fail()
            return record
        finally:
            os.close(fd)

    @staticmethod
    def _validate_binding(record):
        if not isinstance(record['jobId'], str) or not _JOB.fullmatch(record['jobId']) or any(not isinstance(record[k], str) or not v._HASH.fullmatch(record[k]) for k in ('installationId', 'sourceSha256')) or not isinstance(record['recoveryImageId'], str) or not v._IMAGE.fullmatch(record['recoveryImageId']):
            _fail()
        _reservation(record['reservation'])

    @contextmanager
    def _source_boundary(self, data_directory):
        source = v._open_absolute(data_directory)
        try:
            before = v._dirseal(os.fstat(source))
            def disjoint():
                if os.path.commonpath((data_directory, self._path)) in (data_directory, self._path):
                    _fail()
                v._require_disjoint(data_directory, source, self._path, self._root)
                # A nested bind can expose catalog backing under a different name.
                for mount in _nested_mounts(data_directory):
                    descriptor = v._open_absolute(mount)
                    try:
                        v._require_disjoint(mount, descriptor, self._path, self._root)
                    finally:
                        os.close(descriptor)
            disjoint()
            yield
            if (v._dirseal(os.fstat(source)) != before
                    or v._dirseal(os.stat(data_directory, follow_symlinks=False)) != before):
                _fail()
            disjoint()
        finally:
            os.close(source)

    def reserve(self, *, job_id, installation_id, source_sha256, recovery_image_id, reservation, key_fd, data_directory, additional_data_directories=()):
        with self._operation(), ExitStack() as boundaries:
            if (not isinstance(additional_data_directories, (tuple, list)) or len(additional_data_directories) > 64
                    or any(not isinstance(directory, str) for directory in additional_data_directories)):
                _fail()
            for directory in dict.fromkeys((data_directory, *additional_data_directories)):
                boundaries.enter_context(self._source_boundary(directory))
            r = _reservation(reservation)
            record = {'schema': 'orbis-sentinel.capture-reservation.v1', 'jobId': job_id, 'installationId': installation_id, 'sourceSha256': source_sha256, 'recoveryImageId': recovery_image_id, 'reservation': r}
            self._validate_binding(record)
            key, digest, _ = _read_fd(key_fd, 32, 32)
            if digest != r['envelope']['keyId']:
                _fail()
            parent = self._children['reservations'][0]
            if r['id'] in _names(parent):
                if self._record(r['id']) != record:
                    _fail()
                return self._get(r['id'])
            stage, fd = self._stage()
            try:
                _write(fd, 'master-v1.key', key)
                _write(fd, 'record.json', v._canonical(record).encode())
                os.fsync(fd)
                os.rename(stage, r['id'], src_dir_fd=self._children['work'][0], dst_dir_fd=parent)
                os.fsync(parent)
                os.fsync(self._children['work'][0])
            finally:
                os.close(fd)
            return self._get(r['id'])

    def _files(self, fd, recorded=None, *, required=_REQUIRED, allowed=_ALLOWED):
        names = _names(fd)
        if not required <= names <= allowed:
            _fail()
        if recorded is not None and (type(recorded) is not dict or set(recorded) != names):
            _fail()
        files, seals = {}, {}
        for name in sorted(names):
            limit = _LIMITS[name]
            if recorded is None:
                _, digest, s = _read(fd, name, limit, collect=False)
            else:
                entry = recorded[name]
                if (not v._exact(entry, ('bytes', 'sha256')) or not v._integer(entry['bytes'], 1, limit)
                        or not isinstance(entry['sha256'], str) or not v._HASH.fullmatch(entry['sha256'])):
                    _fail()
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    s = _regular(opened, limit, entry['bytes'])
                    if v._seal(s) != v._seal(os.stat(name, dir_fd=fd, follow_symlinks=False)):
                        _fail()
                finally:
                    os.close(opened)
                digest = entry['sha256']
            files[name] = {'bytes': s.st_size, 'sha256': digest}
            seals[name] = list(v._seal(s))
        if _names(fd) != names:
            _fail()
        return files, seals

    @staticmethod
    def _draft_point(fd, reservation):
        point = v._json(_read(fd, 'point.json', _LIMITS['point.json'])[0])
        if (not isinstance(point, dict) or point.get('status') != 'capturing'
                or any(k not in point for k in reservation)
                or v._canonical({k: point[k] for k in reservation}) != v._canonical(reservation)):
            _fail()

    def _draft(self, point, binding):
        parent = self._children['prepared'][0]
        fd, seal = _dir(parent, point)
        try:
            full_seal = v._seal(os.fstat(fd))
            if v._mount_id(fd) != self._mount or _names(fd) != {'record.json', 'point'}:
                _fail()
            record = _json_read(fd, 'record.json')
            if (not v._exact(record, ('schema', 'binding', 'preparationSha256', 'sourceHoldSha256', 'files', 'seals'))
                    or record['schema'] != 'orbis-sentinel.capture-draft.v1'
                    or v._canonical(record['binding']) != v._canonical(binding)
                    or any(not isinstance(record[k], str) or not v._HASH.fullmatch(record[k])
                           for k in ('preparationSha256', 'sourceHoldSha256'))):
                _fail()
            pfd, ps = _dir(fd, 'point')
            try:
                pfull = v._seal(os.fstat(pfd))
                if v._mount_id(pfd) != self._mount:
                    _fail()
                files, seals = self._files(pfd, record['files'], required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED)
                if seals != record['seals']:
                    _fail()
                self._draft_point(pfd, binding['reservation'])
                if (v._seal(os.fstat(pfd)) != pfull or v._seal(os.stat('point', dir_fd=fd, follow_symlinks=False)) != pfull
                        or self._files(pfd, record['files'], required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED) != (files, seals)):
                    _fail()
            finally:
                os.close(pfd)
            if (v._seal(os.fstat(fd)) != full_seal or v._seal(os.stat(point, dir_fd=parent, follow_symlinks=False)) != full_seal
                    or _names(fd) != {'record.json', 'point'} or _json_read(fd, 'record.json') != record):
                _fail()
            return record
        finally:
            os.close(fd)

    @staticmethod
    def _draft_summary(point, record):
        return {'id': point, 'dataState': 'retained-unverified', 'lifecycleState': 'unobserved',
                'preparationSha256': record['preparationSha256'], 'sourceHoldSha256': record['sourceHoldSha256'],
                'files': sorted(record['files'])}

    def draft(self, point_id):
        """Observe retained bytes; this grants no verification or lifecycle authority."""
        with self._operation():
            binding = self._record(point_id)
            return self._draft_summary(point_id, self._draft(point_id, binding))

    def retain_draft(self, point_id, *, point_fd, preparation_sha256, source_hold_sha256):
        """Retain original draft bytes without granting capture or release authority."""
        with self._operation():
            binding = self._record(point_id)
            if (type(point_fd) is not int or point_fd < 0
                    or fcntl.fcntl(point_fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                    or any(not isinstance(x, str) or not v._HASH.fullmatch(x)
                           for x in (preparation_sha256, source_hold_sha256))):
                _fail()
            initial = os.fstat(point_fd)
            if (not stat.S_ISDIR(initial.st_mode) or initial.st_uid != _OWNER_UID
                    or stat.S_IMODE(initial.st_mode) != 0o700):
                _fail()
            initial_seal = v._seal(initial)
            files, source_seals = self._files(point_fd, required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED)
            self._draft_point(point_fd, binding['reservation'])
            parent = self._children['prepared'][0]
            if point_id in _names(parent):
                record = self._draft(point_id, binding)
                if (record['files'] != files or record['preparationSha256'] != preparation_sha256
                        or record['sourceHoldSha256'] != source_hold_sha256):
                    _fail()
            else:
                stage, target = self._stage()
                try:
                    os.mkdir('point', 0o700, dir_fd=target)
                    pfd, _ = _dir(target, 'point')
                    try:
                        for name in sorted(files):
                            digest, size, seal = v._copy(point_fd, name, '/proc/self/fd/%d/%s' % (pfd, name), _LIMITS[name], _OWNER_UID)
                            if {'bytes': size, 'sha256': digest} != files[name] or list(seal) != source_seals[name]:
                                _fail()
                        os.fsync(pfd)
                        copied, seals = self._files(pfd, required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED)
                        if copied != files:
                            _fail()
                    finally:
                        os.close(pfd)
                    if (v._seal(os.fstat(point_fd)) != initial_seal
                            or self._files(point_fd, files, required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED) != (files, source_seals)):
                        _fail()
                    record = {'schema': 'orbis-sentinel.capture-draft.v1', 'binding': binding,
                              'preparationSha256': preparation_sha256, 'sourceHoldSha256': source_hold_sha256,
                              'files': files, 'seals': seals}
                    _write(target, 'record.json', v._canonical(record).encode())
                    os.fsync(target)
                    os.rename(stage, point_id, src_dir_fd=self._children['work'][0], dst_dir_fd=parent)
                    os.fsync(parent)
                    os.fsync(self._children['work'][0])
                finally:
                    os.close(target)
                record = self._draft(point_id, binding)
            if (v._seal(os.fstat(point_fd)) != initial_seal
                    or self._files(point_fd, files, required=_DRAFT_REQUIRED, allowed=_DRAFT_ALLOWED) != (files, source_seals)):
                _fail()
            return self._draft_summary(point_id, record)

    def _validate_publication(self, pub, expected, reservation, point_fd, files):
        if not v._exact(pub, ('schema', 'core', 'keyId', 'files')) or pub['schema'] != 'orbis.core-capture-catalog-publication.v1' or pub['keyId'] != reservation['envelope']['keyId'] or pub['files'] != files:
            _fail()
        if any(not v._exact(item, ('bytes', 'sha256')) or not v._integer(item['bytes'], 1, v._LIMIT) or not isinstance(item['sha256'], str) or not v._HASH.fullmatch(item['sha256']) for item in pub['files'].values()):
            _fail()
        point = v._json(_read(point_fd, 'point.json', 32768)[0])
        if not isinstance(point, dict) or any(point.get(k) != reservation[k] or type(point.get(k)) is not type(reservation[k]) for k in reservation):
            _fail()
        hashes = {k: (item['sha256'], item['bytes']) for k, item in files.items()}
        v._publication(pub['core'], expected, point, hashes, reservation['ownerId'], reservation['createdAt'])

    def _object(self, point, binding):
        parent = self._children['objects'][0]
        fd, seal = _dir(parent, point)
        try:
            if _names(fd) != {'record.json', 'point'}:
                _fail()
            record = _json_read(fd, 'record.json')
            if not v._exact(record, ('schema', 'binding', 'expectation', 'publication', 'seals', 'verifiedAtNs')) or record['schema'] != 'orbis-sentinel.capture-object.v1' or record['binding'] != binding or not v._integer(record['verifiedAtNs'], 1, 2**63-1):
                _fail()
            expected, _ = v._expectation(record['expectation'])
            if expected['pointId'] != point or expected['sourceSha256'] != binding['sourceSha256']:
                _fail()
            pfd, ps = _dir(fd, 'point')
            try:
                publication = record['publication']
                if not v._exact(publication, ('schema', 'core', 'keyId', 'files')):
                    _fail()
                # Listing observes the recorded verification and current identities.
                # Export/restore must authenticate delivered bytes separately.
                files, seals = self._files(pfd, publication['files'])
                if seals != record['seals']:
                    _fail()
                self._validate_publication(record['publication'], expected, binding['reservation'], pfd, files)
                if v._dirseal(os.fstat(pfd)) != ps or v._dirseal(os.stat('point', dir_fd=fd, follow_symlinks=False)) != ps:
                    _fail()
            finally:
                os.close(pfd)
            if v._dirseal(os.fstat(fd)) != seal or v._dirseal(os.stat(point, dir_fd=parent, follow_symlinks=False)) != seal:
                _fail()
            return record
        finally:
            os.close(fd)

    def _get(self, point):
        if not isinstance(point, str) or not v._UUID.fullmatch(point):
            _fail()
        b = self._record(point)
        r = b['reservation']
        result = {'id': point, 'jobId': b['jobId'], 'installationId': b['installationId'], 'sourceSha256': b['sourceSha256'], 'ownerId': r['ownerId'], 'createdAt': r['createdAt'], 'dataState': 'reserved', 'lifecycleState': 'unobserved', 'archiveBytes': 0, 'files': []}
        if point in _names(self._children['objects'][0]):
            obj = self._object(point, b)
            result.update(dataState='verified', archiveBytes=obj['publication']['files']['core.orbis']['bytes'], files=sorted(obj['publication']['files']), verifiedAtNs=obj['verifiedAtNs'], integrity='recorded')
        return result

    def get(self, point_id):
        with self._operation():
            return self._get(point_id)

    def list(self):
        with self._operation():
            reservations = _names(self._children['reservations'][0])
            objects = _names(self._children['objects'][0])
            if any(not v._UUID.fullmatch(x) for x in reservations | objects) or not objects <= reservations:
                _fail()
            return [self._get(point) for point in sorted(reservations)]

    def pending_work(self):
        with self._operation():
            names = _names(self._children['work'][0])
            if any(not _STAGE.fullmatch(x) for x in names):
                _fail()
            return {'count': len(names), 'stages': sorted(names)}

    def publish(self, point_id, *, data_directory, expectation, verifier=None):
        with self._operation():
            binding = self._record(point_id)
            expected, _ = v._expectation(expectation)
            if expected['pointId'] != point_id or expected['sourceSha256'] != binding['sourceSha256']:
                _fail()
            objects = self._children['objects'][0]
            if point_id in _names(objects):
                if self._object(point_id, binding)['expectation'] != expected:
                    _fail()
                return self._get(point_id)
            reservation = binding['reservation']
            rfd, _ = _dir(self._children['reservations'][0], point_id)
            try:
                keyfd = os.open('master-v1.key', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=rfd)
                try:
                    _, key_hash, key_seal = _read_fd(keyfd, 32, 32)
                    if key_hash != reservation['envelope']['keyId']:
                        _fail()
                    if verifier is None:
                        from .catalog_verification import verify_catalog_capture
                        verifier = verify_catalog_capture
                    result = verifier(data_directory=data_directory, scratch_directory=os.path.join(self._path, 'work'), image_id=binding['recoveryImageId'], expectation=expected, owner_id=reservation['ownerId'], created_at=reservation['createdAt'], master_key_fd=keyfd)
                    _, after_hash, after_seal = _read_fd(keyfd, 32, 32)
                    if after_hash != key_hash or v._seal(after_seal) != v._seal(key_seal) or v._seal(os.stat('master-v1.key', dir_fd=rfd, follow_symlinks=False)) != v._seal(key_seal):
                        _fail()
                finally:
                    os.close(keyfd)
            finally:
                os.close(rfd)
            snapshot = result.snapshot_id
            if not isinstance(snapshot, str) or not re.fullmatch(r'catalog-[0-9a-f]{32}', snapshot):
                _fail()
            work = self._children['work'][0]
            fds = []
            try:
                parent = work
                for name in (snapshot, 'data', 'backups', 'time-machine', 'points', point_id):
                    parent, _ = _dir(parent, name)
                    fds.append(parent)
                    if os.fstat(parent).st_dev != os.fstat(self._root).st_dev or v._mount_id(parent) != self._mount:
                        _fail()
                files, seals = self._files(parent)
                self._validate_publication(result.publication, expected, reservation, parent, files)
                for name in sorted(files):
                    file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
                    try:
                        if list(v._seal(_regular(file_fd, v._LIMIT))) != seals[name]:
                            _fail()
                        os.fsync(file_fd)
                        if list(v._seal(os.fstat(file_fd))) != seals[name]:
                            _fail()
                    finally:
                        os.close(file_fd)
                os.fsync(parent)
                if self._files(parent, files) != (files, seals):
                    _fail()
                stage, target = self._stage()
                try:
                    os.rename(point_id, 'point', src_dir_fd=fds[-2], dst_dir_fd=target)
                    os.fsync(fds[-2])
                    os.fsync(target)
                    record = {'schema': 'orbis-sentinel.capture-object.v1', 'binding': binding, 'expectation': expected, 'publication': result.publication, 'seals': seals, 'verifiedAtNs': time.time_ns()}
                    _write(target, 'record.json', v._canonical(record).encode())
                    os.fsync(target)
                    os.rename(stage, point_id, src_dir_fd=work, dst_dir_fd=objects)
                    os.fsync(objects)
                    os.fsync(work)
                finally:
                    os.close(target)
            finally:
                for fd in reversed(fds):
                    os.close(fd)
            return self._get(point_id)
