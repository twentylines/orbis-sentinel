"""Detached data verification. This module conveys no lifecycle authority."""
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass


class VerificationError(ValueError):
    """Verification failed; any private snapshot is retained."""


class CleanupIndeterminate(VerificationError):
    """An owned verifier may still exist and requires reconciliation."""


@dataclass(frozen=True)
class VerificationResult:
    publication: dict
    snapshot_id: str


_HASH = re.compile(r'[0-9a-f]{64}\Z')
_IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')
_SAFE = 9007199254740991
_LIMIT = 2**36
_FIELDS = {'schema', 'pointId', 'ownerId', 'createdAt', 'pointSha256', 'pointReservationSha256', 'metadataSha256', 'cipherBytes', 'cipherSha256', 'manifestSha256', 'imageInventorySha256', 'captureReceiptSha256', 'sourceSha256', 'checkpointSha256', 'checkpoint', 'resourceCount', 'imageCount'}
_HASH_FIELDS = {'pointSha256', 'pointReservationSha256', 'metadataSha256', 'cipherSha256', 'manifestSha256', 'imageInventorySha256', 'captureReceiptSha256', 'sourceSha256', 'checkpointSha256'}


def _fail():
    raise VerificationError('Saved capture verification failed')


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _exact(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(data):
    return json.loads(data, object_pairs_hook=_unique, parse_constant=lambda _: _fail())


def _expectation(value):
    if not _exact(value, ['pointId', 'sourceSha256', 'checkpointSha256', 'captureReceiptSha256', 'resourceCount', 'images', 'compatibility', 'checkpoint']):
        _fail()
    if not isinstance(value['pointId'], str) or not _UUID.fullmatch(value['pointId']):
        _fail()
    if any(not isinstance(value[k], str) or not _HASH.fullmatch(value[k]) for k in ('sourceSha256', 'checkpointSha256', 'captureReceiptSha256')) or not _integer(value['resourceCount'], 1, 4096):
        _fail()
    images, checkpoint, compat = value['images'], value['checkpoint'], value['compatibility']
    if not _exact(images, ['controller', 'database', 'queue']) or any(not isinstance(v, str) or not _IMAGE.fullmatch(v) for v in images.values()):
        _fail()
    if not _exact(checkpoint, ['bytes', 'sha256']) or not _integer(checkpoint['bytes'], 1, 2**36 - 32 - 2**20) or not isinstance(checkpoint['sha256'], str) or not _HASH.fullmatch(checkpoint['sha256']):
        _fail()
    if not _exact(compat, ['os', 'architecture', 'database', 'storageFormat']) or compat['os'] != 'linux' or compat['architecture'] not in ('amd64', 'arm64') or compat['storageFormat'] != 'physical-pgdata.v1':
        _fail()
    db = compat['database']
    if not _exact(db, ['engine', 'major']) or db['engine'] != 'postgresql' or not _integer(db['major'], 1, 99):
        _fail()
    encoded = _canonical(value)
    if len(encoded.encode()) > 8192:
        _fail()
    return _json(encoded), encoded


def _seal(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _dirseal(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)


def _open_absolute(path):
    if not isinstance(path, str) or not path.startswith('/') or os.path.normpath(path) != path or os.path.realpath(path) != path or ',' in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        _fail()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.split('/')[1:]:
            if not part:
                continue
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _secure_scratch(path, owner):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in ['', *path.split('/')[1:]]:
            if part:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            item = os.fstat(fd)
            if item.st_uid != owner or item.st_mode & 0o022:
                _fail()
    finally:
        os.close(fd)


def _kernel_read(path, limit):
    with open(path, 'rb') as stream:
        body = stream.read(limit + 1)
    if not body or len(body) > limit:
        _fail()
    return body.decode('utf8', errors='surrogateescape')


def _mount_id(descriptor):
    body = _kernel_read('/proc/self/fdinfo/' + str(descriptor), 8192)
    fields = [line.split(':', 1)[1].strip() for line in body.splitlines() if line.startswith('mnt_id:')]
    if len(fields) != 1 or not re.fullmatch(r'[1-9][0-9]*', fields[0]):
        _fail()
    return int(fields[0])


def _mount_path(value):
    if re.search(r'\\(?!040|011|012|134)', value):
        _fail()
    value = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), value)
    if (not value.startswith('/') or os.path.normpath(value) != value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _fail()
    return value


def _mount_coordinates(path, descriptor, body):
    selected = []
    mount_id = _mount_id(descriptor)
    for line in body.splitlines():
        fields = line.split(' ')
        if len(fields) < 10 or ' - ' not in line or not re.fullmatch(r'[1-9][0-9]*', fields[0]):
            _fail()
        if int(fields[0]) == mount_id:
            selected.append(fields)
    if len(selected) != 1:
        _fail()
    fields = selected[0]
    if not re.fullmatch(r'[0-9]+:[0-9]+', fields[2]):
        _fail()
    device = tuple(int(part) for part in fields[2].split(':'))
    opened = os.fstat(descriptor)
    if device != (os.major(opened.st_dev), os.minor(opened.st_dev)):
        _fail()
    root, mount = _mount_path(fields[3]), _mount_path(fields[4])
    if os.path.commonpath([mount, path]) != mount:
        _fail()
    relative = os.path.relpath(path, mount)
    return device, os.path.normpath(os.path.join(root, relative))


def _require_disjoint(data, data_fd, scratch, scratch_fd):
    # Resolve bind roots using the opened descriptors' mount IDs, not path spelling.
    body = _kernel_read('/proc/self/mountinfo', 4 * 1024 * 1024)
    source_device, source = _mount_coordinates(data, data_fd, body)
    target_device, target = _mount_coordinates(scratch, scratch_fd, body)
    if source_device == target_device and os.path.commonpath([source, target]) in (source, target):
        _fail()


def _directory(parent, name, owner, private=True):
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    s = os.fstat(fd)
    if s.st_uid != owner or (stat.S_IMODE(s.st_mode) != 0o700 if private else bool(s.st_mode & 0o022)):
        os.close(fd)
        _fail()
    return fd, s


def _copy(parent, name, destination, maximum, owner, exact=None):
    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) not in (0o400, 0o600) or not 1 <= before.st_size <= maximum or (exact is not None and before.st_size != exact):
            _fail()
        digest = hashlib.sha256()
        target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            remaining = before.st_size
            while remaining:
                chunk = os.read(source, min(65536, remaining))
                if not chunk:
                    _fail()
                remaining -= len(chunk)
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    if written <= 0:
                        _fail()
                    view = view[written:]
            if os.read(source, 1) or _seal(before) != _seal(os.fstat(source)) or _seal(before) != _seal(os.stat(name, dir_fd=parent, follow_symlinks=False)):
                _fail()
            os.fsync(target)
        finally:
            os.close(target)
        return digest.hexdigest(), before.st_size, _seal(before)
    finally:
        os.close(source)


def _copy_key_descriptor(source, destination, owner):
    before = os.fstat(source)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) not in (0o400, 0o600) or before.st_size != 32):
        _fail()
    value = os.pread(source, 33, 0)
    if len(value) != 32 or _seal(before) != _seal(os.fstat(source)):
        _fail()
    target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        remaining = memoryview(value)
        while remaining:
            written = os.write(target, remaining)
            if not written:
                _fail()
            remaining = remaining[written:]
        os.fsync(target)
    finally:
        os.close(target)
    return hashlib.sha256(value).hexdigest(), 32, _seal(before)


def _snapshot_point(data, scratch, expected, owner, *, master_key_fd=None, include_assets=False):
    data_fd = _open_absolute(data)
    try:
        scratch_fd = _open_absolute(scratch)
    except BaseException:
        os.close(data_fd)
        raise
    dirs = []
    try:
        _secure_scratch(scratch, owner)
        ds, ss = os.fstat(data_fd), os.fstat(scratch_fd)
        if ds.st_uid != owner or ds.st_mode & 0o022 or ss.st_uid != owner or stat.S_IMODE(ss.st_mode) != 0o700 or os.path.commonpath([data, scratch]) in (data, scratch):
            _fail()
        _require_disjoint(data, data_fd, scratch, scratch_fd)
        name = ('catalog-' if include_assets else 'capture-') + secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=scratch_fd)
        root = os.path.join(scratch, name)
        destination = os.path.join(root, 'data', 'backups', 'time-machine')
        for suffix in ('', 'points', 'points/' + expected['pointId'], 'keys', 'core-verification'):
            os.makedirs(os.path.join(destination, suffix), mode=0o700, exist_ok=True)
        # Explicitly constrain all copied-data directories, regardless of umask.
        for path in (os.path.join(root, 'data'), os.path.join(root, 'data', 'backups'), destination, os.path.join(destination, 'points'), os.path.join(destination, 'points', expected['pointId']), os.path.join(destination, 'keys'), os.path.join(destination, 'core-verification')):
            os.chmod(path, 0o700)
        parent = data_fd
        for component, private in (('backups', False), ('time-machine', True)):
            fd, before = _directory(parent, component, owner, private)
            dirs.append((parent, component, fd, before))
            parent = fd
        base = parent
        points, points_s = _directory(base, 'points', owner)
        dirs.append((base, 'points', points, points_s))
        point, point_s = _directory(points, expected['pointId'], owner)
        dirs.append((points, expected['pointId'], point, point_s))
        keys = None
        if master_key_fd is None:
            keys, keys_s = _directory(base, 'keys', owner)
            dirs.append((base, 'keys', keys, keys_s))
        required = {'point.json', 'metadata.orbis', 'core.orbis'}
        permitted = required | {'capture-draft.orbis', 'wallpaper.orbis', 'icons.orbis'}
        point_names = set(os.listdir(point))
        if not required <= point_names <= permitted or (keys is not None and set(os.listdir(keys)) != {'master-v1.key'}):
            _fail()
        extras = {}
        for extra in point_names - required:
            fd = os.open(extra, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=point)
            try:
                item = os.fstat(fd)
                if not stat.S_ISREG(item.st_mode) or item.st_uid != owner or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) not in (0o400, 0o600):
                    _fail()
                extras[extra] = _seal(item)
            finally:
                os.close(fd)
        target = os.path.join(destination, 'points', expected['pointId'])
        hashes = {}
        for filename, limit in (('point.json', 32768), ('metadata.orbis', 524340), ('core.orbis', _LIMIT)):
            hashes[filename] = _copy(point, filename, os.path.join(target, filename), limit, owner)
        if include_assets:
            limits = {'capture-draft.orbis': 524340, 'wallpaper.orbis': 32 * 1024**2 + 52,
                      'icons.orbis': 24 * 1024**2 + 52}
            for filename in sorted(point_names - required):
                hashes[filename] = _copy(point, filename, os.path.join(target, filename), limits[filename], owner)
        key_target = os.path.join(destination, 'keys', 'master-v1.key')
        hashes['key'] = (_copy(keys, 'master-v1.key', key_target, 32, owner, 32) if keys is not None
                         else _copy_key_descriptor(master_key_fd, key_target, owner))
        for filename in sorted(point_names if include_assets else required):
            if _seal(os.stat(filename, dir_fd=point, follow_symlinks=False)) != hashes[filename][2]:
                _fail()
        if keys is not None:
            if _seal(os.stat('master-v1.key', dir_fd=keys, follow_symlinks=False)) != hashes['key'][2]:
                _fail()
        elif _seal(os.fstat(master_key_fd)) != hashes['key'][2]:
            _fail()
        for extra, before in extras.items():
            if _seal(os.stat(extra, dir_fd=point, follow_symlinks=False)) != before:
                _fail()
        if set(os.listdir(point)) != point_names or (keys is not None and set(os.listdir(keys)) != {'master-v1.key'}) or os.path.realpath(data) != data or os.path.realpath(scratch) != scratch:
            _fail()
        for p, component, fd, before in dirs:
            if _dirseal(before) != _dirseal(os.fstat(fd)) or _dirseal(before) != _dirseal(os.stat(component, dir_fd=p, follow_symlinks=False)):
                _fail()
        if _dirseal(ds) != _dirseal(os.fstat(data_fd)) or _dirseal(ds) != _dirseal(os.stat(data, follow_symlinks=False)) or _dirseal(ss) != _dirseal(os.fstat(scratch_fd)) or _dirseal(ss) != _dirseal(os.stat(scratch, follow_symlinks=False)):
            _fail()
        for path in (target, os.path.join(destination, 'keys'), os.path.join(destination, 'points'), os.path.join(destination, 'core-verification'), destination, os.path.join(root, 'data', 'backups'), os.path.join(root, 'data'), root, scratch):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        with open(os.path.join(target, 'point.json'), 'rb') as f:
            value = _json(f.read(32769))
        if type(value) is not dict or value.get('id') != expected['pointId'] or value.get('version') != 3 or value.get('status') != 'sealed' or type(value.get('envelope')) is not dict or value['envelope'].get('keyId') != hashes['key'][0] or value.get('archiveBytes') != hashes['core.orbis'][1] or value.get('archiveSha256') != hashes['core.orbis'][0] or value.get('metadataSha256') != hashes['metadata.orbis'][0]:
            _fail()
        return name, root, value, hashes
    finally:
        for _, _, fd, _ in reversed(dirs):
            os.close(fd)
        os.close(data_fd)
        os.close(scratch_fd)


def _snapshot(data, scratch, expected, owner):
    return _snapshot_point(data, scratch, expected, owner)


class _Docker:
    """The only process transport: fixed local Docker binary and daemon."""
    _WORKER = '/app/core-capture-publication.mjs'
    def _run(self, arguments, timeout=30):
        proc = subprocess.Popen(['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/'}, close_fds=True)
        output = [bytearray(), bytearray()]
        overflow = [False]
        def drain(stream, index):
            while True:
                block = stream.read(4096)
                if not block:
                    break
                remaining = 8192 - len(output[index])
                output[index].extend(block[:max(0, remaining)])
                if len(block) > remaining:
                    overflow[0] = True
        threads = [threading.Thread(target=drain, args=(proc.stdout, 0)), threading.Thread(target=drain, args=(proc.stderr, 1))]
        for thread in threads:
            thread.start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            for thread in threads:
                thread.join()
            raise TimeoutError('Verifier command timed out') from None
        for thread in threads:
            thread.join()
        if overflow[0]:
            raise VerificationError('Verifier output exceeded limit')
        return code, bytes(output[0])

    def create(self, name, nonce, image, data, staging, encoded):
        args = ['create', '--pull=never', '--name', name, '--label', 'orbis.sentinel.verifier=' + nonce, '--network', 'none', '--ipc', 'none', '--no-healthcheck', '--restart', 'no', '--cpus', '1', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '2g', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m', '--mount', 'type=bind,src=' + data + ',dst=/data,readonly', '--mount', 'type=bind,src=' + staging + ',dst=/data/backups/time-machine/core-verification', '--entrypoint', '/usr/local/bin/node', image, self._WORKER, '--verify', encoded]
        code, body = self._run(args)
        if code:
            raise VerificationError('Verifier container creation failed')
        value = body.decode('ascii').strip()
        if not _HASH.fullmatch(value):
            raise VerificationError('Verifier container creation was indeterminate')
        return value

    def find(self, name, nonce):
        code, body = self._run(['ps', '-a', '--no-trunc', '--filter', 'name=^/' + name + '$', '--filter', 'label=orbis.sentinel.verifier=' + nonce, '--format', '{{.ID}}'])
        if code:
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')
        ids = body.decode('ascii').splitlines()
        if len(ids) > 1 or any(not _HASH.fullmatch(x) for x in ids):
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')
        return ids[0] if ids else None

    def exists(self, container):
        code, body = self._run(['ps', '-a', '--no-trunc', '--filter', 'id=' + container, '--format', '{{.ID}}'])
        if code:
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')
        ids = body.decode('ascii').splitlines()
        if len(ids) > 1 or any(not _HASH.fullmatch(item) or item != container for item in ids):
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')
        return container in ids

    def inspect(self, container):
        projection = '{{json .Id}}\n{{json .Name}}\n{{json .Image}}\n{{json (index .Config.Labels "orbis.sentinel.verifier")}}\n{{json .State.Running}}\n{{json .State.ExitCode}}'
        code, body = self._run(['inspect', '--type', 'container', '--format', projection, container])
        if code:
            raise CleanupIndeterminate('Verifier ownership could not be established')
        lines = body.splitlines()
        if len(lines) != 6:
            raise CleanupIndeterminate('Verifier ownership could not be established')
        identity, name, image, nonce, running, exit_code = (_json(line) for line in lines)
        return {'Id': identity, 'Name': name, 'Image': image, 'Config': {'Labels': {'orbis.sentinel.verifier': nonce}}, 'State': {'Running': running, 'ExitCode': exit_code}}

    def start(self, container):
        return self._run(['start', '--attach', container], timeout=1900)

    def remove(self, container):
        code, _ = self._run(['rm', '--force', container], timeout=60)
        if code:
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')


def _owned(transport, container, name, nonce, image):
    info = transport.inspect(container)
    if info.get('Id') != container or info.get('Name') != '/' + name or info.get('Image') != image or info.get('Config', {}).get('Labels', {}).get('orbis.sentinel.verifier') != nonce:
        raise CleanupIndeterminate('Verifier ownership could not be established')
    return info


def _publication(result, expected, point, hashes, owner, created):
    if not _exact(result, _FIELDS) or result['schema'] != 'orbis.core-capture-publication.v1' or any(not isinstance(result[k], str) or not _HASH.fullmatch(result[k]) for k in _HASH_FIELDS):
        _fail()
    if result['pointId'] != expected['pointId'] or type(result['ownerId']) is not int or result['ownerId'] != owner or type(result['createdAt']) is not int or result['createdAt'] != created or type(point.get('ownerId')) is not int or point.get('ownerId') != owner or type(point.get('createdAt')) is not int or point.get('createdAt') != created:
        _fail()
    if not _exact(result['checkpoint'], ['bytes', 'sha256']) or type(result['checkpoint']['bytes']) is not int or not isinstance(result['checkpoint']['sha256'], str):
        _fail()
    if any(result[k] != expected[k] for k in ('sourceSha256', 'checkpointSha256', 'captureReceiptSha256', 'checkpoint', 'resourceCount')) or type(result['resourceCount']) is not int or type(result['imageCount']) is not int or result['imageCount'] != len(set(expected['images'].values())):
        _fail()
    reservation = {k: point[k] for k in ('version', 'id', 'ownerId', 'createdAt', 'envelope')}
    if result['pointReservationSha256'] != hashlib.sha256(_canonical(reservation).encode()).hexdigest() or result['pointSha256'] != hashes['point.json'][0] or result['metadataSha256'] != hashes['metadata.orbis'][0] or result['cipherSha256'] != hashes['core.orbis'][0] or type(result['cipherBytes']) is not int or result['cipherBytes'] != hashes['core.orbis'][1] or not expected['checkpoint']['bytes'] + 52 < result['cipherBytes'] <= _LIMIT:
        _fail()
    return result


def _execute_worker(transport, root, image_id, encoded, validate):
    nonce = secrets.token_hex(16)
    name = 'orbis-sentinel-verifier-' + nonce
    receipt = os.path.join(root, 'verifier-receipt.jsonl')
    with open(receipt, 'x', encoding='ascii') as stream:
        os.chmod(receipt, 0o600)
        stream.write(_canonical({'name': name, 'nonce': nonce, 'image': image_id}))
        stream.flush()
        os.fsync(stream.fileno())
    receipt_dir = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(receipt_dir)
    finally:
        os.close(receipt_dir)
    container = None
    creation_indeterminate = False
    failure = None
    result = None
    try:
        try:
            container = transport.create(name, nonce, image_id, os.path.join(root, 'data'), os.path.join(root, 'data', 'backups', 'time-machine', 'core-verification'), encoded)
        except Exception:
            creation_indeterminate = True
            container = transport.find(name, nonce)
            if container is not None:
                creation_indeterminate = False
                with open(receipt, 'a', encoding='ascii') as stream:
                    stream.write('\n' + _canonical({'containerId': container}) + '\n')
                    stream.flush()
                    os.fsync(stream.fileno())
            raise
        with open(receipt, 'a', encoding='ascii') as stream:
            stream.write('\n' + _canonical({'containerId': container}) + '\n')
            stream.flush()
            os.fsync(stream.fileno())
        _owned(transport, container, name, nonce, image_id)
        code, output = transport.start(container)
        info = _owned(transport, container, name, nonce, image_id)
        if code != 0 or info.get('State', {}).get('Running') is not False or info.get('State', {}).get('ExitCode') != 0 or len(output) > 8192:
            _fail()
        result = validate(_json(output))
    except Exception as exc:
        failure = exc
    try:
        if container is not None:
            _owned(transport, container, name, nonce, image_id)
            transport.remove(container)
        if (container is not None and transport.exists(container)) or transport.find(name, nonce) is not None:
            raise CleanupIndeterminate('Verifier cleanup is indeterminate')
    except Exception:
        raise CleanupIndeterminate('Verifier cleanup is indeterminate') from None
    if creation_indeterminate:
        raise CleanupIndeterminate('Verifier creation is indeterminate') from None
    if failure is not None:
        raise VerificationError('Saved capture verification failed') from None
    return result


def verify_saved_capture(*, data_directory, scratch_directory, image_id, expectation, owner_id, created_at, runner=None):
    """Verify an isolated copy and retain it; snapshot_id is relative to scratch_directory.

    The result does not authorize capture, adoption, lease release, or any app mutation.
    runner is an internal transport seam for tests, not a command interface.
    """
    if sys.platform != 'linux' or os.geteuid() != 0:
        _fail()
    if not isinstance(image_id, str) or not _IMAGE.fullmatch(image_id) or not _integer(owner_id, 1, _SAFE) or not _integer(created_at, 1, _SAFE):
        _fail()
    try:
        expected, encoded = _expectation(expectation)
        snapshot_id, root, point, hashes = _snapshot(data_directory, scratch_directory, expected, 0)
        _secure_scratch(scratch_directory, 0)
        transport = runner if runner is not None else _Docker()
        result = _execute_worker(transport, root, image_id, encoded,
                                 lambda value: _publication(value, expected, point, hashes, owner_id, created_at))
        summary = _canonical({
            'schema': 'orbis-sentinel.capture-data-verification.v1',
            'snapshotId': snapshot_id, 'imageId': image_id, 'expectation': expected,
            'ownerId': owner_id, 'createdAt': created_at, 'publication': result,
        }).encode('utf8')
        descriptor = os.open(os.path.join(root, 'verification.json'),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            remaining = memoryview(summary)
            while remaining:
                written = os.write(descriptor, remaining)
                if not written:
                    _fail()
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return VerificationResult(publication=result, snapshot_id=snapshot_id)
    except CleanupIndeterminate:
        raise
    except Exception:
        raise VerificationError('Saved capture verification failed') from None
