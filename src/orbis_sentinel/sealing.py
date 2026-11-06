"""Seal only a caller-prepared private workspace; conveys no lifecycle authority."""
import hashlib
import os
import re
import stat
import sys

from . import verification as v


class _Sealer(v._Docker):
    _WORKER = '/app/core-capture-seal.mjs'

    def create(self, name, nonce, image, data, staging, encoded):
        base = os.path.join(data, 'backups', 'time-machine')
        point = os.path.join(base, 'points', v._json(encoded)['pointId'])
        args = ['create', '--pull=never', '--name', name, '--label', 'orbis.sentinel.verifier=' + nonce,
                '--network', 'none', '--ipc', 'none', '--no-healthcheck', '--restart', 'no',
                '--cpus', '1', '--read-only', '--user', '0:0', '--cap-drop', 'ALL',
                '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '2g',
                '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                '--mount', 'type=bind,src=' + data + ',dst=/data']
        for source in (os.path.join(base, 'keys'), os.path.join(base, 'core-publish-input'),
                       *(os.path.join(point, name) for name in ('capture-draft.orbis', 'wallpaper.orbis', 'icons.orbis') if os.path.exists(os.path.join(point, name)))):
            args += ['--mount', 'type=bind,src=' + source + ',dst=/data/' + os.path.relpath(source, data) + ',readonly']
        args += ['--entrypoint', '/usr/local/bin/node', image, self._WORKER, '--seal', encoded]
        code, body = self._run(args)
        if code:
            raise v.VerificationError('Sealer container creation failed')
        result = body.decode('ascii').strip()
        if not v._HASH.fullmatch(result):
            raise v.VerificationError('Sealer container creation was indeterminate')
        return result


def _read(parent, name, limit, owner, *, content=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in (0o400, 0o600) or not 1 <= before.st_size <= limit):
            v._fail()
        digest, parts, remaining = hashlib.sha256(), [], before.st_size
        while remaining:
            block = os.read(fd, min(65536, remaining))
            if not block:
                v._fail()
            digest.update(block)
            if content:
                parts.append(block)
            remaining -= len(block)
        if os.read(fd, 1) or v._seal(before) != v._seal(os.fstat(fd)) or v._seal(before) != v._seal(os.stat(name, dir_fd=parent, follow_symlinks=False)):
            v._fail()
        return digest.hexdigest(), before.st_size, v._seal(before), b''.join(parts)
    finally:
        os.close(fd)


def _layout(root, expected, owner, sealed=False):
    descriptors = []
    try:
        rootfd = v._open_absolute(root)
        descriptors.append(rootfd)
        rootstat = os.fstat(rootfd)
        if rootstat.st_uid != owner or stat.S_IMODE(rootstat.st_mode) != 0o700:
            v._fail()
        def directory(parent, name):
            fd, _ = v._directory(parent, name, owner)
            descriptors.append(fd)
            return fd
        data = directory(rootfd, 'data')
        backups = directory(data, 'backups')
        base = directory(backups, 'time-machine')
        points = directory(base, 'points')
        point = directory(points, expected['pointId'])
        keys = directory(base, 'keys')
        inp = directory(base, 'core-publish-input')
        capture = directory(inp, expected['pointId'])
        images = directory(capture, 'images')
        staging = directory(base, 'core-verification')
        if set(os.listdir(keys)) != {'master-v1.key'} or set(os.listdir(capture)) != {'checkpoint.tar', 'images'}:
            v._fail()
        names = set(os.listdir(point))
        initial = {'point.json', 'capture-draft.orbis'}
        allowed = initial | {'wallpaper.orbis', 'icons.orbis'}
        if sealed:
            initial |= {'metadata.orbis', 'core.orbis'}
            allowed |= {'metadata.orbis', 'core.orbis'}
        if not initial <= names <= allowed or (not sealed and os.listdir(staging)):
            v._fail()
        key = _read(keys, 'master-v1.key', 32, owner, content=True)
        if key[1] != 32:
            v._fail()
        files = {}
        limits = {'point.json': 32768, 'capture-draft.orbis': 524340, 'wallpaper.orbis': 32 * 1024**2 + 52, 'icons.orbis': 24 * 1024**2 + 52, 'metadata.orbis': 524340, 'core.orbis': v._LIMIT}
        for name in names:
            files[name] = _read(point, name, limits[name], owner, content=name == 'point.json')
        checkpoint = _read(capture, 'checkpoint.tar', v._LIMIT, owner)
        if checkpoint[:2] != (expected['checkpoint']['sha256'], expected['checkpoint']['bytes']):
            v._fail()
        image_names = set(os.listdir(images))
        if 'inventory.json' not in image_names or len(image_names) > 4097 or any(not re.fullmatch(r'[A-Za-z0-9._-]{1,255}', name) or name in ('.', '..') for name in image_names):
            v._fail()
        inputs = {'key': key[:3], 'checkpoint': checkpoint[:3]}
        for name in image_names:
            inputs['image/' + name] = _read(images, name, 2 * 1024 * 1024 if name == 'inventory.json' else v._LIMIT, owner)[:3]
        for name in names & {'capture-draft.orbis', 'wallpaper.orbis', 'icons.orbis'}:
            inputs[name] = files[name][:3]
        value = v._json(files['point.json'][3])
        if (type(value) is not dict or value.get('version') != 3 or value.get('id') != expected['pointId']
                or value.get('status') != ('sealed' if sealed else 'capturing') or type(value.get('envelope')) is not dict
                or value['envelope'].get('keyId') != key[0]):
            v._fail()
        return value, files, inputs
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def seal_prepared_capture(*, workspace_directory, image_id, expectation, owner_id, created_at, runner=None):
    """Seal a private prepared workspace and retain it, including failure evidence."""
    if sys.platform != 'linux' or os.geteuid() != 0:
        v._fail()
    if not isinstance(image_id, str) or not v._IMAGE.fullmatch(image_id) or not v._integer(owner_id, 1, v._SAFE) or not v._integer(created_at, 1, v._SAFE):
        v._fail()
    try:
        expected, encoded = v._expectation(expectation)
        v._secure_scratch(workspace_directory, 0)
        original, _, inputs = _layout(workspace_directory, expected, 0)
        if type(original.get('ownerId')) is not int or original['ownerId'] != owner_id or type(original.get('createdAt')) is not int or original['createdAt'] != created_at:
            v._fail()
        reservation = {k: original[k] for k in ('version', 'id', 'ownerId', 'createdAt', 'envelope')}
        proof = v._execute_worker(runner if runner is not None else _Sealer(), workspace_directory, image_id, encoded, lambda value: value)
        point, files, after = _layout(workspace_directory, expected, 0, sealed=True)
        if inputs != after or v._canonical({k: point[k] for k in reservation}) != v._canonical(reservation):
            v._fail()
        if point.get('archiveBytes') != files['core.orbis'][1] or point.get('archiveSha256') != files['core.orbis'][0] or point.get('metadataSha256') != files['metadata.orbis'][0]:
            v._fail()
        return v._publication(proof, expected, point, files, owner_id, created_at)
    except v.CleanupIndeterminate:
        raise
    except Exception:
        raise v.VerificationError('Prepared capture sealing failed') from None
