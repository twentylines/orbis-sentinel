"""Authenticate a complete capture using a separately retained catalog key."""

import os
import re
import sys
from dataclasses import dataclass

from . import verification as v


@dataclass(frozen=True)
class CatalogVerificationResult:
    publication: dict
    snapshot_id: str


class _CatalogDocker(v._Docker):
    _WORKER = '/app/core-capture-catalog.mjs'


def _validate(value, expected, point, hashes, owner, created):
    if (not v._exact(value, {'schema', 'core', 'keyId', 'files'})
            or value['schema'] != 'orbis.core-capture-catalog-publication.v1'
            or value['keyId'] != hashes['key'][0]):
        v._fail()
    v._publication(value['core'], expected, point, hashes, owner, created)
    files = value['files']
    if type(files) is not dict or set(files) != set(hashes) - {'key'}:
        v._fail()
    for name, item in files.items():
        if (not v._exact(item, {'bytes', 'sha256'}) or type(item['bytes']) is not int
                or item['bytes'] != hashes[name][1] or item['sha256'] != hashes[name][0]):
            v._fail()
    return value


def verify_catalog_capture(*, data_directory, scratch_directory, image_id, expectation,
                           owner_id, created_at, master_key_fd, runner=None):
    """Preserve all point files and verify them; this grants no lifecycle authority.

    The key comes from the protected reservation, even if Orbis's key directory
    has been removed. The caller separately authorizes the image and expectation.
    """
    if sys.platform != 'linux' or os.geteuid() != 0:
        v._fail()
    if (not isinstance(image_id, str) or not v._IMAGE.fullmatch(image_id)
            or not v._integer(owner_id, 1, v._SAFE) or not v._integer(created_at, 1, v._SAFE)
            or type(master_key_fd) is not int or master_key_fd < 0):
        v._fail()
    try:
        expected, encoded = v._expectation(expectation)
        snapshot_id, root, point, hashes = v._snapshot_point(
            data_directory, scratch_directory, expected, 0,
            master_key_fd=master_key_fd, include_assets=True,
        )
        if not re.fullmatch(r'catalog-[a-f0-9]{32}', snapshot_id):
            v._fail()
        v._secure_scratch(scratch_directory, 0)
        transport = runner if runner is not None else _CatalogDocker()
        publication = v._execute_worker(
            transport, root, image_id, encoded,
            lambda value: _validate(value, expected, point, hashes, owner_id, created_at),
        )
        body = v._canonical({'schema': 'orbis-sentinel.catalog-data-verification.v1',
                             'snapshotId': snapshot_id, 'imageId': image_id,
                             'expectation': expected, 'publication': publication}).encode('utf8')
        descriptor = os.open(os.path.join(root, 'catalog-verification.json'),
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            remaining = memoryview(body)
            while remaining:
                count = os.write(descriptor, remaining)
                if not count:
                    v._fail()
                remaining = remaining[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return CatalogVerificationResult(publication=publication, snapshot_id=snapshot_id)
    except v.CleanupIndeterminate:
        raise
    except Exception:
        raise v.VerificationError('Complete capture verification failed') from None


def verify_owned_catalog_workspace(*, workspace_directory, image_id, expectation, owner_id,
                                   created_at, master_key_fd, runner=None):
    """Internal publication path for an exclusively owned, quiescent seal workspace.

    Unlike external Orbis data, this data was assembled under the catalog lock
    and its owned sealing container has exited and been removed. Verify in place
    to avoid a second full archive copy. The catalog adopts it only afterwards.
    """
    from . import capture_catalog as c
    if sys.platform != 'linux' or os.geteuid() != 0:
        v._fail()
    expected, encoded = v._expectation(expectation)
    if not isinstance(image_id, str) or not v._IMAGE.fullmatch(image_id):
        v._fail()
    snapshot = os.path.basename(workspace_directory)
    if not re.fullmatch(r'catalog-[a-f0-9]{32}', snapshot):
        v._fail()
    v._secure_scratch(workspace_directory, 0)
    descriptors, bindings = [], []
    try:
        root = v._open_absolute(workspace_directory)
        descriptors.append(root)
        root_seal = v._dirseal(os.fstat(root))
        if root_seal[2] & 0o7777 != 0o700 or root_seal[3] != 0:
            v._fail()
        parent = root
        for name in ('data', 'backups', 'time-machine'):
            child, before = v._directory(parent, name, 0)
            descriptors.append(child)
            bindings.append((parent, name, child, v._dirseal(before)))
            parent = child
        base = parent
        points, before = v._directory(base, 'points', 0)
        descriptors.append(points)
        bindings.append((base, 'points', points, v._dirseal(before)))
        point, before = v._directory(points, expected['pointId'], 0)
        descriptors.append(point)
        bindings.append((points, expected['pointId'], point, v._dirseal(before)))
        keys, before = v._directory(base, 'keys', 0)
        descriptors.append(keys)
        bindings.append((base, 'keys', keys, v._dirseal(before)))
        if set(os.listdir(keys)) != {'master-v1.key'}:
            v._fail()
        hashes, seals = {}, {}
        names = set(os.listdir(point))
        if not c._REQUIRED <= names <= c._ALLOWED:
            v._fail()
        for name in names:
            _, digest, item = c._read(point, name, c._LIMITS[name], collect=False)
            hashes[name], seals[name] = (digest, item.st_size), v._seal(item)
        value = v._json(c._read(point, 'point.json', 32768)[0])
        _, key_digest, key_item = c._read(keys, 'master-v1.key', 32, 32)
        _, original_digest, original_item = c._read_fd(master_key_fd, 32, 32)
        if key_digest != original_digest:
            v._fail()
        hashes['key'] = (key_digest, 32)
        audit = os.path.join(workspace_directory, 'catalog-verification')
        os.mkdir(audit, 0o700)
        transport = runner if runner is not None else _CatalogDocker()
        class BoundData:
            def __getattr__(self, name):
                return getattr(transport, name)

            def create(self, name, nonce, image, _data, _staging, args):
                data = os.path.join(workspace_directory, 'data')
                return transport.create(name, nonce, image, data,
                                        os.path.join(data, 'backups/time-machine/core-verification'), args)
        result = v._execute_worker(BoundData(), audit, image_id, encoded,
                                   lambda output: _validate(output, expected, value, hashes, owner_id, created_at))
        if (set(os.listdir(point)) != names or v._seal(os.fstat(master_key_fd)) != v._seal(original_item)
                or v._seal(os.stat('master-v1.key', dir_fd=keys, follow_symlinks=False)) != v._seal(key_item)):
            v._fail()
        for name, seal in seals.items():
            if v._seal(os.stat(name, dir_fd=point, follow_symlinks=False)) != seal:
                v._fail()
        for ancestor, name, child, seal in bindings:
            if (v._dirseal(os.fstat(child)) != seal
                    or v._dirseal(os.stat(name, dir_fd=ancestor, follow_symlinks=False)) != seal):
                v._fail()
        if v._dirseal(os.stat(workspace_directory, follow_symlinks=False)) != root_seal:
            v._fail()
        return CatalogVerificationResult(publication=result, snapshot_id=snapshot)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
