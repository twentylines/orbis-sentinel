"""Publish retained capture data without depending on a live Orbis process."""

import hashlib
import fcntl
import os
import secrets

from . import verification as v
from . import capture_catalog as c


def _copy_descriptor(source, destination, maximum, expected=None):
    if type(source) is not int or source < 3 or fcntl.fcntl(source, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
        c._fail()
    before = c._regular(source, maximum)
    if expected is not None and before.st_size != expected['bytes']:
        c._fail()
    target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    total, digest = 0, hashlib.sha256()
    try:
        while total < before.st_size:
            block = os.pread(source, min(65536, before.st_size - total), total)
            if not block:
                c._fail()
            total += len(block)
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(target, view)
                if written <= 0:
                    c._fail()
                view = view[written:]
        if os.pread(source, 1, total) or v._seal(os.fstat(source)) != v._seal(before):
            c._fail()
        if expected is not None and digest.hexdigest() != expected['sha256']:
            c._fail()
        os.fsync(target)
    finally:
        os.close(target)
    return v._seal(before)


def _ready(catalog, point_id, binding, claim):
    obj = catalog._object(point_id, binding)
    if v._canonical(obj['expectation']) != v._canonical(claim['expectation']):
        c._fail()
    return {'schema': 'orbis-sentinel.prepared-publication.v1', 'id': point_id,
            'dataState': 'verified', 'lifecycleState': 'unobserved',
            'preparationSha256': claim['preparationSha256'], 'sourceHoldSha256': claim['sourceHoldSha256'],
            'terminalSha256': claim['terminalSha256'], 'publication': obj['publication']}


def publish_prepared_capture(catalog, point_id, *, expectation, checkpoint_fd, preparation_sha256,
                             source_hold_sha256, terminal_sha256, exporter=None, inventory_runner=None,
                             sealer=None, verifier=None):
    """One data attempt. Existing incomplete work is never automatically replayed.

    The privileged caller must establish original-source and successful supervisor
    terminal authority. None of these data operations authorizes hold release.
    """
    with catalog._operation():
        expected, _ = v._expectation(expectation)
        if (expected['pointId'] != point_id or any(not isinstance(value, str) or not v._HASH.fullmatch(value)
                for value in (preparation_sha256, source_hold_sha256, terminal_sha256))):
            c._fail()
        binding = catalog._record(point_id)
        if expected['sourceSha256'] != binding['sourceSha256']:
            c._fail()
        draft = catalog._draft(point_id, binding)
        if draft['preparationSha256'] != preparation_sha256 or draft['sourceHoldSha256'] != source_hold_sha256:
            c._fail()
        publications = catalog._children['publications'][0]
        name = point_id + '.json'
        fixed = {'schema': 'orbis-sentinel.publication-claim.v1', 'bindingSha256': hashlib.sha256(v._canonical(binding).encode()).hexdigest(),
                 'expectation': expected, 'preparationSha256': preparation_sha256,
                 'sourceHoldSha256': source_hold_sha256, 'terminalSha256': terminal_sha256}
        if name in c._names(publications):
            claim = c._json_read(publications, name)
            if (not v._exact(claim, set(fixed) | {'workspace'})
                    or v._canonical({k: claim[k] for k in fixed}) != v._canonical(fixed)
                    or not isinstance(claim['workspace'], str) or not c._STAGE.fullmatch(claim['workspace'])):
                c._fail()
            if point_id not in c._names(catalog._children['objects'][0]):
                raise c.CatalogError('Capture publication requires reconciliation')
            return _ready(catalog, point_id, binding, claim)
        if point_id in c._names(catalog._children['objects'][0]):
            c._fail()
        stage = 'catalog-' + secrets.token_hex(16)
        os.mkdir(stage, 0o700, dir_fd=catalog._children['work'][0])
        os.fsync(catalog._children['work'][0])
        workspace = os.path.join(catalog._path, 'work', stage)
        claim = {**fixed, 'workspace': stage}
        # Even a partial claim prevents a second external attempt after interruption.
        c._write(publications, name, v._canonical(claim).encode())
        os.fsync(publications)
        data = os.path.join(workspace, 'data')
        base = os.path.join(data, 'backups', 'time-machine')
        for path in (data, os.path.join(data, 'backups'), base, os.path.join(base, 'points'),
                     os.path.join(base, 'points', point_id), os.path.join(base, 'keys'),
                     os.path.join(base, 'core-publish-input'), os.path.join(base, 'core-publish-input', point_id),
                     os.path.join(base, 'core-verification')):
            os.mkdir(path, 0o700)
        prepared, _ = c._dir(catalog._children['prepared'][0], point_id)
        try:
            source, _ = c._dir(prepared, 'point')
            try:
                for file, info in sorted(draft['files'].items()):
                    digest, size, _ = v._copy(source, file, os.path.join(base, 'points', point_id, file),
                                              c._LIMITS[file], c._OWNER_UID)
                    if {'sha256': digest, 'bytes': size} != info:
                        c._fail()
                if catalog._draft(point_id, binding) != draft:
                    c._fail()
            finally:
                os.close(source)
        finally:
            os.close(prepared)
        reservation, _ = c._dir(catalog._children['reservations'][0], point_id)
        try:
            digest, size, _ = v._copy(reservation, 'master-v1.key', os.path.join(base, 'keys', 'master-v1.key'),
                                      32, c._OWNER_UID, 32)
            if digest != binding['reservation']['envelope']['keyId'] or size != 32:
                c._fail()
        finally:
            os.close(reservation)
        input_directory = os.path.join(base, 'core-publish-input', point_id)
        checkpoint_seal = _copy_descriptor(checkpoint_fd, os.path.join(input_directory, 'checkpoint.tar'),
                                            v._LIMIT, expected['checkpoint'])
        inventory_control = os.path.join(workspace, 'image-inventory')
        os.mkdir(inventory_control, 0o700)
        from .image_exports import prepare_images
        images, _ = prepare_images(inventory_control, binding['recoveryImageId'], expected,
                                    exporter=exporter, runner=inventory_runner)
        os.rename(images, os.path.join(input_directory, 'images'))
        for path in (os.path.dirname(images), input_directory):
            fd = v._open_absolute(path)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        if sealer is None:
            from .sealing import seal_prepared_capture
            sealer = seal_prepared_capture
        proof = sealer(workspace_directory=workspace, image_id=binding['recoveryImageId'],
                       expectation=expected, owner_id=binding['reservation']['ownerId'],
                       created_at=binding['reservation']['createdAt'])
        if (v._seal(os.fstat(checkpoint_fd)) != checkpoint_seal or catalog._record(point_id) != binding
                or catalog._draft(point_id, binding) != draft):
            c._fail()
        if verifier is None:
            from .catalog_verification import verify_owned_catalog_workspace
            def verifier(**options):
                if options['data_directory'] != data:
                    c._fail()
                return verify_owned_catalog_workspace(
                    workspace_directory=workspace, image_id=options['image_id'], expectation=options['expectation'],
                    owner_id=options['owner_id'], created_at=options['created_at'], master_key_fd=options['master_key_fd'])
        def checked_verifier(**options):
            result = verifier(**options)
            if v._canonical(result.publication['core']) != v._canonical(proof):
                c._fail()
            return result
        catalog.publish(point_id, data_directory=data, expectation=expected, verifier=checked_verifier)
        result = _ready(catalog, point_id, binding, claim)
        if result['publication']['core'] != proof:
            c._fail()
        return result
