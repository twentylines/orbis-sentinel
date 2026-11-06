"""Opt-in capability probe for a caller-approved local capture image.

This result grants no lifecycle authority. The caller must establish image approval.
"""
import os
import secrets
import sys

from . import capture_catalog as c
from . import verification as v

_CAPABILITIES = {
    'publication': {'schema': 'orbis.core-capture-publication-capability.v1', 'version': 1, 'pointVersion': 3, 'payloadFormat': 'orbis.time-machine-core.v1', 'publicationSchema': 'orbis.core-capture-publication.v1', 'dataRoot': '/data', 'verification': 'authenticated-stream-and-images.v1', 'mutations': 'private-verification-staging-only'},
    'seal': {'schema': 'orbis.core-capture-seal-capability.v1', 'version': 1, 'pointVersion': 3, 'payloadFormat': 'orbis.time-machine-core.v1', 'dataRoot': '/data', 'mutations': 'staged-point-files-only'},
    'catalog': {'schema': 'orbis.core-capture-catalog-capability.v1', 'version': 1, 'pointVersion': 3, 'payloadFormat': 'orbis.time-machine-core.v1', 'publicationSchema': 'orbis.core-capture-catalog-publication.v1', 'dataRoot': '/data', 'verification': 'authenticated-stream-and-images.v1', 'mutations': 'read-only-data-with-private-staging'},
    'image-inventory': {'schema': 'orbis.core-image-inventory-capability.v1', 'version': 1, 'dataRoot': '/data', 'mutations': 'image-inventory-output-only'},
}
# Fixed script and fixed paths; neither the image nor caller supplies code or arguments.
_SCRIPT = r'''const {spawnSync}=require('node:child_process');
const names=['publication','seal','catalog','image-inventory'];const result={};
for(const n of names){const p=spawnSync('/usr/local/bin/node',['/app/core-capture-'+n+'.mjs','--capability'],{encoding:'utf8',timeout:10000,maxBuffer:8192,stdio:['ignore','pipe','pipe']});if(p.error||p.status!==0||Buffer.byteLength(p.stdout)>8192||Buffer.byteLength(p.stderr)>8192)process.exit(1);result[n]=p.stdout}
process.stdout.write(JSON.stringify(result));'''


class _PreflightDocker(v._Docker):
    def create(self, name, nonce, image, data, staging, encoded):
        args = ['create', '--pull=never', '--name', name, '--label', 'orbis.sentinel.verifier=' + nonce, '--network', 'none', '--ipc', 'none', '--no-healthcheck', '--restart', 'no', '--cpus', '1', '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '2g', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m', '--entrypoint', '/usr/local/bin/node', image, '-e', _SCRIPT]
        code, body = self._run(args)
        if code:
            raise v.VerificationError('Preflight container creation failed')
        value = body.decode('ascii').strip()
        if not v._HASH.fullmatch(value):
            raise v.VerificationError('Preflight container creation was indeterminate')
        return value

    def start(self, container):
        return self._run(['start', '--attach', container], timeout=60)


def _validate(value):
    if not v._exact(value, _CAPABILITIES) or any(type(item) is not str or len(item.encode('utf8')) > 8192 for item in value.values()):
        v._fail()
    value = {key: v._json(body) for key, body in value.items()}
    # Canonical equality preserves strict types (including bool versus int).
    if v._canonical(value) != v._canonical(_CAPABILITIES):
        v._fail()
    return v._json(v._canonical(_CAPABILITIES))


def check_publication_image(catalog, image_id, runner=None):
    """Probe an already-approved immutable image; retain work and receipt for review.

    Approval is the caller's responsibility. runner is a test transport seam only.
    """
    if sys.platform != 'linux' or os.geteuid() != 0 or not isinstance(image_id, str) or not v._IMAGE.fullmatch(image_id):
        v._fail()
    with catalog._operation():
        work = catalog._children['work'][0]
        name = 'preflight-' + secrets.token_hex(16)
        os.mkdir(name, 0o700, dir_fd=work)
        os.fsync(work)
        fd, seal = c._dir(work, name)
        try:
            if os.fstat(fd).st_dev != os.fstat(work).st_dev or v._mount_id(fd) != catalog._mount:
                c._fail()
            root = os.path.join(catalog._path, 'work', name)
            uncertain = False
            try:
                result = v._execute_worker(runner if runner is not None else _PreflightDocker(), root, image_id, '', _validate)
            except v.CleanupIndeterminate:
                uncertain = True
                raise
            finally:
                try:
                    if v._dirseal(os.fstat(fd)) != seal or v._dirseal(os.stat(name, dir_fd=work, follow_symlinks=False)) != seal or v._mount_id(fd) != catalog._mount:
                        c._fail()
                    catalog._check()
                except Exception:
                    if not uncertain:
                        raise
            return {'schema': 'orbis-sentinel.capture-image-preflight.v1', 'imageId': image_id, 'workers': result, 'lifecycleAuthority': False}
        finally:
            os.close(fd)
