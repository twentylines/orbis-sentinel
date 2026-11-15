"""Boot a workspace-owned Ubuntu rootfs for installed Sentinel acceptance.

No host package installation or shared container storage is used. The only
container is labelled and named for this run; its rootfs and runtime storage
remain beneath the supplied CI project workspace.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from urllib.request import urlopen
import uuid


OLD = {'version': '0.1.0-dev.10', 'sourceCommit': '95610965b5c8d86113a6a58ff98e6c9433f47e00',
       'sha256': '918216769be653966f66d84c9ab0dc3f2c300d4b714d56a5454de504e17df9e9',
       'bundleSha256': '2e678fd249312c42d7675b04335b0c4bc8e983c9e9f472e3bd94ee398e9d4942'}
BASE = Path('/opt/sentinel-qualification')
ORBIS_ADAPTER_COMMIT = '9e8f9f5bce1a7e8a3a7ee1d0070dbcd20228684f'
ORBIS_ADAPTER_SHA256 = '16440f3daf91035204bdba4f68123803e503c0221dc90bbd500ad31ab93e3995'


def download(url, target, digest, maximum):
    with urlopen(url, timeout=30) as response:
        assert response.status == 200 and response.geturl().startswith('https://')
        body = response.read(maximum + 1)
    assert 0 < len(body) <= maximum and hashlib.sha256(body).hexdigest() == digest
    with target.open('xb') as output:
        output.write(body)
    target.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'work', 'artifact', 'bundle'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('sha256', 'version', 'source-commit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    assert sys.platform.startswith('linux') and os.getuid() == os.geteuid() == 0
    source = args.source.resolve(strict=True)
    work = args.work
    assert work.is_absolute() and work.parent == source and not work.exists() and not work.is_symlink()
    assert re.fullmatch(r'[0-9a-f]{64}', args.sha256) and re.fullmatch(r'[0-9a-f]{40}', args.source_commit)
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', args.version) and args.version != OLD['version']
    assert subprocess.check_output(['git', '-c', 'safe.directory=' + str(source), '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == args.source_commit
    for path, maximum in ((args.artifact, 72 * 1024 * 1024), (args.bundle, 4 * 1024 * 1024)):
        assert path.is_absolute() and path.resolve(strict=True).is_relative_to(source)
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= maximum
    assert hashlib.sha256(args.artifact.read_bytes()).hexdigest() == args.sha256
    work.mkdir(mode=0o700)
    temporary, tools = work / 'tmp', work / 'tools'
    temporary.mkdir(mode=0o700)
    tools.mkdir(mode=0o700)
    environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'TMPDIR': str(temporary), 'DEBIAN_FRONTEND': 'noninteractive',
                   'XDG_CACHE_HOME': str(work / 'cache'), 'XDG_CONFIG_HOME': str(work / 'config'),
                   'XDG_DATA_HOME': str(work / 'data')}
    for name in ('cache', 'config', 'data'):
        (work / name).mkdir(mode=0o700)
    # Podman bounds runroot to 50 bytes for its Unix sockets, even in a long checkout path.
    runroot, podman_tmp = source / 'r', source / 't'
    for path in (runroot, podman_tmp):
        assert len(os.fsencode(path)) <= 50 and not path.exists() and not path.is_symlink()
        path.mkdir(mode=0o700)
    network_config, hooks = work / 'networks', work / 'hooks'
    network_config.mkdir(mode=0o700)
    hooks.mkdir(mode=0o700)
    number = 0
    def run(command, *, cwd=work, timeout=300, capture=False):
        nonlocal number
        number += 1
        log = work / ('command-' + str(number) + '.log')
        with log.open('wb') as output:
            result = subprocess.run([str(item) for item in command], cwd=cwd, env=environment,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        if result.returncode:
            lines = log.read_text(errors='replace').splitlines()
            print('\n'.join(lines[-16:]), file=sys.stderr)
            raise RuntimeError('Native qualification command failed: ' + str(number))
        return log.read_text() if capture else ''

    # apt download reads the runner's existing signed indexes; it installs nothing on the host.
    run(['/usr/bin/apt-get', 'download', 'debootstrap'], cwd=tools)
    packages = list(tools.glob('debootstrap_*_all.deb'))
    assert len(packages) == 1
    assert run(['/usr/bin/dpkg-deb', '-f', packages[0], 'Package'], capture=True).strip() == 'debootstrap'
    run(['/usr/bin/dpkg-deb', '-x', packages[0], tools / 'extracted'])
    environment['DEBOOTSTRAP_DIR'] = str(tools / 'extracted/usr/share/debootstrap')
    rootfs = work / 'rootfs'
    run([tools / 'extracted/usr/sbin/debootstrap', '--arch=amd64', '--variant=minbase',
         '--include=systemd-sysv,python3,ca-certificates',
         '--keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg',
         'noble', rootfs, 'https://archive.ubuntu.com/ubuntu'], timeout=600)
    inside = rootfs / str(BASE).lstrip('/')
    (inside / 'source/packaging').mkdir(parents=True, mode=0o755)
    (inside / 'tmp').mkdir(mode=0o700)
    (inside / 'orbis-state').mkdir(mode=0o700)
    for name in ('activate_release.py', 'verify_release.py', 'stage_release.py'):
        shutil.copyfile(source / 'packaging' / name, inside / 'source/packaging' / name)
        (inside / 'source/packaging' / name).chmod(0o644)
    shutil.copyfile(source / 'tests/systemd_scenario.py', inside / 'scenario.py')
    download('https://raw.githubusercontent.com/twentylines/orbis/' + ORBIS_ADAPTER_COMMIT + '/scripts/orbis-sentinel-install.py',
             inside / 'orbis-sentinel-install.py', ORBIS_ADAPTER_SHA256, 1024 * 1024)
    gh = Path(shutil.which('gh', path=os.defpath)).resolve(strict=True)
    info = gh.stat()
    assert info.st_uid == 0 and not info.st_mode & 0o7022 and info.st_mode & 0o111
    shutil.copyfile(gh, inside / 'gh')
    (inside / 'gh').chmod(0o555)
    shutil.copyfile(args.artifact, inside / 'new.tar.gz')
    shutil.copyfile(args.bundle, inside / 'new.sigstore.json')
    filename = 'orbis-sentinel-' + OLD['version'] + '.tar.gz'
    url = 'https://github.com/twentylines/orbis-sentinel/releases/download/v' + OLD['version'] + '/' + filename
    download(url, inside / 'old.tar.gz', OLD['sha256'], 72 * 1024 * 1024)
    download(url + '.sigstore.json', inside / 'old.sigstore.json', OLD['bundleSha256'], 4 * 1024 * 1024)
    inputs = {'old': {**OLD, 'artifact': 'old.tar.gz', 'bundle': 'old.sigstore.json'},
              'new': {'artifact': 'new.tar.gz', 'bundle': 'new.sigstore.json', 'version': args.version,
                      'sha256': args.sha256, 'sourceCommit': args.source_commit}}
    (inside / 'inputs.json').write_text(json.dumps(inputs))
    (inside / 'inputs.json').chmod(0o600)
    (inside / 'scenario.py').chmod(0o644)
    # Keep DNS configuration inside the rootfs rather than binding the runner's file.
    resolv = rootfs / 'etc/resolv.conf'
    if resolv.is_symlink():
        resolv.unlink()
    resolv.write_bytes(Path('/etc/resolv.conf').read_bytes())
    identity = 'orbis-sentinel-' + uuid.uuid4().hex[:16]
    podman = ['/usr/bin/podman', '--root', str(work / 'podman-storage'), '--runroot', str(runroot),
              '--tmpdir', str(podman_tmp), '--network-config-dir', str(network_config), '--hooks-dir', str(hooks),
              '--storage-driver=vfs', '--events-backend=file', '--cgroup-manager=systemd']
    resource = {'schema': 'orbis-sentinel.qualification-resource.v1', 'owner': identity,
                'rootfs': str(rootfs), 'storage': str(work / 'podman-storage'),
                'runroot': str(runroot), 'temporary': str(podman_tmp), 'networks': str(network_config),
                'lifecycle': 'Disposable CI-only rootfs; stop/remove only the labelled container; never upload rootfs'}
    (work / 'resource.json').write_text(json.dumps(resource, indent=2))
    started = network_created = False
    try:
        run([*podman, 'network', 'create', '--label', 'io.orbis.qualification=' + identity, identity])
        network_created = True
        run([*podman, 'run', '--detach', '--name', identity, '--hostname', 'sentinel-qualification',
             '--label', 'io.orbis.qualification=' + identity, '--cap-add=SYS_ADMIN',
             '--security-opt=seccomp=unconfined', '--security-opt=apparmor=unconfined', '--systemd=always',
             '--cgroupns=private', '--network', identity, '--log-driver=k8s-file',
             '--log-opt', 'path=' + str(work / 'container.log'), '--rootfs', rootfs, '/sbin/init'])
        started = True
        deadline = time.monotonic() + 45
        while True:
            result = subprocess.run([*podman, 'exec', identity, 'test', '-S', '/run/systemd/private'],
                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('The isolated systemd manager did not become ready')
            time.sleep(0.25)
        result = run([*podman, 'exec', '--env', 'TMPDIR=' + str(BASE / 'tmp'), '--env', 'PYTHONDONTWRITEBYTECODE=1',
                      identity, '/usr/bin/python3', '-I', '-B', str(BASE / 'scenario.py')], timeout=600, capture=True)
        summary = json.loads(result.strip().splitlines()[-1])
        assert summary['passed'] is True
        (work / 'result.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps(summary, sort_keys=True))
    finally:
        inspected = subprocess.run([*podman, 'inspect', identity], env=environment, capture_output=True, timeout=10)
        if inspected.returncode == 0:
            observed = json.loads(inspected.stdout)
            assert len(observed) == 1 and observed[0]['Config']['Labels'].get('io.orbis.qualification') == identity
            run([*podman, 'rm', '--force', identity], timeout=60)
        elif started:
            raise RuntimeError('The started test container identity could not be confirmed for cleanup')
        if network_created:
            observed = json.loads(run([*podman, 'network', 'inspect', identity], capture=True))
            labels = observed[0].get('labels', observed[0].get('Labels', {}))
            assert len(observed) == 1 and labels.get('io.orbis.qualification') == identity
            run([*podman, 'network', 'rm', identity], timeout=60)
        # The workspace-owned OS files/logs remain private until the disposable CI VM exits.


if __name__ == '__main__':
    main()
