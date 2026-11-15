"""Exercise the real activator inside the disposable Linux systemd rootfs."""

import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace


BASE = Path('/opt/sentinel-qualification')
sys.path.insert(0, str(BASE / 'source' / 'packaging'))
import activate_release as activation


def request(route):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(str(activation.SOCKET))
        connection.sendall(('GET /sentinel/api/v1/' + route + ' HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n').encode())
        wire = bytearray()
        while chunk := connection.recv(16384):
            wire.extend(chunk)
            assert len(wire) <= 65536
    response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda *args, **kwargs: io.BytesIO(wire)))
    try:
        response.begin()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        response.close()


def snapshot(directory):
    return {str(path.relative_to(directory)): [path.stat().st_ino, hashlib.sha256(path.read_bytes()).hexdigest()]
            for path in directory.rglob('*') if path.is_file()}


def options(record, workspace):
    return dict(artifact=BASE / record['artifact'], bundle=BASE / record['bundle'],
                workspace=BASE / workspace, sha256=record['sha256'], version=record['version'],
                source_commit=record['sourceCommit'], verifier=BASE / 'gh')


def cli(record, workspace):
    command = [sys.executable, '-I', '-B', str(BASE / 'source/packaging/activate_release.py')]
    for key, value in options(record, workspace).items():
        command.extend(['--' + key.replace('_', '-'), str(value)])
    result = subprocess.run(command, capture_output=True, timeout=150,
        env={'PATH': os.defpath, 'TMPDIR': str(BASE / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'})
    if result.returncode:
        print(result.stderr.decode(errors='replace')[-2000:], file=sys.stderr)
        # The journal is kept inside the disposable project rootfs, never uploaded.
        phase = json.loads((activation.STATE / 'activation.json').read_bytes()).get('phase') if (activation.STATE / 'activation.json').exists() else 'not-admitted'
        for command in [
            ['systemctl', '--no-pager', 'status', 'orbis-sentinel.service', 'orbis-sentinel.socket'],
            ['journalctl', '--no-pager', '-u', 'orbis-sentinel.service', '-n', '12', '-o', 'cat'],
        ]:
            diagnostic = subprocess.run(command, capture_output=True, timeout=5, env={'PATH': os.defpath})
            print(diagnostic.stdout.decode(errors='replace')[-6000:], file=sys.stderr)
        verifier_error = BASE / workspace / 'verification.stderr'
        if verifier_error.is_file():
            print(verifier_error.read_text(errors='replace')[-2000:], file=sys.stderr)
        raise RuntimeError('Native activation failed; journal phase=' + str(phase))
    value = json.loads(result.stdout)
    assert value['publisherVerified'] is True and value['activated'] is True
    return value


def privileges(systemd):
    service = systemd.inspect('orbis-sentinel.service')
    pid = int(service['MainPID'])
    fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    assert int(fields['Uid'].split()[1]) != 0, 'Sentinel must run as its dynamic user'
    assert int(fields['CapEff'].strip(), 16) == 0
    assert fields['NoNewPrivs'].strip() == '1'
    assert os.stat(activation.SOCKET).st_uid == 0
    assert os.stat(activation.SOCKET).st_mode & 0o777 == 0o600


def main():
    assert sys.platform.startswith('linux') and os.getuid() == os.geteuid() == 0
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    inputs = json.loads((BASE / 'inputs.json').read_bytes())
    old, new = inputs['old'], inputs['new']
    assert old['version'] != new['version']
    systemd = activation.Systemd()
    first = cli(old, 'verify-old')
    assert first['previousVersion'] is None
    activation._ready(systemd, old['version'])
    privileges(systemd)
    status = request('status')
    assert status['components']['orbis']['state'] == 'unknown'
    assert status['components']['sentinel']['installedVersion'] == old['version']
    old_directory = activation.ROOT / 'releases' / old['version']
    old_files = snapshot(old_directory)
    old_receipt = (activation.STATE / 'installed.json').read_bytes()

    original_health = activation._health
    def unavailable_candidate(version, timeout):
        if version == new['version']:
            raise activation.ActivationError('Injected unavailable candidate health observation')
        return original_health(version, timeout)
    activation._health = unavailable_candidate
    try:
        try:
            activation.activate_release(**options(new, 'verify-failure'))
        except activation.ActivationError as error:
            assert type(error) is activation.ActivationError, 'Unknown rollback state must not be counted as success'
        else:
            raise AssertionError('The injected unhealthy observation must fail activation')
    finally:
        activation._health = original_health
    journal = json.loads((activation.STATE / 'activation.json').read_bytes())
    assert journal['phase'] == 'rolled-back'
    assert (activation.STATE / 'installed.json').read_bytes() == old_receipt
    assert (activation.ROOT / 'current').readlink().as_posix() == 'releases/' + old['version']
    activation._ready(systemd, old['version'])
    assert snapshot(old_directory) == old_files

    result = cli(new, 'verify-new')
    assert result['previousVersion'] == old['version'] and result['reused'] is True
    activation._ready(systemd, new['version'])
    privileges(systemd)
    status = request('status')
    assert status['components']['sentinel']['installedVersion'] == new['version']
    assert status['components']['orbis']['state'] == 'unknown'
    assert snapshot(old_directory) == old_files
    subprocess.run([sys.executable, '-I', '-B', str(old_directory / 'bin/orbis-sentinel-capture'), '--help'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10,
                   env={'PATH': os.defpath, 'TMPDIR': str(BASE / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'})
    before = {name: (activation.STATE / name).read_bytes() for name in ('installed.json', 'activation.json')}
    service = systemd.inspect('orbis-sentinel.service')
    try:
        activation.activate_release(**options(old, 'verify-downgrade'))
    except activation.ActivationError as error:
        assert type(error) is activation.ActivationError and 'no downgrade was made' in str(error)
    else:
        raise AssertionError('An older installer must not downgrade the installed component')
    assert not (BASE / 'verify-downgrade').exists()
    assert {name: (activation.STATE / name).read_bytes() for name in before} == before
    observed = systemd.inspect('orbis-sentinel.service')
    assert all(observed[key] == service[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    activation._ready(systemd, new['version'])
    current_directory = activation.ROOT / 'releases' / new['version']
    current_files = snapshot(current_directory)
    adapter = subprocess.run([sys.executable, '-I', '-B', str(BASE / 'orbis-sentinel-install.py'),
        '--state-dir', str(BASE / 'orbis-state')], capture_output=True, timeout=300,
        env={'PATH': os.defpath, 'TMPDIR': str(BASE / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'})
    assert adapter.returncode != 0 and adapter.stdout == b'', 'The older pinned adapter must not replace the current component'
    assert adapter.stderr == b'Sentinel setup did not complete; retained preparation and activation records require inspection.\n'
    preparations = list((BASE / 'orbis-state').glob('sentinel-install-*'))
    assert len(preparations) == 1
    prepared = json.loads((preparations[0] / 'verify-package.stdout').read_bytes())
    assert prepared['activated'] is False and prepared['publisherVerified'] is True
    assert prepared['version'] == '0.1.0-dev.11'
    assert prepared['sha256'] == '11c45eec2da2a4a28790ce5b231f72a2256b440bda3abdf42511f5ac7db7ff1a'
    assert prepared['sourceCommit'] == 'c9b44e69cb70fc0f8c7f48f4dd183b2c3f099f3a'
    assert (preparations[0] / 'activate-sentinel.stderr').read_bytes() == (
        b'Sentinel activation did not complete; inspect the retained activation journal before retrying.\n')
    assert not (preparations[0] / 'verification').exists()
    assert {name: (activation.STATE / name).read_bytes() for name in before} == before
    observed = systemd.inspect('orbis-sentinel.service')
    assert all(observed[key] == service[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    assert snapshot(current_directory) == current_files
    activation._ready(systemd, new['version'])
    privileges(systemd)
    assert snapshot(old_directory) == old_files
    systemd.stop()
    print(json.dumps({'schema': 'orbis-sentinel.systemd-qualification.v1', 'passed': True,
        'cases': ['signed-first-install', 'fault-injected-health-rollback', 'signed-older-to-current-retry',
                  'retained-old-runtime', 'independent-unprivileged-service', 'older-installer-downgrade-refusal',
                  'older-orbis-installer-cli-refusal', 'supervisor-stop'],
        'oldVersion': old['version'], 'newVersion': new['version'],
        'orbisAdapterSource': '9e8f9f5bce1a7e8a3a7ee1d0070dbcd20228684f',
        'publisherVerification': 'real', 'systemd': 'real', 'healthFaultOnly': 'explicit injection',
        'retainedOldFiles': len(old_files)}, sort_keys=True))


if __name__ == '__main__':
    main()
