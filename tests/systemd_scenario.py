"""Exercise the real activator inside the disposable Linux systemd rootfs."""

import hashlib
import fcntl
from contextlib import contextmanager
import grp
import http.client
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import uuid


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


def signed_lease_roundtrip(old, new):
    """A real parent lock spans separate verified activation/return children."""
    original = (activation.STATE / 'installed.json').read_bytes()
    parent = activation._Parent(activation.STATE)
    lease = activation._activation_lock(parent, None)
    try:
        def child(code, arguments):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
                                     str(BASE / 'source/packaging'), str(lease), *arguments],
                                    pass_fds=(lease,), capture_output=True, timeout=150,
                                    env={'PATH': os.defpath, 'TMPDIR': str(BASE / 'tmp'),
                                         'PYTHONDONTWRITEBYTECODE': '1'})
            assert result.returncode == 0, result.stderr[-2000:]
            contender = os.open(activation.STATE / 'activation.lock', os.O_RDWR)
            try:
                try:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    raise AssertionError('A child released the coordinator activation lease')
            finally:
                os.close(contender)
            return json.loads(result.stdout)
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '6' * 64,
                   'targetDigest': 'sha256:' + '7' * 64}
        selected = {key: str(value) for key, value in options(new, 'verify-leased-child').items()}
        result = child('''import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
import activate_release as api
options=json.loads(sys.argv[3])
for key in ('artifact','bundle','workspace','verifier'):
    options[key]=pathlib.Path(options[key])
print(json.dumps(api.activate_release(**options,retain=json.loads(sys.argv[4]),activation_lock_fd=int(sys.argv[2]))))
''', [json.dumps(selected), json.dumps(binding)])
        assert result['publisherVerified'] and result['activated'] and result['previousVersion'] == old['version']
        activation._ready(activation.Systemd(), new['version'])
        before = (activation.STATE / 'activation.json').read_bytes()
        command = [sys.executable, '-I', '-B', str(BASE / 'source/packaging/activate_release.py')]
        for key, value in options(new, 'verify-competing-under-lease').items():
            command.extend(['--' + key.replace('_', '-'), str(value)])
        refused = subprocess.run(command, capture_output=True, timeout=10,
            env={'PATH': os.defpath, 'TMPDIR': str(BASE / 'tmp'), 'PYTHONDONTWRITEBYTECODE': '1'})
        assert refused.returncode != 0 and (activation.STATE / 'activation.json').read_bytes() == before
        assert not (BASE / 'verify-competing-under-lease').exists()
        program = '''import json,sys
sys.path.insert(0,sys.argv[1])
import activate_release as api
print(json.dumps(api.restore_retained(json.loads(sys.argv[3]),activation_lock_fd=int(sys.argv[2]))))
'''
        ticket = result['retainedRollback']
        returned = child(program, [json.dumps(ticket)])
        assert returned['restored'] and returned['version'] == old['version']
        assert (activation.STATE / 'installed.json').read_bytes() == original
        activation._ready(activation.Systemd(), old['version'])
        before = activation.Systemd().inspect('orbis-sentinel.service')
        assert child(program, [json.dumps(ticket)]) == returned
        after = activation.Systemd().inspect('orbis-sentinel.service')
        assert all(before[key] == after[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    finally:
        os.close(lease)
        parent.close()


def privileges(systemd):
    service = systemd.inspect('orbis-sentinel.service')
    pid = int(service['MainPID'])
    fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    assert int(fields['Uid'].split()[1]) != 0, 'Sentinel must run as its dynamic user'
    assert int(fields['CapEff'].strip(), 16) == 0
    assert fields['NoNewPrivs'].strip() == '1'
    assert os.stat(activation.SOCKET).st_uid == 0
    assert os.stat(activation.SOCKET).st_mode & 0o777 == 0o600


@contextmanager
def independent_progress(operation='12345678-1234-4123-8123-123456789abc'):
    """A disposable Root progress-only peer, never a lifecycle authority."""
    folder = Path('/run/orbis-upgrade')
    assert not folder.exists() and not folder.is_symlink()
    folder.mkdir(mode=0o755)
    endpoint = folder / 'progress.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(endpoint))
    os.chown(endpoint, 0, grp.getgrnam('orbis-observer').gr_gid)
    endpoint.chmod(0o660)
    listener.listen(16)
    listener.settimeout(0.2)
    stop, errors = threading.Event(), []
    progress = {'version': 1, 'job': {'id': operation,
        'state': 'running', 'targetTag': 'v0.9.2', 'phase': 'installing'}}

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if stop.is_set():
                    return
                raise
            try:
                with conn:
                    conn.settimeout(2)
                    header = b''
                    while b'\r\n\r\n' not in header:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        assert len(header) + len(chunk) <= 4096
                        header += chunk
                    if b'\r\n\r\n' not in header:
                        continue
                    route = header.split(b'\r\n', 1)[0]
                    if route == b'GET /v1/capability HTTP/1.1':
                        payload = {'schema': 'orbis.sentinel-observer.v1', 'protocolVersion': 1,
                                   'kind': 'core-update-progress'}
                    elif route == b'GET /v1/core-operation/progress HTTP/1.1':
                        payload = progress
                    else:
                        raise AssertionError('Independent observer requested an unrelated route')
                    body = json.dumps(payload).encode()
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
                                 + b'\r\nConnection: close\r\n\r\n' + body)
            except OSError:
                # A collector restart can retire its reader mid-exchange.
                pass
            except BaseException as error:
                errors.append(error)
                stop.set()

    thread = threading.Thread(target=serve, name='qualification-upgrade-observer')
    thread.start()
    try:
        yield progress
    finally:
        stop.set()
        listener.close()
        thread.join(3)
        assert not thread.is_alive() and not errors
        endpoint.unlink()
        folder.rmdir()


def await_progress(expected):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        value = request('progress')
        if ((expected is None and value['available'] is False and value['progress'] is None)
                or expected is not None and value['available'] is True and value['progress'] == expected):
            return
        time.sleep(0.1)
    raise AssertionError('Independent progress did not reach the expected live state')


def managed_observer_api_roundtrip(record):
    """Actual managed API/systemd effects with a disposable Host placeholder."""
    systemd = activation.Systemd()
    # Prior fault/return cases intentionally exercised this same collector.
    # Isolate this scenario's start budget, without altering production limits.
    systemd.run('reset-failed', 'orbis-sentinel.service')
    host = b'[Unit]\nDescription=Disposable qualification observer placeholder\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nKillMode=control-group\n'
    parent = activation._Parent(activation.UNITS)
    try:
        assert activation._read(parent, 'orbis-host.service', 0o644) is None
        activation._write(parent, 'orbis-host.service', host, 0o644)
    finally:
        parent.close()
    systemd.run('daemon-reload')
    systemd.run('start', 'orbis-host.service')
    original_host = activation._observer_host(activation.Systemd(), None)
    binding = {'operationId': str(uuid.uuid4()), 'planSha256': 'c' * 64,
               'targetDigest': 'sha256:' + 'd' * 64}
    parent = activation._Parent(activation.STATE)
    lease = activation._activation_lock(parent, None)
    try:
        activated = activation.activate_release(**options(record, 'verify-observer-api-retained'),
            retain=binding, activation_lock_fd=lease)
        retained = activated['retainedRollback']
        before = activation.Systemd().inspect('orbis-sentinel.service')
        prepared = activation.prepare_observer_profile(retained, activation_lock_fd=lease)
        assert prepared['prepared'] and prepared['ticket']['binding'] == binding
        same = activation.Systemd().inspect('orbis-sentinel.service')
        assert all(same[key] == before[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
        assert activation._observer_host(activation.Systemd(), None, pending=True) == original_host
        with independent_progress(binding['operationId']) as progress:
            enrolled = activation.activate_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            assert enrolled['enrolled'] and enrolled['profile'] == prepared['profile']
            assert activation._observer_host(activation.Systemd(), enrolled['profile']) == original_host
            activation._observer_socket(activation.Systemd(), False)
            assert systemd.run('show', 'orbis-host.service', '--property=TriggeredBy', '--value').strip() == 'orbis-host-observer.socket'
            activation._ready(activation.Systemd(), record['version'])
            await_progress(progress)
            # A real helper replacement stops the old process before starting
            # its successor. Exercise the actual socket dependency at that
            # boundary using this explicitly disposable Host placeholder.
            systemd.run('stop', 'orbis-host.service')
            systemd.run('start', 'orbis-host.service')
            replacement_host = activation._observer_host(activation.Systemd(), enrolled['profile'])
            assert replacement_host['InvocationID'] != original_host['InvocationID']
            activation._observer_socket(activation.Systemd(), True)
            await_progress(progress)
            returned = activation.restore_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            assert returned['restored'] and returned['profile'] is None
            assert activation._observer_host(activation.Systemd(), None) == replacement_host
            activation._ready(activation.Systemd(), record['version'])
        # A known prepared change can return if the progress endpoint cannot
        # start. Neither Host nor collector may restart in that path.
        next_binding = {**binding, 'operationId': str(uuid.uuid4()), 'planSha256': 'e' * 64}
        next_activation = activation.activate_release(**options(record, 'verify-observer-api-prepared-only'),
            retain=next_binding, activation_lock_fd=lease)
        before = activation.Systemd().inspect('orbis-sentinel.service')
        prepared = activation.prepare_observer_profile(next_activation['retainedRollback'], activation_lock_fd=lease)
        assert activation.restore_observer_profile(prepared['ticket'], activation_lock_fd=lease)['restored']
        same = activation.Systemd().inspect('orbis-sentinel.service')
        assert all(same[key] == before[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
        assert activation._observer_host(activation.Systemd(), None) == replacement_host
        # An admitted observer can still have a deferred socket when the
        # operation returns before another Host generation claims it.
        systemd.run('reset-failed', 'orbis-sentinel.service')
        deferred_binding = {**binding, 'operationId': str(uuid.uuid4())}
        deferred = activation.activate_release(**options(record, 'verify-observer-deferred-return'),
            retain=deferred_binding, activation_lock_fd=lease)
        prepared = activation.prepare_observer_profile(deferred['retainedRollback'], activation_lock_fd=lease)
        with independent_progress(deferred_binding['operationId']) as progress:
            enrolled = activation.activate_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            activation._observer_socket(activation.Systemd(), False)
            assert activation._observer_host(activation.Systemd(), enrolled['profile']) == replacement_host
            await_progress(progress)
            returned = activation.restore_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            assert returned['restored'] and returned['profile'] is None
            final_systemd = activation.Systemd()
            activation._observer_socket(final_systemd, False)
            assert final_systemd.inspect('orbis-host-observer.socket')['LoadState'] == 'not-found'
            assert activation._observer_host(final_systemd, None) == replacement_host
            activation._ready(final_systemd, record['version'])
        # A same-byte helper update can finish without creating a new Host
        # generation. A later activation must respect that exact deferral.
        systemd.run('reset-failed', 'orbis-sentinel.service')
        first_binding = {**binding, 'operationId': str(uuid.uuid4())}
        first = activation.activate_release(**options(record, 'verify-observer-defer-first'),
            retain=first_binding, activation_lock_fd=lease)
        prepared = activation.prepare_observer_profile(first['retainedRollback'], activation_lock_fd=lease)
        with independent_progress(first_binding['operationId']) as progress:
            enrolled = activation.activate_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            activation._observer_socket(activation.Systemd(), False)
            await_progress(progress)
        second_binding = {**binding, 'operationId': str(uuid.uuid4())}
        second = activation.activate_release(**options(record, 'verify-observer-defer-second'),
            retain=second_binding, activation_lock_fd=lease)
        collector = activation.Systemd().inspect('orbis-sentinel.service')
        prepared = activation.prepare_observer_profile(second['retainedRollback'], activation_lock_fd=lease)
        with independent_progress(second_binding['operationId']) as progress:
            repeated = activation.activate_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            assert repeated['enrolled'] and repeated['profile'] == enrolled['profile']
            activation._observer_socket(activation.Systemd(), False)
            assert activation._observer_host(activation.Systemd(), repeated['profile']) == replacement_host
            current = activation.Systemd().inspect('orbis-sentinel.service')
            assert all(current[key] == collector[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
            await_progress(progress)
            returned = activation.restore_observer_profile(prepared['ticket'], activation_lock_fd=lease)
            assert returned['restored'] and returned['profile'] == repeated['profile']
            activation._observer_socket(activation.Systemd(), False)
            assert activation._observer_host(activation.Systemd(), returned['profile']) == replacement_host
        other = os.open(activation.STATE / 'activation.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise AssertionError('A managed observer API released the parent activation lease')
        finally:
            os.close(other)
    finally:
        os.close(lease)
        parent.close()

    # The following legacy fixture owns a fresh socket/Host start. Retire only
    # this scenario's disposable placeholder after all preservation assertions.
    systemd.run('stop', 'orbis-host.service')
    stopped = systemd.inspect('orbis-host.service')
    assert (stopped['ActiveState'], stopped['SubState'], stopped['MainPID'], stopped['ControlPID']) == (
        'inactive', 'dead', '0', '0')
    assert not stopped['ControlGroup']


def managed_observer_profile(systemd, current_directory, record, name='orbis-observer-v1', *, progress=None):
    # Earlier scenarios intentionally fail and roll back the same service.
    # Give this independent fixture its own restart budget; production start
    # limits and the activator's health/rollback behavior remain unchanged.
    systemd.run('reset-failed', 'orbis-sentinel.service')
    # This explicit fixture enrollment installs only publisher-staged templates.
    # The Host endpoint is a disposable socket-activation placeholder, not an
    # installed Core/Host or recovery-authority acceptance test.
    paths = {
        'collector': (activation.UNITS / 'orbis-sentinel.service.d/observer.conf', 'packaging/systemd/orbis-sentinel.service.d/observer.conf'),
        'host': (activation.UNITS / 'orbis-host.service.d/sentinel-observer.conf', 'packaging/systemd/orbis-host.service.d/sentinel-observer.conf'),
        'socket': (activation.UNITS / 'orbis-host-observer.socket', 'packaging/systemd/orbis-host-observer.socket'),
        'sysusers': (activation.SYSUSERS / 'orbis-sentinel-observer.conf', 'packaging/sysusers.d/orbis-sentinel-observer.conf'),
    }
    hashes = activation.OBSERVER_PROFILES[name]
    suffix = name.rsplit('-', 1)[1]
    if name == 'orbis-observer-v2':
        paths['collector'] = (paths['collector'][0], 'packaging/systemd/observer-profiles/upgrade-observer.conf')
    for role, (target, source) in paths.items():
        body = (current_directory / source).read_bytes()
        assert hashlib.sha256(body).hexdigest() == hashes[role]
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    # Use the activator's protected writer and exact expected bodies.
    for role, (target, source) in paths.items():
        parent = activation._Parent(target.parent)
        try:
            previous = activation._read(parent, target.name, 0o644, 4096)
            assert previous is None or hashlib.sha256(previous).hexdigest() in {
                profile[role] for profile in activation.OBSERVER_PROFILES.values()}
            activation._write(parent, target.name, (current_directory / source).read_bytes(), 0o644, previous)
        finally:
            parent.close()
    subprocess.run(['/usr/bin/systemd-sysusers', str(paths['sysusers'][0])], check=True,
                   capture_output=True, timeout=10, env={'PATH': os.defpath})
    group = grp.getgrnam('orbis-observer').gr_gid
    assert 0 < group < 2**31
    host = b'[Unit]\nDescription=Disposable qualification observer placeholder\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\nKillMode=control-group\n'
    parent = activation._Parent(activation.UNITS)
    try:
        previous = activation._read(parent, 'orbis-host.service', 0o644, 4096)
        assert previous in (None, host)
        activation._write(parent, 'orbis-host.service', host, 0o644, previous)
    finally:
        parent.close()
    profile = {'schema': 'orbis-sentinel.observer-profile.v1', 'profile': name,
               'groupId': group, 'files': dict(hashes)}
    parent = activation._Parent(activation.STATE)
    try:
        previous = activation._read(parent, 'observer-profile.json', 0o600, 8192)
        assert previous is None or any(previous == activation._encoded({
            'schema': 'orbis-sentinel.observer-profile.v1', 'profile': selected,
            'groupId': group, 'files': dict(values)}) for selected, values in activation.OBSERVER_PROFILES.items())
        activation._write(parent, 'observer-profile.json', activation._encoded(profile), 0o600, previous)
    finally:
        parent.close()
    systemd.run('daemon-reload')
    systemd.run('start', 'orbis-host-observer.socket')
    systemd.run('restart', 'orbis-sentinel.service')
    systemd = activation.Systemd()  # A separately recorded Root profile transition.
    activation._ready(systemd, record['version'])
    observed = activation._profile(systemd, True)
    assert observed['observerProfile'] == profile
    pid = int(systemd.inspect('orbis-sentinel.service')['MainPID'])
    fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
    assert int(fields['Gid'].split()[1]) == group
    assert b'--observer-socket\0/run/orbis-observer/progress.sock\0' in Path(f'/proc/{pid}/cmdline').read_bytes()
    command = Path(f'/proc/{pid}/cmdline').read_bytes()
    assert (b'--upgrade-observer-socket\0/run/orbis-upgrade/progress.sock\0' in command) == (name == 'orbis-observer-v2')
    if progress is not None:
        await_progress(progress)
    privileges(systemd)
    before = {role: target.read_bytes() for role, (target, _) in paths.items()}
    result = cli(record, 'verify-managed-observer-' + suffix)
    assert result['activated'] is True and result['reused'] is True
    systemd = activation.Systemd()
    activation._ready(systemd, record['version'])
    assert before == {role: target.read_bytes() for role, (target, _) in paths.items()}
    journal = json.loads((activation.STATE / 'activation.json').read_bytes())
    assert journal['phase'] == 'complete' and journal['previousUnits']['observerProfile'] == profile
    if progress is not None:
        await_progress(progress)
        assert request('status')['components']['orbis']['state'] == 'unknown'
    collector = paths['collector'][0]
    modified = before['collector'] + b'\n# not the recorded managed template\n'
    collector.write_bytes(modified)
    prior = systemd.inspect('orbis-sentinel.service')
    try:
        activation.activate_release(**options(record, 'verify-observer-drift-' + suffix))
    except activation.ActivationError:
        pass
    else:
        raise AssertionError('A changed observer profile must not be activated')
    after = systemd.inspect('orbis-sentinel.service')
    assert all(prior[key] == after[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    assert collector.read_bytes() == modified
    parent = activation._Parent(collector.parent)
    try:
        activation._write(parent, collector.name, before['collector'], 0o644, modified)
    finally:
        parent.close()
    systemd.run('daemon-reload')
    activation._ready(systemd, record['version'])
    privileges(systemd)
    return systemd


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

    binding = {'operationId': str(uuid.uuid4()), 'planSha256': '4' * 64,
               'targetDigest': 'sha256:' + '5' * 64}
    result = activation.activate_release(**options(new, 'verify-new'), retain=binding)
    retention = result['retainedRollback']
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
    # A later component failure can return this exact, explicitly retained
    # activation. This is a real signed-payload/systemd restoration; the
    # broader multi-component coordinator remains outside this fixture.
    systemd.run('reset-failed', 'orbis-sentinel.service')
    returned = activation.restore_retained(retention)
    assert returned['restored'] and returned['version'] == old['version']
    assert (activation.STATE / 'installed.json').read_bytes() == old_receipt
    activation._ready(activation.Systemd(), old['version'])
    assert snapshot(old_directory) == old_files and snapshot(current_directory) == current_files
    same = systemd.inspect('orbis-sentinel.service')
    assert activation.restore_retained(retention) == returned
    observed = systemd.inspect('orbis-sentinel.service')
    assert all(observed[key] == same[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    signed_lease_roundtrip(old, new)
    systemd.run('reset-failed', 'orbis-sentinel.service')
    assert cli(new, 'verify-after-retained-return')['previousVersion'] == old['version']
    activation._ready(activation.Systemd(), new['version'])
    same = systemd.inspect('orbis-sentinel.service')
    try:
        activation.restore_retained(retention)
    except activation.RecoveryRequired:
        pass
    else:
        raise AssertionError('A superseded restoration must not return an earlier installation')
    observed = systemd.inspect('orbis-sentinel.service')
    assert all(observed[key] == same[key] for key in ('MainPID', 'InvocationID', 'ControlGroup'))
    assert snapshot(old_directory) == old_files and snapshot(current_directory) == current_files
    managed_observer_api_roundtrip(new)
    systemd = managed_observer_profile(systemd, current_directory, new)
    with independent_progress() as progress:
        systemd = managed_observer_profile(systemd, current_directory, new, 'orbis-observer-v2', progress=progress)
    await_progress(None)
    systemd.stop()
    print(json.dumps({'schema': 'orbis-sentinel.systemd-qualification.v1', 'passed': True,
        'cases': ['signed-first-install', 'fault-injected-health-rollback', 'signed-older-to-current-retry',
                  'retained-old-runtime', 'independent-unprivileged-service', 'older-installer-downgrade-refusal',
                  'older-orbis-installer-cli-refusal', 'managed-observer-profile-loaded',
                  'exact-retained-signed-collector-return', 'retained-return-observed-replay',
                  'signed-update-after-retained-return', 'superseded-retained-return-refusal',
                  'signed-child-activation-under-parent-lease', 'competing-cli-refused-under-parent-lease',
                  'signed-child-return-under-parent-lease', 'leased-return-observed-replay',
                  'managed-observer-api-prepare-without-restart', 'managed-observer-api-progress-ready-before-restart',
                  'managed-observer-api-activation-preserves-host', 'managed-observer-api-return-preserves-host',
                  'managed-observer-api-prepared-only-return-without-restart', 'managed-observer-api-preserves-parent-lease',
                  'deferred-observer-socket-starts-with-next-host',
                  'successive-activation-preserves-deferred-observer-socket',
                  'signed-collector-retry-preserves-managed-observer', 'unreviewed-managed-observer-change-refused',
                  'managed-independent-progress-profile-loaded', 'signed-collector-retry-preserves-independent-progress',
                  'independent-progress-with-stalled-host', 'unreviewed-independent-profile-change-refused',
                  'independent-progress-clears-after-supervisor-stop',
                  'supervisor-stop'],
        'oldVersion': old['version'], 'newVersion': new['version'],
        'orbisAdapterSource': '9e8f9f5bce1a7e8a3a7ee1d0070dbcd20228684f',
        'publisherVerification': 'real', 'systemd': 'real', 'healthFaultOnly': 'explicit injection',
        'observerHost': 'disposable-placeholder', 'upgradeObserver': 'disposable-supervisor-placeholder',
        'installedRecoveryAccepted': 0,
        'retainedOldFiles': len(old_files)}, sort_keys=True))


if __name__ == '__main__':
    main()
