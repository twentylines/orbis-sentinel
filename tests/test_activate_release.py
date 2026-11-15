import fcntl
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import test_build_release as fixtures
from test_stage_release import stage


PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'
spec = importlib.util.spec_from_file_location('activate_release', PACKAGING / 'activate_release.py')
activate = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, 'path', [str(PACKAGING), *sys.path]):
    spec.loader.exec_module(activate)


class ActivationCliTests(unittest.TestCase):
    def test_isolated_cli_loads_only_its_sibling_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ('stage_release.py', 'verify_release.py'):
                (root / name).write_text("raise RuntimeError('Untrusted module was imported')\n")
            result = subprocess.run([sys.executable, '-I', '-B', str(PACKAGING / 'activate_release.py'), '--help'],
                cwd=root, env={'PATH': os.defpath, 'PYTHONPATH': directory, 'TMPDIR': directory,
                               'PYTHONDONTWRITEBYTECODE': '1'}, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('--source-commit', result.stdout)
            self.assertEqual(result.stderr, '')


class Supervisor(activate.Systemd):
    def __init__(self):
        self.enabled = {name: False for name in activate.UNIT_HASHES}
        self.active = dict(self.enabled)
        self.events = []
        self.fail_restart = False
        self.fail_quiescence = False
        self.drop_ins = ''
        self.socket_state = 'listening'

    def inspect(self, name):
        exists = (activate.UNITS / name).exists()
        service = name.endswith('.service')
        active = self.active[name]
        value = dict.fromkeys(activate.PROPERTIES, '')
        value.update(LoadState='loaded' if exists else 'not-found',
            FragmentPath=str(activate.UNITS / name) if exists else '',
            ActiveState='active' if active else 'inactive',
            SubState=('running' if service else self.socket_state) if active else 'dead',
            UnitFileState=('enabled' if self.enabled[name] else 'disabled') if exists else '',
            NeedDaemonReload='no', KillMode='control-group' if service else '',
            MainPID='123' if active and service else '0', ControlPID='0',
            ControlGroup='/system.slice/orbis-sentinel.service' if active and service else '',
            InvocationID='a' * 32 if active else '', DropInPaths=self.drop_ins)
        if self.fail_quiescence and not active and service and any(event[0] == 'stop' for event in self.events):
            value['ControlGroup'] = '/system.slice/orbis-sentinel.service'
        if not service:
            value.pop('MainPID')
        return value

    def run(self, action, *names):
        self.events.append((action, *names))
        if action == 'restart' and self.fail_restart:
            self.fail_restart = False
            raise activate.ActivationError('Synthetic supervisor refusal')
        for name in names:
            if name not in self.active:
                continue
            if action in {'start', 'restart', 'stop'}:
                self.active[name] = action != 'stop'
            if action in {'enable', 'disable'}:
                self.enabled[name] = action == 'enable'
        return ''


class ActivationTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReleaseTests.setUp(self)
        for name in activate.UNIT_HASHES:
            (self.source / 'packaging' / 'systemd' / name).write_bytes((PACKAGING / 'systemd' / name).read_bytes())
        self.install = self.root / 'install'
        self.state = self.root / 'state'
        self.units = self.root / 'units'
        self.units.mkdir(mode=0o755)
        self.sequence = 0
        self.release_sequence = 0
        self.bundle = self.root / 'synthetic-bundle.json'
        self.bundle.write_text('{}')
        self.tool = self.root / 'unused-synthetic-verifier'
        self.systemd = Supervisor()
        self.fail_health_version = None
        for target, value in [('ROOT', self.install), ('STATE', self.state), ('UNITS', self.units)]:
            patch = mock.patch.object(activate, target, value)
            patch.start()
            self.addCleanup(patch.stop)
        for target, value in [('_operator', lambda: None), ('Systemd', lambda: self.systemd),
                              ('_ready', self.ready), ('verify_release', self.synthetic_publisher)]:
            patch = mock.patch.object(activate, target, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.package = self.build('0.1.0-dev.10')

    def build(self, version):
        self.release_sequence += 1
        (self.source / 'src' / 'orbis_sentinel' / '__init__.py').write_text(f'__version__ = {version!r}\n')
        return fixtures.release.build_release(self.source, self.root / ('out-' + str(self.release_sequence)))

    def synthetic_publisher(self, artifact, bundle, releases, workspace, **options):
        self.assertTrue(options['reuse_existing'])
        result = stage.stage_release(artifact, releases, sha256=options['sha256'],
            version=options['version'], reuse_existing=True)
        return {**result, 'publisherVerified': True, 'sourceCommit': options['source_commit']}

    def ready(self, systemd, version):
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/' + version)
        self.assertTrue(all(systemd.active.values()))
        if version == self.fail_health_version:
            raise activate.ActivationError('Synthetic wrong health identity')

    def run_activation(self, package=None):
        self.sequence += 1
        package = package or self.package
        return activate.activate_release(Path(package['artifact']), self.bundle,
            self.root / ('verify-' + str(self.sequence)), sha256=package['sha256'],
            version=package['version'], source_commit='1' * 40, verifier=self.tool)

    def journal(self):
        return json.loads((self.state / 'activation.json').read_bytes())

    def test_first_install_uses_real_staging_and_writes_a_private_verified_receipt(self):
        self.systemd.socket_state = 'running'
        previous = os.umask(0o077)
        try:
            result = self.run_activation()
        finally:
            os.umask(previous)
        self.assertTrue(result['activated'])
        self.assertEqual(result['retainedVersionsRemoved'], 0)
        self.assertIsNone(result['previousVersion'])
        self.assertEqual(self.journal()['phase'], 'complete')
        self.assertEqual(os.stat(self.state / 'installed.json').st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.install).st_mode & 0o777, 0o755)
        for name in activate.UNIT_HASHES:
            self.assertEqual((self.units / name).read_bytes(), (PACKAGING / 'systemd' / name).read_bytes())
            self.assertEqual(os.stat(self.units / name).st_mode & 0o777, 0o644)

    def test_update_retains_old_immutable_bundle_and_archives_completed_admission(self):
        old = self.run_activation()
        old_path = Path(old['directory'])
        before = {p.relative_to(old_path).as_posix(): p.read_bytes() for p in old_path.rglob('*') if p.is_file()}
        newer = self.build('0.1.0-dev.11')
        result = self.run_activation(newer)
        self.assertEqual(result['previousVersion'], self.package['version'])
        self.assertTrue((self.state / ('result-' + old['activationId'] + '.json')).is_file())
        self.assertEqual(before, {p.relative_to(old_path).as_posix(): p.read_bytes() for p in old_path.rglob('*') if p.is_file()})
        self.assertEqual(json.loads((self.state / 'installed.json').read_bytes())['version'], newer['version'])

    def test_wrong_candidate_health_rolls_back_to_verified_previous_version(self):
        self.run_activation()
        before = (self.state / 'installed.json').read_bytes()
        newer = self.build('0.1.0-dev.11')
        self.fail_health_version = newer['version']
        with self.assertRaisesRegex(activate.ActivationError, 'previous configuration was restored'):
            self.run_activation(newer)
        self.assertEqual((self.state / 'installed.json').read_bytes(), before)
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/' + self.package['version'])
        self.assertTrue((self.install / 'releases' / newer['version']).is_dir())
        self.assertTrue(all(self.systemd.active.values()))
        self.assertEqual(self.journal()['phase'], 'rolled-back')

    def test_failed_first_install_removes_only_its_owned_units_and_allows_authenticated_retry(self):
        self.systemd.fail_restart = True
        with self.assertRaises(activate.ActivationError):
            self.run_activation()
        self.assertEqual(self.journal()['phase'], 'rolled-back')
        self.assertFalse((self.install / 'current').is_symlink())
        self.assertFalse((self.state / 'installed.json').exists())
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertTrue((self.install / 'releases' / self.package['version']).is_dir())
        result = self.run_activation()
        self.assertTrue(result['activated'])
        self.assertTrue(result['reused'])

    def test_failed_supervisor_quiescence_preserves_candidate_and_blocks_replay(self):
        self.systemd.fail_restart = True
        self.systemd.fail_quiescence = True
        with self.assertRaises(activate.RecoveryRequired):
            self.run_activation()
        self.assertTrue((self.install / 'current').is_symlink())
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        events = list(self.systemd.events)
        with self.assertRaises(activate.RecoveryRequired):
            self.run_activation()
        self.assertEqual(self.systemd.events, events)

    def test_publisher_failure_never_switches_selector_or_writes_units(self):
        with mock.patch.object(activate, 'verify_release', side_effect=ValueError('Synthetic bad signature')):
            with self.assertRaises(ValueError):
                self.run_activation()
        self.assertFalse((self.install / 'current').exists())
        self.assertEqual(list(self.units.iterdir()), [])
        self.assertEqual(self.systemd.events, [])

    def test_modified_retained_runtime_refuses_update_before_verifier_or_supervisor(self):
        self.run_activation()
        (self.install / 'current' / 'src' / 'orbis_sentinel' / 'runtime.py').write_text('changed\n')
        self.systemd.events.clear()
        with mock.patch.object(activate, 'verify_release') as verifier:
            with self.assertRaises(ValueError):
                self.run_activation(self.build('0.1.0-dev.11'))
            verifier.assert_not_called()
        self.assertEqual(self.systemd.events, [])

    def test_unmanaged_unit_or_loaded_dropin_is_preserved_without_activation(self):
        foreign = self.units / 'orbis-sentinel.service'
        foreign.write_text('foreign unit\n')
        with self.assertRaises(ValueError):
            self.run_activation()
        self.assertEqual(foreign.read_text(), 'foreign unit\n')
        foreign.unlink()
        self.systemd.drop_ins = '/foreign.conf'
        with self.assertRaises(ValueError):
            self.run_activation()
        self.assertEqual(self.systemd.events, [])

    def test_changed_candidate_unit_profile_is_not_activated(self):
        (self.source / 'packaging' / 'systemd' / 'orbis-sentinel.service').write_text('[Service]\nDynamicUser=no\n')
        newer = self.build('0.1.0-dev.11')
        with self.assertRaisesRegex(activate.ActivationError, 'profile requires'):
            self.run_activation(newer)
        self.assertFalse((self.install / 'current').is_symlink())
        self.assertEqual(self.systemd.events, [])

    def test_selector_change_during_startup_is_preserved_for_reconciliation(self):
        def change(systemd, version):
            selector = self.install / 'current'
            selector.unlink()
            selector.symlink_to('releases/9.9.9')
        with mock.patch.object(activate, '_ready', side_effect=change):
            with self.assertRaises(activate.RecoveryRequired):
                self.run_activation()
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/9.9.9')
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.assertNotIn(('stop', *activate.UNIT_HASHES), self.systemd.events)

    def test_a_new_unmanaged_dropin_is_not_stopped_or_overwritten_during_rollback(self):
        def change(systemd, version):
            systemd.drop_ins = '/foreign-profile.conf'
            raise activate.ActivationError('Synthetic changed loaded profile')
        with mock.patch.object(activate, '_ready', side_effect=change):
            with self.assertRaises(activate.RecoveryRequired):
                self.run_activation()
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.assertNotIn(('stop', *activate.UNIT_HASHES), self.systemd.events)

    def test_journal_and_installed_receipt_must_agree_before_another_update(self):
        self.run_activation()
        path = self.state / 'activation.json'
        value = self.journal()
        value['candidate']['version'] = '9.9.9'
        path.write_text(json.dumps(value))
        with mock.patch.object(activate, 'verify_release') as verifier:
            with self.assertRaises(activate.RecoveryRequired):
                self.run_activation(self.build('0.1.0-dev.11'))
            verifier.assert_not_called()

    def test_invalid_reviewed_identity_and_operator_refusal_do_not_create_installation(self):
        with mock.patch.object(activate, '_operator', side_effect=activate.ActivationError('Not root')):
            with self.assertRaises(activate.ActivationError):
                self.run_activation()
        self.assertFalse(self.install.exists())
        with self.assertRaises(activate.ActivationError):
            activate.activate_release(Path(self.package['artifact']), self.bundle, self.root / 'bad',
                sha256='x', version='../escape', source_commit='1' * 40, verifier=self.tool)
        self.assertFalse(self.install.exists())

    def test_a_second_activation_cannot_steal_the_live_transaction_lock(self):
        self.state.mkdir(mode=0o700)
        descriptor = os.open(self.state / 'activation.lock', os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.run_activation()
        finally:
            os.close(descriptor)
        self.assertEqual(self.systemd.events, [])


class SupervisorObservationTests(unittest.TestCase):
    def test_a_not_found_unit_with_active_process_evidence_cannot_be_adopted(self):
        systemd = mock.Mock()
        value = self.running('orbis-sentinel.service')
        value.update(LoadState='not-found', FragmentPath='', DropInPaths='')
        systemd.inspect.return_value = value
        with self.assertRaises(activate.ActivationError):
            activate._profile(systemd, False)

    def running(self, name):
        value = dict.fromkeys(activate.PROPERTIES, '')
        value.update(LoadState='loaded', ActiveState='active', SubState='running',
            FragmentPath=str(activate.UNITS / name), UnitFileState='enabled', NeedDaemonReload='no',
            KillMode='control-group', MainPID='123', ControlPID='0',
            ControlGroup='/system.slice/orbis-sentinel.service', InvocationID='a' * 32)
        if name.endswith('.socket'):
            value.pop('MainPID')
        return value

    def test_ready_accepts_an_active_running_socket_and_stable_service_identity(self):
        systemd = mock.Mock()
        systemd.inspect.side_effect = self.running
        with mock.patch.object(activate, '_health') as health:
            activate._ready(systemd, '1.2.3', timeout=0)
            health.assert_called_once()

    def test_ready_refuses_missing_cgroup_evidence_before_the_health_probe(self):
        systemd = mock.Mock()
        def inspect(name):
            value = self.running(name)
            value['ControlGroup'] = ''
            return value
        systemd.inspect.side_effect = inspect
        with mock.patch.object(activate, '_health') as health:
            with self.assertRaises(activate.ActivationError):
                activate._ready(systemd, '1.2.3', timeout=0)
            health.assert_not_called()

    def test_socket_properties_do_not_require_a_service_only_main_pid(self):
        value = dict.fromkeys((key for key in activate.PROPERTIES if key != 'MainPID'), '')
        value.update(LoadState='loaded', ActiveState='active', SubState='running')
        output = '\n'.join(key + '=' + item for key, item in value.items())
        with mock.patch.object(activate.Systemd, 'run', return_value=output):
            self.assertEqual(activate.Systemd().inspect('orbis-sentinel.socket'), value)

    def test_incomplete_or_duplicate_property_observations_are_rejected(self):
        systemd = activate.Systemd()
        for output in ['LoadState=loaded\n', '\n'.join('LoadState=x' for _ in activate.PROPERTIES)]:
            with mock.patch.object(systemd, 'run', return_value=output):
                with self.assertRaises(activate.ActivationError):
                    systemd.inspect('orbis-sentinel.service')


class HealthProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ.get('SENTINEL_TEST_SOCKET_DIR'))
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 's'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        self.path.chmod(0o600)
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.stop = threading.Event()
        self.thread = None
        patch = mock.patch.object(activate, 'SOCKET', self.path)
        patch.start()
        self.addCleanup(patch.stop)
        original = Path.lstat
        def socket_identity(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            if path != self.path:
                return value
            fields = {key: getattr(value, key) for key in (
                'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')}
            fields['st_uid'] = 0
            return SimpleNamespace(**fields)
        patch = mock.patch.object(Path, 'lstat', socket_identity)
        patch.start()
        self.addCleanup(patch.stop)

    def tearDown(self):
        self.stop.set()
        self.listener.close()
        if self.thread is not None:
            self.thread.join(timeout=2)
            self.assertFalse(self.thread.is_alive())

    def serve(self, payload, *, extra=b'', length=None):
        body = json.dumps(payload).encode()
        wire = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body) if length is None else length).encode() + b'\r\n\r\n' + body + extra
        def run():
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with connection:
                    connection.settimeout(1)
                    try:
                        data = connection.recv(4096)
                        if data.startswith(b'GET /sentinel/api/v1/health HTTP/1.1\r\n'):
                            connection.sendall(wire)
                    except OSError:
                        pass
                return
        self.thread = threading.Thread(target=run)
        self.thread.start()

    def payload(self):
        return {'schema': 'orbis-sentinel.health.v1', 'state': 'ready', 'version': '1.2.3', 'protocolVersion': 1}

    def test_real_unix_health_response_requires_exact_candidate_identity(self):
        self.serve(self.payload())
        activate._health('1.2.3', timeout=1)

    def test_boolean_protocol_is_not_an_integer_protocol(self):
        self.serve({**self.payload(), 'protocolVersion': True})
        with self.assertRaises(activate.ActivationError):
            activate._health('1.2.3', timeout=1)

    def test_a_complete_body_with_trailing_unframed_bytes_is_rejected(self):
        self.serve(self.payload(), extra=b'foreign trailing bytes')
        with self.assertRaises(activate.ActivationError):
            activate._health('1.2.3', timeout=1)

    def test_a_truncated_declared_response_is_rejected(self):
        self.serve(self.payload(), length=4096)
        with self.assertRaises(activate.http.client.IncompleteRead):
            activate._health('1.2.3', timeout=1)


class OperatorTests(unittest.TestCase):
    def test_activation_requires_linux_and_both_real_and_effective_root_identity(self):
        for platform, real, effective in [('darwin', 0, 0), ('linux', 1001, 0), ('linux', 0, 1001)]:
            with mock.patch.object(activate.sys, 'platform', platform), \
                    mock.patch.object(activate.os, 'getuid', return_value=real), \
                    mock.patch.object(activate.os, 'geteuid', return_value=effective):
                with self.assertRaises(activate.ActivationError):
                    activate._operator()


if __name__ == '__main__':
    unittest.main()
