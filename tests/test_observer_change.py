"""Managed integration filesystem tests with explicit supervisor/group doubles."""
import copy
import fcntl
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import test_activate_release as activation_fixtures

PACKAGING = activation_fixtures.PACKAGING
activate = activation_fixtures.activate


class ScopedSupervisor:
    """Fresh profile cache over the same simulated systemd state."""
    def __init__(self, fixture):
        self.fixture = fixture

    def __getattr__(self, name):
        return getattr(self.fixture.systemd, name)

    def inspect(self, name):
        f = self.fixture
        if name == 'orbis-host.service':
            return {'LoadState': 'loaded', 'FragmentPath': str(f.units / name),
                    'DropInPaths': str(activate._observer_paths()['host']) if f.loaded_host else '',
                    'NeedDaemonReload': 'no', 'KillMode': 'control-group', 'ActiveState': 'active',
                    'SubState': 'running', 'MainPID': str(f.host_pid), 'ControlPID': '0',
                    'InvocationID': format(f.host_pid, '032x'), 'ControlGroup': '/system.slice/orbis-host.service'}
        if name == 'orbis-host-observer.socket':
            return {'LoadState': 'loaded' if f.loaded_socket else 'not-found',
                    'FragmentPath': str(activate._observer_paths()['socket']) if f.loaded_socket else '',
                    'DropInPaths': '', 'NeedDaemonReload': 'no', 'ControlPID': '0',
                    'ActiveState': 'active' if f.observer_active else 'inactive',
                    'SubState': f.socket_substate if f.observer_active else 'dead'}
        return f.systemd.inspect(name)

    def run(self, action, *names):
        f = self.fixture
        if action == 'start' and names == ('orbis-host-observer.socket',) and not f.observer_active:
            # Linux systemd cannot start a newly associated activation socket
            # while its service is already active. A fake supervisor must not
            # conceal that constraint by silently accepting the request.
            raise activate.ActivationError('Socket service is already active')
        if action == 'stop' and names == ('orbis-host-observer.socket',) and not f.observer_active and not f.loaded_socket:
            raise activate.ActivationError('The unloaded socket cannot be stopped')
        if action == 'show':
            f.systemd.events.append((action, *names))
            return 'Requires=' + ('orbis-host-observer.socket' if f.foreign_dependency else '') + '\nBindsTo=\nPartOf=\n'
        result = f.systemd.run(action, *names)
        if action == 'daemon-reload':
            f.reload()
        if names == ('orbis-host-observer.socket',):
            if action in {'start', 'stop'}:
                f.observer_active = action == 'start'
            if action == 'stop' and f.loaded_host:
                f.host_pid += 1  # Models the dangerous still-required socket.
        if action == 'restart' and names == ('orbis-sentinel.service',) and f.change_host:
            f.host_pid += 1
        return result

    def stop(self):
        # Bind the real stop algorithm to this scoped observer, not the shared
        # underlying fixture whose observer unit inventory is intentionally empty.
        return activation_fixtures.Supervisor.stop(self)


class ObserverChangeTests(unittest.TestCase):
    build = activation_fixtures.ActivationTests.build
    ready = activation_fixtures.ActivationTests.ready
    synthetic_publisher = activation_fixtures.ActivationTests.synthetic_publisher
    run_activation = activation_fixtures.ActivationTests.run_activation

    def setUp(self):
        activation_fixtures.ActivationTests.setUp(self)
        for relative in ('systemd/observer-profiles/upgrade-observer.conf',
                         'systemd/orbis-sentinel.service.d/observer.conf',
                         'systemd/orbis-host.service.d/sentinel-observer.conf',
                         'systemd/orbis-host-observer.socket', 'sysusers.d/orbis-sentinel-observer.conf'):
            destination = self.source / 'packaging' / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((PACKAGING / relative).read_bytes())
        self.host_pid = 4321
        self.loaded_host = self.loaded_socket = self.observer_active = False
        self.socket_substate = 'listening'
        self.group = None
        self.change_host = self.foreign_dependency = False
        self.sysusers_calls = []
        self.units.joinpath('orbis-host.service').write_bytes(b'[Service]\nKillMode=control-group\n')
        for patch in (mock.patch.object(activate, 'Systemd', side_effect=lambda: ScopedSupervisor(self)),
                      mock.patch.object(activate.grp, 'getgrnam', side_effect=self.get_group),
                      mock.patch.object(activate, '_observer_sysusers', side_effect=self.sysusers),
                      mock.patch.object(activate, '_health', side_effect=lambda version,timeout:
                          self.ready(ScopedSupervisor(self),version))):
            patch.start()
            self.addCleanup(patch.stop)

    def get_group(self, name):
        self.assertEqual(name, 'orbis-observer')
        if self.group is None:
            raise KeyError(name)
        return SimpleNamespace(gr_gid=self.group)

    def sysusers(self, path):
        self.assertEqual(path, activate._observer_paths()['sysusers'])
        self.assertEqual(path.read_bytes(), (PACKAGING / 'sysusers.d/orbis-sentinel-observer.conf').read_bytes())
        self.sysusers_calls.append(path)
        self.group = 1234

    def reload(self):
        self.loaded_host = activate._observer_paths()['host'].exists()
        self.loaded_socket = activate._observer_paths()['socket'].exists()
        self.systemd.unit_drop_ins['orbis-sentinel.service'] = (
            str(activate._observer_paths()['collector']) if activate._observer_paths()['collector'].exists() else '')

    def prepare(self, original=False):
        self.run_activation()
        if original:
            self.group = 1234
            profile_name = original if type(original) is str else 'orbis-observer-v1'
            hashes = activate.OBSERVER_PROFILES[profile_name]
            for role, path in activate._observer_paths().items():
                relative = {'collector': 'systemd/orbis-sentinel.service.d/observer.conf',
                            'host': 'systemd/orbis-host.service.d/sentinel-observer.conf',
                            'socket': 'systemd/orbis-host-observer.socket',
                            'sysusers': 'sysusers.d/orbis-sentinel-observer.conf'}[role]
                if role == 'collector' and profile_name == 'orbis-observer-v2':
                    relative = 'systemd/observer-profiles/upgrade-observer.conf'
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                path.write_bytes((PACKAGING / relative).read_bytes());path.chmod(0o644)
            profile = {'schema': 'orbis-sentinel.observer-profile.v1', 'profile': profile_name,
                       'groupId': self.group, 'files': hashes}
            (self.state / 'observer-profile.json').write_bytes(activate._encoded(profile))
            (self.state / 'observer-profile.json').chmod(0o600)
            self.reload();self.observer_active = True
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '2' * 64, 'targetDigest': 'sha256:' + '3' * 64}
        self.retention = self.run_activation(self.build('0.1.0-dev.11'), retain=binding)['retainedRollback']
        self.systemd.events.clear()
        self.lease = os.open(self.state / 'activation.lock', os.O_RDWR)
        self.addCleanup(os.close, self.lease)
        fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def enroll(self):
        return activate.change_observer_profile(self.retention, activation_lock_fd=self.lease)

    def restore(self, ticket):
        return activate.restore_observer_profile(ticket, activation_lock_fd=self.lease)

    def change_record(self):
        return json.loads((self.state / 'observer-change.json').read_bytes())

    def assert_host_preserved(self):
        self.assertEqual(self.host_pid, 4321)
        self.assertFalse(any('orbis-host.service' in event[1:] for event in self.systemd.events if event[0] != 'show'))

    def test_enrolls_and_returns_default_profile_without_restarting_host(self):
        self.prepare()
        result = self.enroll()
        self.assertTrue(result['enrolled'])
        self.assertEqual(result['profile']['profile'], 'orbis-observer-v2')
        self.assertEqual(self.change_record()['phase'], 'complete')
        self.assertEqual(len(self.sysusers_calls), 1)
        self.assertFalse(self.observer_active)
        self.assert_host_preserved()
        restored = self.restore(result['ticket'])
        self.assertTrue(restored['restored']);self.assertIsNone(restored['profile'])
        self.assertEqual(self.change_record()['phase'], 'returned')
        self.assertNotIn(('stop', 'orbis-host-observer.socket'), self.systemd.events)
        self.assertTrue(all(not path.exists() for path in activate._observer_paths().values()))
        self.assertFalse((self.state / 'observer-profile.json').exists())
        self.assertEqual(self.group, 1234)  # Never delete a possibly used system group.
        self.assertTrue((self.state / 'observer-group.json').exists())
        self.assert_host_preserved()
        # Actual retained collector return now accepts the restored profile.
        returned = activate.restore_retained(self.retention, activation_lock_fd=self.lease)
        self.assertTrue(returned['restored'])

    def test_enrolled_v1_returns_its_exact_files_and_group(self):
        self.prepare(original=True)
        before = {role: path.read_bytes() for role, path in activate._observer_paths().items()}
        result = self.enroll()
        restored = self.restore(result['ticket'])
        self.assertEqual(restored['profile']['profile'], 'orbis-observer-v1')
        self.assertEqual(restored['profile']['groupId'], 1234)
        self.assertEqual({role: path.read_bytes() for role, path in activate._observer_paths().items()}, before)
        self.assert_host_preserved()
        self.assertTrue(activate.restore_retained(self.retention, activation_lock_fd=self.lease)['restored'])

    def test_active_socket_may_already_be_serving_its_host(self):
        self.prepare(original=True)
        self.socket_substate = 'running'
        result = self.enroll()
        self.assertTrue(result['enrolled'])
        self.assertTrue(self.restore(result['ticket'])['restored'])
        self.assert_host_preserved()

    def test_existing_v2_needs_no_service_restart_or_system_configuration_rewrite(self):
        self.prepare(original='orbis-observer-v2')
        before={role: (path.stat().st_ino,path.read_bytes()) for role,path in activate._observer_paths().items()}
        result=self.enroll()
        self.assertEqual(self.systemd.events,[])
        self.assertEqual(self.sysusers_calls,[])
        self.restore(result['ticket'])
        self.assertEqual(self.systemd.events,[])
        self.assertEqual({role: (path.stat().st_ino,path.read_bytes()) for role,path in activate._observer_paths().items()},before)

    def test_preparation_allows_progress_listener_to_start_before_collector_reload(self):
        self.prepare()
        prepared=activate.prepare_observer_profile(self.retention,activation_lock_fd=self.lease)
        self.assertTrue(prepared['prepared']);self.assertEqual(prepared['profile']['groupId'],1234)
        self.assertEqual(self.change_record()['phase'],'installed')
        self.assertEqual(self.systemd.events,[])
        self.assertFalse(self.observer_active)
        # The real parent starts and verifies its progress listener at this
        # boundary; no collector reload has happened before that acknowledgement.
        result=activate.activate_observer_profile(prepared['ticket'],activation_lock_fd=self.lease)
        self.assertTrue(result['enrolled']);self.assertEqual(self.change_record()['phase'],'complete')
        self.assertFalse(self.observer_active)
        self.assertNotIn(('start', 'orbis-host-observer.socket'), self.systemd.events)
        self.assert_host_preserved()

    def test_deferred_socket_is_observed_without_restarting_the_original_host(self):
        self.prepare()
        result = self.enroll()
        before = list(self.systemd.events)
        self.assertEqual(activate.activate_observer_profile(result['ticket'], activation_lock_fd=self.lease), result)
        self.assertEqual(self.systemd.events, before)
        self.assertFalse(self.observer_active)
        self.assert_host_preserved()

    def advance_retained_activation(self, version):
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '4' * 64, 'targetDigest': 'sha256:' + '5' * 64}
        self.retention = self.run_activation(self.build(version), retain=binding,
                                             activation_lock_fd=self.lease)['retainedRollback']
        self.systemd.events.clear()

    def test_successive_activations_preserve_deferred_socket_until_host_maintenance(self):
        self.prepare()
        initial = self.enroll()
        self.advance_retained_activation('0.1.0-dev.12')
        repeated = self.enroll()
        self.assertEqual(repeated['profile'], initial['profile'])
        self.assertEqual(self.restore(repeated['ticket'])['profile'], initial['profile'])
        self.assertEqual(self.systemd.events, [])
        self.assertFalse(self.observer_active)
        self.assert_host_preserved()

        self.advance_retained_activation('0.1.0-dev.13')
        repeated = self.enroll()
        self.host_pid += 100
        with self.assertRaises(activate.RecoveryRequired):
            activate.activate_observer_profile(repeated['ticket'], activation_lock_fd=self.lease)
        self.observer_active = True
        self.assertEqual(activate.activate_observer_profile(repeated['ticket'], activation_lock_fd=self.lease), repeated)
        self.assertEqual(self.systemd.events, [])

    def test_inactive_socket_requires_intact_custody_and_the_original_host(self):
        self.prepare()
        initial = self.enroll()
        self.advance_retained_activation('0.1.0-dev.12')
        record = self.state / 'observer-change.json'
        body = record.read_bytes()
        admission = self.state / ('observer-admission-' + initial['ticket']['id'] + '.json')
        original_admission = admission.read_bytes()

        record.unlink()
        with self.assertRaises(activate.RecoveryRequired):
            self.enroll()
        self.assertFalse(record.exists())
        record.write_bytes(body)
        record.chmod(0o600)

        admission.write_bytes(original_admission + b'\n')
        with self.assertRaises(activate.RecoveryRequired):
            self.enroll()
        admission.write_bytes(original_admission)

        self.host_pid += 100
        with self.assertRaises(activate.RecoveryRequired):
            self.enroll()
        self.assertEqual(record.read_bytes(), body)
        self.assertEqual(len(list(self.state.glob('observer-admission-*'))), 1)
        self.assertEqual(self.systemd.events, [])

    def test_return_after_helper_start_preserves_the_new_host_and_stops_its_removed_socket(self):
        self.prepare()
        result = self.enroll()
        # The admitted helper maintenance is outside this toolkit API. Model
        # its new process inheriting the now-loaded socket dependency.
        self.host_pid += 100
        self.observer_active = True
        current_host = self.host_pid
        self.assertEqual(activate.activate_observer_profile(result['ticket'], activation_lock_fd=self.lease), result)
        self.assertTrue(self.restore(result['ticket'])['restored'])
        self.assertEqual(self.host_pid, current_host)
        self.assertFalse(self.observer_active)
        self.assertIn(('stop', 'orbis-host-observer.socket'), self.systemd.events)

    def test_cancelled_preparation_can_return_without_restarting_either_service(self):
        self.prepare()
        prepared=activate.prepare_observer_profile(self.retention,activation_lock_fd=self.lease)
        result=self.restore(prepared['ticket'])
        self.assertIsNone(result['profile']);self.assertEqual(self.change_record()['phase'],'returned')
        self.assertEqual(self.systemd.events,[('daemon-reload',)])
        self.assert_host_preserved()

    def test_absent_lease_and_changed_activation_ticket_refuse_before_effects(self):
        self.prepare()
        with self.assertRaises(activate.ActivationError):
            activate.change_observer_profile(self.retention, activation_lock_fd=None)
        changed = copy.deepcopy(self.retention);changed['binding']['planSha256'] = 'a' * 64
        with self.assertRaises(activate.RecoveryRequired):
            activate.change_observer_profile(changed, activation_lock_fd=self.lease)
        self.assertEqual(self.systemd.events, [])
        self.assertEqual(self.sysusers_calls, [])
        self.assertFalse((self.state / 'observer-change.json').exists())

    def test_unmanaged_group_or_files_are_never_adopted(self):
        self.prepare()
        self.group = 777
        with self.assertRaises(activate.ActivationError):self.enroll()
        self.group = None
        path = activate._observer_paths()['host'];path.parent.mkdir(mode=0o755)
        path.write_bytes(b'# unmanaged\n');path.chmod(0o644)
        with self.assertRaises(activate.ActivationError):self.enroll()
        self.assertEqual(path.read_bytes(), b'# unmanaged\n')
        self.assertEqual(self.systemd.events, [])
        self.assertFalse((self.state / 'observer-change.json').exists())

    def test_same_enrollment_and_return_cannot_replay_effects(self):
        self.prepare();result = self.enroll()
        events = list(self.systemd.events)
        with self.assertRaises(activate.RecoveryRequired):self.enroll()
        self.assertEqual(self.systemd.events, events)
        self.restore(result['ticket']);events = list(self.systemd.events)
        with self.assertRaises(activate.RecoveryRequired):self.restore(result['ticket'])
        self.assertEqual(self.systemd.events, events)

    def test_unexpected_host_restart_is_not_reported_as_success(self):
        self.prepare();self.change_host = True
        with self.assertRaises(activate.RecoveryRequired):self.enroll()
        self.assertEqual(self.change_record()['phase'], 'recovery-required')
        events = list(self.systemd.events)
        with self.assertRaises(activate.RecoveryRequired):self.enroll()
        self.assertEqual(self.systemd.events, events)

    def test_sysusers_failure_preserves_interrupted_admission_without_automatic_rollback(self):
        self.prepare()
        with mock.patch.object(activate, '_observer_sysusers', side_effect=RuntimeError('supervisor unavailable')):
            with self.assertRaises(RuntimeError):self.enroll()
        self.assertEqual(self.change_record()['phase'], 'recovery-required')
        self.assertEqual(len(list(self.state.glob('observer-admission-*'))), 1)
        self.assertEqual(self.systemd.events, [])
        self.assert_host_preserved()

    def test_changed_return_ticket_or_current_file_cannot_restore(self):
        self.prepare();result = self.enroll()
        original = (self.state / 'observer-change.json').read_bytes()
        changed = copy.deepcopy(result['ticket']);changed['sha256'] = 'f' * 64
        with self.assertRaises(activate.RecoveryRequired):self.restore(changed)
        path = activate._observer_paths()['collector'];path.write_bytes(path.read_bytes() + b'# changed\n')
        with self.assertRaises(activate.ActivationError):self.restore(result['ticket'])
        self.assertEqual((self.state / 'observer-change.json').read_bytes(), original)

    def test_remaining_host_dependency_blocks_socket_stop_during_return(self):
        self.prepare();result = self.enroll();self.foreign_dependency = True
        with self.assertRaises(activate.RecoveryRequired):self.restore(result['ticket'])
        self.assertEqual(self.change_record()['phase'], 'recovery-required')
        self.assertNotIn(('stop', 'orbis-host-observer.socket'), self.systemd.events)
        self.assert_host_preserved()

    def test_changed_publisher_template_refuses_before_configuration_effects(self):
        self.prepare()
        path = self.install / 'current/packaging/systemd/observer-profiles/upgrade-observer.conf'
        path.write_bytes(path.read_bytes() + b'# changed\n')
        with self.assertRaises((activate.ActivationError, ValueError)):self.enroll()
        self.assertEqual(self.systemd.events, [])
        self.assertEqual(self.sysusers_calls, [])
        self.assertFalse((self.state / 'observer-change.json').exists())


if __name__ == '__main__':
    unittest.main()
