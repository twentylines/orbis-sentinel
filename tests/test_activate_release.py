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
import uuid

import test_build_release as fixtures
from test_stage_release import stage


PACKAGING = Path(__file__).resolve().parents[1] / 'packaging'
spec = importlib.util.spec_from_file_location('activate_release', PACKAGING / 'activate_release.py')
activate = importlib.util.module_from_spec(spec)
with mock.patch.object(sys, 'path', [str(PACKAGING), *sys.path]):
    spec.loader.exec_module(activate)


class ActivationCliTests(unittest.TestCase):
    def test_version_precedence_handles_numeric_prerelease_and_stable_versions(self):
        versions = ['0.1.0-alpha', '0.1.0-alpha.1', '0.1.0-dev.2', '0.1.0-dev.10', '0.1.0', '0.1.1', '1.0.0']
        self.assertEqual(sorted(reversed(versions), key=activate._version_order), versions)
        for version in ('00.1.0', '0.01.0', '0.1.0-dev.01', '0.1', '0.1.0-'):
            with self.subTest(version=version), self.assertRaises(activate.ActivationError):
                activate._version_order(version)

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
        self.unit_drop_ins = {}
        self.extra_profiles = {}
        self.socket_state = 'listening'

    def inspect(self, name):
        if name in self.extra_profiles:
            return dict(self.extra_profiles[name])
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
            InvocationID='a' * 32 if active else '', DropInPaths=self.unit_drop_ins.get(name, self.drop_ins))
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
        for target, value in [('ROOT', self.install), ('STATE', self.state), ('UNITS', self.units), ('SYSUSERS', self.root / 'sysusers')]:
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

    def run_activation(self, package=None, *, retain=None):
        self.systemd.__dict__.pop('_orbis_observer_profile', None)
        self.sequence += 1
        package = package or self.package
        return activate.activate_release(Path(package['artifact']), self.bundle,
            self.root / ('verify-' + str(self.sequence)), sha256=package['sha256'],
            version=package['version'], source_commit='1' * 40, verifier=self.tool, retain=retain)

    def retained_update(self):
        self.run_activation()
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '2' * 64,
                   'targetDigest': 'sha256:' + '3' * 64}
        result = self.run_activation(self.build('0.1.0-dev.11'), retain=binding)
        self.systemd.events.clear()
        return result['retainedRollback']

    def run_restoration(self, ticket):
        self.systemd.__dict__.pop('_orbis_observer_profile', None)
        return activate.restore_retained(ticket)

    def journal(self):
        return json.loads((self.state / 'activation.json').read_bytes())

    def managed_observer(self, name='orbis-observer-v1'):
        paths = {
            'collector': (self.units / 'orbis-sentinel.service.d/observer.conf', PACKAGING / 'systemd/orbis-sentinel.service.d/observer.conf'),
            'host': (self.units / 'orbis-host.service.d/sentinel-observer.conf', PACKAGING / 'systemd/orbis-host.service.d/sentinel-observer.conf'),
            'socket': (self.units / 'orbis-host-observer.socket', PACKAGING / 'systemd/orbis-host-observer.socket'),
            'sysusers': (activate.SYSUSERS / 'orbis-sentinel-observer.conf', PACKAGING / 'sysusers.d/orbis-sentinel-observer.conf'),
        }
        if name == 'orbis-observer-v2':
            paths['collector'] = (paths['collector'][0], PACKAGING / 'systemd/observer-profiles/upgrade-observer.conf')
        for target, source in paths.values():
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
            target.chmod(0o644)
        self.observer_paths = {role: pair[0] for role, pair in paths.items()}
        self.observer_group = SimpleNamespace(gr_gid=1234)
        patch = mock.patch.object(activate.grp, 'getgrnam', return_value=self.observer_group)
        patch.start()
        self.addCleanup(patch.stop)
        self.systemd.unit_drop_ins['orbis-sentinel.service'] = str(paths['collector'][0])
        self.systemd.extra_profiles = {
            'orbis-host.service': {'LoadState': 'loaded', 'FragmentPath': str(self.units / 'orbis-host.service'),
                'DropInPaths': str(paths['host'][0]), 'NeedDaemonReload': 'no', 'KillMode': 'control-group'},
            'orbis-host-observer.socket': {'LoadState': 'loaded', 'FragmentPath': str(paths['socket'][0]),
                'DropInPaths': '', 'NeedDaemonReload': 'no'},
        }
        receipt = {'schema': 'orbis-sentinel.observer-profile.v1', 'profile': name,
                   'groupId': 1234, 'files': dict(activate.OBSERVER_PROFILES[name])}
        (self.state / 'observer-profile.json').write_bytes(activate._encoded(receipt))
        (self.state / 'observer-profile.json').chmod(0o600)
        return receipt

    def test_default_collector_accepts_an_empty_dropin_directory_without_enabling_an_observer(self):
        directory = self.units / 'orbis-sentinel.service.d'
        directory.mkdir(mode=0o755)
        result = self.run_activation()
        self.assertTrue(result['activated'])
        self.assertNotIn('observerProfile', self.journal()['previousUnits'])
        self.assertEqual(list(directory.iterdir()), [])
        self.assertFalse((self.state / 'observer-profile.json').exists())

    def test_default_activation_does_not_create_a_retention_ticket(self):
        result = self.run_activation()
        self.assertNotIn('retainedRollback', result)
        self.assertEqual(list(self.state.glob('retention-*')), [])

    def test_retained_return_restores_exact_runtime_and_writes_a_real_new_admission(self):
        ticket = self.retained_update()
        original = self.journal()
        admission = (self.state / ('admission-' + original['id'] + '.json')).read_bytes()
        result = self.run_restoration(ticket)
        restored = self.journal()
        self.assertTrue(result['restored'])
        self.assertEqual(result['version'], '0.1.0-dev.10')
        self.assertNotEqual(restored['id'], original['id'])
        self.assertEqual(restored['phase'], 'complete')
        self.assertEqual(restored['candidate'], original['previous'])
        self.assertEqual(restored['previous'], original['candidate'])
        self.assertEqual((self.state / 'installed.json').read_bytes(), activate._encoded(original['previous']))
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/0.1.0-dev.10')
        self.assertEqual((self.state / ('admission-' + restored['id'] + '.json')).read_bytes(),
                         activate._encoded({**restored, 'phase': 'prepared'}))
        self.assertEqual((self.state / ('result-' + original['id'] + '.json')).read_bytes(), activate._encoded(original))
        self.assertEqual((self.state / ('admission-' + original['id'] + '.json')).read_bytes(), admission)
        for receipt in (original['candidate'], original['previous']):
            self.assertEqual(activate._inventory(self.install / 'releases' / receipt['version'], receipt['version']), receipt['files'])

    def test_successful_return_replay_observes_health_without_repeating_effects(self):
        ticket = self.retained_update()
        first = self.run_restoration(ticket)
        self.systemd.events.clear()
        self.assertEqual(self.run_restoration(ticket), first)
        self.assertEqual(self.systemd.events, [])
        self.fail_health_version = '0.1.0-dev.10'
        with self.assertRaises(activate.ActivationError):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_restored_installation_can_take_another_verified_update_but_old_ticket_is_spent(self):
        ticket = self.retained_update()
        self.run_restoration(ticket)
        self.assertTrue(self.run_activation(self.build('0.1.0-dev.12'))['activated'])
        before = (self.state / 'activation.json').read_bytes()
        self.systemd.events.clear()
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual((self.state / 'activation.json').read_bytes(), before)
        self.assertEqual(self.systemd.events, [])

    def test_unretained_and_first_install_cannot_be_used_as_a_return_target(self):
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '2' * 64, 'targetDigest': 'sha256:' + '3' * 64}
        with self.assertRaisesRegex(activate.ActivationError, 'existing healthy'):
            self.run_activation(retain=binding)
        self.assertEqual(self.systemd.events, [])
        self.assertFalse((self.install / 'current').exists())
        self.run_activation()
        ticket = {'schema': 'orbis-sentinel.upgrade-retention-ticket.v1', 'activationId': self.journal()['id'],
                  'sha256': '4' * 64, 'binding': binding}
        self.systemd.events.clear()
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_retention_rejects_invalid_bindings_before_creating_installation(self):
        valid = {'operationId': str(uuid.uuid4()), 'planSha256': '2' * 64, 'targetDigest': 'sha256:' + '3' * 64}
        for field, item in [('operationId', str(uuid.uuid5(uuid.NAMESPACE_DNS, 'sentinel.invalid'))),
                            ('operationId', valid['operationId'].upper()),
                            ('planSha256', False), ('planSha256', 'g' * 64), ('targetDigest', '3' * 64)]:
            with self.subTest(field=field, item=item), self.assertRaises(activate.ActivationError):
                self.run_activation(retain={**valid, field: item})
        self.assertFalse(self.install.exists())

    def test_tampered_ticket_and_changed_retention_never_stop_the_collector(self):
        ticket = self.retained_update()
        for changed in ({**ticket, 'sha256': '0' * 64}, {**ticket, 'activationId': '../activation'},
                        {**ticket, 'binding': {**ticket['binding'], 'operationId': str(uuid.uuid4())}},
                        {**ticket, 'binding': {**ticket['binding'], 'targetDigest': 'sha256:' + '4' * 64}},
                        {**ticket, 'force': True}):
            with self.subTest(changed=changed), self.assertRaises(activate.ActivationError):
                self.run_restoration(changed)
            self.assertEqual(self.systemd.events, [])
        path = self.state / ('retention-' + ticket['activationId'] + '.json')
        body = path.read_bytes()
        path.write_bytes(body + b' ')
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(path.read_bytes(), body + b' ')
        self.assertEqual(self.systemd.events, [])

    def test_changed_old_runtime_or_current_selector_is_preserved_without_return_effects(self):
        ticket = self.retained_update()
        runtime = self.install / 'releases/0.1.0-dev.10/src/orbis_sentinel/__init__.py'
        before = runtime.read_bytes()
        runtime.write_bytes(before + b'\n')
        with self.assertRaises(ValueError):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])
        runtime.write_bytes(before)
        (self.install / 'current').unlink()
        (self.install / 'current').symlink_to('releases/0.1.0-dev.10')
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_a_later_same_version_activation_also_prevents_old_ticket_restoration(self):
        ticket = self.retained_update()
        self.run_activation(self.build('0.1.0-dev.11'))
        self.systemd.events.clear()
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_return_failure_preserves_uncertain_intent_and_refuses_replay(self):
        ticket = self.retained_update()
        self.fail_health_version = '0.1.0-dev.10'
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.systemd.events.clear()
        self.fail_health_version = None
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])
        with self.assertRaises(activate.RecoveryRequired):
            self.run_activation(self.build('0.1.0-dev.12'))
        self.assertEqual(self.systemd.events, [])

    def test_uncertain_service_quiescence_preserves_selector_and_requires_reconciliation(self):
        ticket = self.retained_update()
        self.systemd.fail_quiescence = True
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/0.1.0-dev.11')
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.systemd.events.clear()
        self.systemd.fail_quiescence = False
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_unhealthy_current_collector_cannot_start_a_new_return_transaction(self):
        ticket = self.retained_update()
        before = (self.state / 'activation.json').read_bytes()
        self.fail_health_version = '0.1.0-dev.11'
        with self.assertRaises(activate.ActivationError):
            self.run_restoration(ticket)
        self.assertEqual((self.state / 'activation.json').read_bytes(), before)
        self.assertEqual(list(self.state.glob('restoration-*')), [])
        self.assertEqual(self.systemd.events, [])

    def test_return_uses_the_normal_exclusive_activation_lock(self):
        ticket = self.retained_update()
        descriptor = os.open(self.state / 'activation.lock', os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                self.run_restoration(ticket)
        finally:
            os.close(descriptor)
        self.assertEqual(self.systemd.events, [])

    def test_changed_managed_receipts_and_units_are_preserved_without_return_effects(self):
        ticket = self.retained_update()
        paths = [self.state / ('admission-' + ticket['activationId'] + '.json'),
                 self.state / 'installed.json', self.state / 'activation.json',
                 self.units / 'orbis-sentinel.service']
        for path in paths:
            original = path.read_bytes()
            changed = original.replace(b'complete', b'prepared') if path.name == 'activation.json' else original + b' '
            path.write_bytes(changed)
            with self.subTest(name=path.name), self.assertRaises(activate.ActivationError):
                self.run_restoration(ticket)
            self.assertEqual(path.read_bytes(), changed)
            self.assertEqual(self.systemd.events, [])
            path.write_bytes(original)

    def test_unprotected_or_symlinked_retention_cannot_authorize_return(self):
        ticket = self.retained_update()
        path = self.state / ('retention-' + ticket['activationId'] + '.json')
        path.chmod(0o644)
        with self.assertRaises(activate.ActivationError):
            self.run_restoration(ticket)
        path.chmod(0o600)
        held = self.state / 'held-retention.json'
        path.rename(held)
        path.symlink_to(held.name)
        with self.assertRaises(OSError):
            self.run_restoration(ticket)
        self.assertTrue(path.is_symlink())
        self.assertTrue(held.is_file())
        self.assertEqual(self.systemd.events, [])

    def test_observer_profile_must_be_restored_separately_before_collector_return(self):
        self.run_activation()
        original_profile = self.managed_observer('orbis-observer-v1')
        binding = {'operationId': str(uuid.uuid4()), 'planSha256': '2' * 64, 'targetDigest': 'sha256:' + '3' * 64}
        ticket = self.run_activation(self.build('0.1.0-dev.11'), retain=binding)['retainedRollback']
        self.managed_observer('orbis-observer-v2')
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.RecoveryRequired, 'original managed observer profile'):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])
        self.managed_observer('orbis-observer-v1')
        self.run_restoration(ticket)
        self.assertEqual(activate._profile(self.systemd, True)['observerProfile'], original_profile)

    def test_lost_final_receipt_is_held_even_when_old_version_is_already_selected(self):
        ticket = self.retained_update()
        write = activate._write
        fail = True

        def write_with_lost_completion(parent, name, body, *args):
            nonlocal fail
            if fail and name == 'activation.json' and json.loads(body)['phase'] == 'complete':
                fail = False
                raise OSError('Synthetic lost completion write')
            return write(parent, name, body, *args)

        with mock.patch.object(activate, '_write', write_with_lost_completion), self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.assertEqual(json.loads((self.state / 'installed.json').read_bytes())['version'], '0.1.0-dev.10')
        self.systemd.events.clear()
        with self.assertRaises(activate.RecoveryRequired):
            self.run_restoration(ticket)
        self.assertEqual(self.systemd.events, [])

    def test_orphan_observer_receipt_is_not_silently_dropped(self):
        self.run_activation()
        self.managed_observer()
        self.observer_paths['collector'].unlink()
        self.observer_paths['collector'].parent.rmdir()
        self.systemd.unit_drop_ins.clear()
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'profile requires review'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertTrue((self.state / 'observer-profile.json').exists())
        self.assertEqual(self.systemd.events, [])

    def test_invalid_group_identity_cannot_broaden_the_managed_collector_profile(self):
        self.run_activation()
        self.managed_observer()
        newer = self.build('0.1.0-dev.11')
        self.systemd.events.clear()
        for group in (0, -1, 2**31, True, '1234'):
            with self.subTest(group=group):
                self.observer_group.gr_gid = group
                with self.assertRaisesRegex(activate.ActivationError, 'observer group'):
                    self.run_activation(newer)
                self.assertEqual(self.systemd.events, [])

    def test_extra_unloaded_dropin_is_preserved_for_review(self):
        self.run_activation()
        self.managed_observer()
        extra = self.observer_paths['collector'].parent / 'extra.conf'
        extra.write_text('[Service]\nProtectSystem=false\n')
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'unreviewed observer drop-in'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(extra.read_text(), '[Service]\nProtectSystem=false\n')
        self.assertEqual(self.systemd.events, [])

    def test_modified_or_public_observer_receipt_is_refused_before_supervisor_changes(self):
        self.run_activation()
        self.managed_observer()
        receipt = self.state / 'observer-profile.json'
        original = receipt.read_bytes()
        newer = self.build('0.1.0-dev.11')
        self.systemd.events.clear()
        receipt.write_bytes(original.replace(b'1234', b'1235'))
        with self.assertRaisesRegex(activate.ActivationError, 'receipt differs'):
            self.run_activation(newer)
        receipt.write_bytes(original)
        receipt.chmod(0o644)
        with self.assertRaisesRegex(activate.ActivationError, 'untrusted identity'):
            self.run_activation(newer)
        self.assertEqual(self.systemd.events, [])

    def test_a_symlinked_managed_profile_is_refused_without_following_it(self):
        self.run_activation()
        self.managed_observer()
        collector = self.observer_paths['collector']
        retained = self.root / 'retained-observer.conf'
        collector.rename(retained)
        collector.symlink_to(retained)
        before = retained.read_bytes()
        self.systemd.events.clear()
        with self.assertRaises(OSError):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(retained.read_bytes(), before)
        self.assertTrue(collector.is_symlink())
        self.assertEqual(self.systemd.events, [])

    def test_recorded_managed_observer_survives_a_collector_update(self):
        self.run_activation()
        receipt = self.managed_observer()
        before = {role: file.read_bytes() for role, file in self.observer_paths.items()}
        result = self.run_activation(self.build('0.1.0-dev.11'))
        self.assertTrue(result['activated'])
        self.assertEqual(self.journal()['previousUnits']['observerProfile'], receipt)
        self.assertEqual(before, {role: file.read_bytes() for role, file in self.observer_paths.items()})
        self.assertEqual((self.state / 'observer-profile.json').read_bytes(), activate._encoded(receipt))

    def test_recorded_independent_upgrade_observer_survives_a_collector_update(self):
        self.run_activation()
        receipt = self.managed_observer('orbis-observer-v2')
        before = {role: file.read_bytes() for role, file in self.observer_paths.items()}
        result = self.run_activation(self.build('0.1.0-dev.11'))
        self.assertTrue(result['activated'])
        self.assertEqual(self.journal()['previousUnits']['observerProfile'], receipt)
        self.assertEqual(before, {role: file.read_bytes() for role, file in self.observer_paths.items()})

    def test_profile_name_does_not_authorize_the_other_collector_template(self):
        self.run_activation()
        receipt = self.managed_observer('orbis-observer-v2')
        self.observer_paths['collector'].write_bytes((PACKAGING / 'systemd/orbis-sentinel.service.d/observer.conf').read_bytes())
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'observer files changed'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(self.systemd.events, [])
        self.assertEqual((self.state / 'observer-profile.json').read_bytes(), activate._encoded(receipt))

    def test_unknown_profile_and_unrecorded_profile_transition_are_refused(self):
        self.run_activation()
        receipt = self.managed_observer('orbis-observer-v2')
        for name in ('orbis-observer-v3', 'orbis-observer-v1'):
            changed = {**receipt, 'profile': name}
            (self.state / 'observer-profile.json').write_bytes(activate._encoded(changed))
            self.systemd.events.clear()
            with self.subTest(profile=name), self.assertRaises(activate.ActivationError):
                self.run_activation(self.build('0.1.0-dev.11'))
            self.assertEqual(self.systemd.events, [])

    def test_known_observer_bytes_without_a_managed_receipt_are_not_adopted(self):
        self.run_activation()
        self.managed_observer()
        (self.state / 'observer-profile.json').unlink()
        previous = (self.install / 'current').readlink()
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'adoption requires'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual((self.install / 'current').readlink(), previous)
        self.assertEqual(self.systemd.events, [])

    def test_observer_files_or_receipt_drift_are_preserved_without_supervisor_changes(self):
        self.run_activation()
        self.managed_observer()
        self.observer_paths['collector'].write_bytes(b'[Service]\nGroup=unreviewed\n')
        before = self.observer_paths['collector'].read_bytes()
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'observer files changed'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(self.observer_paths['collector'].read_bytes(), before)
        self.assertEqual(self.systemd.events, [])

    def test_loaded_host_observer_drift_is_refused_before_activation(self):
        self.run_activation()
        self.managed_observer()
        self.systemd.extra_profiles['orbis-host.service']['DropInPaths'] += ' /foreign.conf'
        self.systemd.events.clear()
        with self.assertRaisesRegex(activate.ActivationError, 'loaded Host observer'):
            self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(self.systemd.events, [])

    def test_wrong_candidate_health_restores_the_old_collector_and_retains_the_observer(self):
        self.run_activation()
        receipt = self.managed_observer()
        before = (self.state / 'installed.json').read_bytes()
        newer = self.build('0.1.0-dev.11')
        self.fail_health_version = newer['version']
        with self.assertRaisesRegex(activate.ActivationError, 'previous configuration was restored'):
            self.run_activation(newer)
        self.assertEqual(self.journal()['phase'], 'rolled-back')
        self.assertEqual((self.state / 'installed.json').read_bytes(), before)
        self.assertEqual((self.state / 'observer-profile.json').read_bytes(), activate._encoded(receipt))

    def test_observer_changes_during_startup_leave_reconciliation_instead_of_claiming_rollback(self):
        self.run_activation()
        self.managed_observer()
        ready = self.ready
        def changed(systemd, version):
            ready(systemd, version)
            self.observer_group.gr_gid = 1235
        with mock.patch.object(activate, '_ready', side_effect=changed):
            with self.assertRaises(activate.RecoveryRequired):
                self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(self.journal()['phase'], 'recovery-required')
        self.assertTrue((self.install / 'releases/0.1.0-dev.10').is_dir())
        self.assertTrue((self.install / 'releases/0.1.0-dev.11').is_dir())

    def test_even_a_known_profile_transition_during_activation_requires_reconciliation(self):
        self.run_activation()
        self.managed_observer()
        ready = self.ready
        def changed(systemd, version):
            ready(systemd, version)
            self.managed_observer('orbis-observer-v2')
        with mock.patch.object(activate, '_ready', side_effect=changed):
            with self.assertRaises(activate.RecoveryRequired):
                self.run_activation(self.build('0.1.0-dev.11'))
        self.assertEqual(self.journal()['phase'], 'recovery-required')

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

    def test_older_candidate_is_refused_before_publisher_or_supervisor_actions(self):
        self.run_activation()
        self.run_activation(self.build('0.1.0-dev.11'))
        before = {name: (self.state / name).read_bytes() for name in ('installed.json', 'activation.json')}
        self.systemd.events.clear()
        with mock.patch.object(activate, 'verify_release') as verifier:
            with self.assertRaisesRegex(activate.ActivationError, 'no downgrade was made'):
                self.run_activation(self.package)
            verifier.assert_not_called()
        self.assertEqual(self.systemd.events, [])
        self.assertEqual((self.install / 'current').readlink().as_posix(), 'releases/0.1.0-dev.11')
        self.assertEqual({name: (self.state / name).read_bytes() for name in before}, before)

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
        with mock.patch.object(activate, '_health') as health, mock.patch.object(activate, '_observer_profile', return_value=None):
            activate._ready(systemd, '1.2.3', timeout=0)
            health.assert_called_once()

    def test_ready_refuses_missing_cgroup_evidence_before_the_health_probe(self):
        systemd = mock.Mock()
        def inspect(name):
            value = self.running(name)
            value['ControlGroup'] = ''
            return value
        systemd.inspect.side_effect = inspect
        with mock.patch.object(activate, '_health') as health, mock.patch.object(activate, '_observer_profile', return_value=None):
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
                with self.assertRaisesRegex(activate.ActivationError, 'Linux root operator'):
                    activate.restore_retained(None)


if __name__ == '__main__':
    unittest.main()
