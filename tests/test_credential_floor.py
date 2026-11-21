"""Actual private files/FD drift and finite history comparison, no runtime grant.

Fixture bindings are synthetic, never installed publisher or live Root evidence.
No recovery key, Docker, native service or production activation is exercised.
"""
import copy
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import credential_floor as floor
from orbis_sentinel import credential_storage as storage
from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel.bootstrap_source import encoded, digest
from orbis_sentinel.writer_journal import directory_seal, mount_id


class CredentialFloorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='credential-floor-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.base.chmod(0o700)
        self.root = self.directory('main'); self.root.chmod(0o755)
        self.state, self.host = self.directory('state'), self.directory('host')
        self.recovery, self.envdir = self.directory('recovery'), self.directory('etc')
        for name, value in (('STATE_ROOT', self.state), ('RECOVERY_ROOT', self.recovery),
                            ('RECOVERY_ENV', self.envdir / 'recovery.env'),
                            ('RECOVERY_UNIT', self.envdir / 'orbis-sentinel-recovery.service')):
            patch = mock.patch.object(floor, name, value)
            patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start(); self.addCleanup(patch.stop)
        self.namespace = self.state / 'installations' / digest(os.fsencode(str(self.root)))
        self.namespace.mkdir(parents=True, mode=0o700)
        self.namespace.parent.chmod(0o700)
        self.identity = digest(encoded({'root': str(self.root), 'context': 'default', 'daemon': 'local-daemon',
                                       'rootIdentity': directory_seal(self.root.stat())}))
        self.reader = floor.CredentialFloorReader(self.root, 'default', 'local-daemon', host_state_directory=self.host)

    def directory(self, name):
        path = self.base / name
        path.mkdir(mode=0o700)
        return path

    def write(self, path, value):
        body = value if type(value) is bytes else encoded(value)
        path.write_bytes(body); path.chmod(0o600)
        return digest(body)

    def storage(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return {'identity': list(directory_seal(os.fstat(fd))), 'mountId': mount_id(fd)}
        finally:
            os.close(fd)

    def fixture(self):
        journal = self.namespace / 'credential-journal'
        journal.mkdir(mode=0o700, exist_ok=True)
        image = 'sha256:' + '1' * 64
        origin = 'https://recovery.example'
        recovery = {'schema': 'orbis.sentinel-recovery-config.v1', 'directory': str(self.recovery),
                    'origin': origin, 'imageId': image, 'listenPort': 9443, 'statusSocket': '/run/orbis-sentinel/api.sock'}
        recovery_sha = self.write(self.recovery / 'config.json', recovery)
        admission = {'schema': 'orbis.host.credential-admission.v1', 'root': str(self.root), 'context': 'default',
                     'installationId': self.identity, 'mode': 'managed', 'origin': origin,
                     'writerProtocol': 1, 'recoveryEpoch': 'e' * 64, 'runtimeDirectory': str(self.base / 'retained-runtime'),
                     'runtimeFiles': dict.fromkeys(('__init__.py', 'writer_broker.py', 'writer_control.py', 'writer_journal.py',
                                                   'recovery_sessions.py', 'recovery_config.py'), 'f' * 64),
                     'recoveryConfig': str(self.recovery / 'config.json'), 'recoveryConfigSha256': recovery_sha,
                     'journalDirectory': str(journal)}
        configuration = {'recoveryConfigSha256': recovery_sha,
                         'hostAdmissionSha256': self.write(self.host / 'credential-admission.json', admission),
                         'recoveryEnvironmentSha256': self.write(self.envdir / 'recovery.env', b'SYNTHETIC_PRIVATE_FIXTURE=1\n')}
        current = {
            'main': {'imageId': image, 'creationSha256': '2' * 64, 'publicationSha256': '3' * 64},
            'host': dict.fromkeys(('inventorySha256', 'unitSha256', 'environmentSha256'), '4' * 64),
            'sentinel': {'version': '0.1.0', **dict.fromkeys(('inventorySha256', 'runtimeSha256', 'unitSha256', 'environmentSha256'), '5' * 64)},
            'authWorker': {'imageId': image, 'anchorSha256': '6' * 64, 'capabilitiesSha256': '7' * 64},
            'sourceExporter': {'imageId': image, 'programSha256': '8' * 64, 'capabilitiesSha256': '9' * 64},
            'recoveryOrigin': origin, 'configuration': configuration,
            'storage': {'namespace': self.storage(self.namespace), 'journal': self.storage(journal),
                        'recovery': self.storage(self.recovery), 'journalSchema': 'orbis.sentinel-writer-journal.v1'},
            'receipts': dict.fromkeys(('bootstrapSha256', 'sourceSha256', 'activationSha256'), 'a' * 64)}
        return {'schema': floor.LEGACY_SCHEMA, 'installationId': self.identity, 'generation': 1, 'managedEver': True,
                'mode': 'managed', 'configSha256': configuration['hostAdmissionSha256'], 'planSha256': 'b' * 64,
                'sentinelVersion': '0.1.0', 'writerProtocol': 1, 'previousSha256': None,
                'minimum': {name: {'family': family, 'version': version} for name, (family, version) in floor.CONTRACTS.items()},
                'current': current, 'positiveNeverManaged': None}

    def save(self, value):
        return self.write(self.namespace / floor.HISTORY, value)

    def report(self):
        with self.reader.snapshot() as snapshot:
            return snapshot.report

    def successor(self, previous):
        archive = self.namespace / floor.ARCHIVE
        archive.mkdir(mode=0o700, exist_ok=True)
        previous_sha = self.write(archive / (digest(encoded(previous)) + '.json'), previous)
        value = copy.deepcopy(previous)
        value['generation'] += 1
        value['previousSha256'] = previous_sha
        value['planSha256'] = 'c' * 64
        return value

    def initializing(self, value):
        value = copy.deepcopy(value)
        value.update(mode='initializing-never-managed', managedEver=False)
        value['current']['receipts'] = dict.fromkeys(value['current']['receipts'])
        value['positiveNeverManaged'] = {'schema': 'orbis.credential-floor-initialization.v1', 'operationId': 'd' * 64,
            'installationId': self.identity, 'kind': 'fresh-initialize', 'scope': 'create-missing-auth',
            'imageId': value['current']['main']['imageId'], 'creationSha256': value['current']['main']['creationSha256'],
            'storageSha256': digest(encoded(value['current']['storage'])), 'issuedAtMs': 1000, 'expiresAtMs': 2000}
        return value

    def test_v1_bootstrap_parent_preserves_the_existing_upgrade_hold(self):
        parent = {'schema': 'orbis.recovery-admission-history.v1', 'installationId': self.identity,
                  'generation': 1, 'managedEver': False, 'mode': 'unmanaged', 'configSha256': 'd' * 64,
                  'planSha256': 'e' * 64, 'sentinelVersion': '0.1.0', 'writerProtocol': 1}
        body = encoded(parent)
        child = self.fixture()
        child.update(schema=floor.SCHEMA, generation=2, previousSha256=digest(body))
        child['current']['storage'] = {'bridgeSha256': 'f' * 64, 'parentFloorSha256': digest(body),
                                       'journalSchema': 'orbis.sentinel-writer-journal.v1'}
        self.assertEqual(floor._bootstrap_parent(body, child, self.identity), parent)
        with self.assertRaises(floor._LegacyUpgrade):
            floor._legacy(parent, self.identity)
        for changes in ({'managedEver': True}, {'mode': 'managed', 'managedEver': True},
                        {'installationId': '0' * 64}, {'writerProtocol': 2}, {'sentinelVersion': '99.0.0'}):
            changed = {**parent, **changes}
            changed_body = encoded(changed)
            successor = copy.deepcopy(child)
            successor['previousSha256'] = successor['current']['storage']['parentFloorSha256'] = digest(changed_body)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                floor._bootstrap_parent(changed_body, successor, self.identity)
        for changes in ({'generation': 3}, {'previousSha256': '0' * 64}, {'schema': floor.LEGACY_SCHEMA}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                floor._bootstrap_parent(body, {**child, **changes}, self.identity)
        with self.assertRaises(ValueError):
            floor._bootstrap_parent(body + b'\n', child, self.identity)

    def stable_observation(self, directory):
        info = os.fstat(directory.fd)
        return {'path': str(directory.path), 'filesystem': 'ext4', 'uuid': 'a' * 32,
                'handle': f'{info.st_ino:016x}', 'owner': [info.st_uid, info.st_gid, info.st_mode],
                'filesystemPath': str(directory.path), 'mountPoint': '/', 'mountRoot': '/'}

    def v3(self, *, installation=None):
        """Materialize a synthetic file fixture, never production publisher evidence."""
        prior = self.fixture()
        if installation is not None:
            prior['installationId'] = installation
            admission_path = self.host / 'credential-admission.json'
            admission = floor.decode(admission_path.read_bytes())
            admission['installationId'] = installation
            prior['current']['configuration']['hostAdmissionSha256'] = self.write(admission_path, admission)
            prior['configSha256'] = prior['current']['configuration']['hostAdmissionSha256']
        prior['minimum']['reader']['version'] = 2
        unit = b'[Service]\nProtectHome=yes\n'
        unit_digest = self.write(floor.RECOVERY_UNIT, unit)
        floor.RECOVERY_UNIT.chmod(0o644)
        prior['current']['sentinel']['unitSha256'] = unit_digest
        successor = self.successor(prior)
        role_paths = {'installation': self.root, 'namespace': self.namespace, 'recovery': self.recovery,
                      'journal': self.namespace / 'credential-journal'}
        roles = {}
        for role, path in role_paths.items():
            directory = floor._InstallationDirectory(path)
            try:
                roles[role] = self.stable_observation(directory)
            finally:
                directory.close()
        bridge = {'schema': storage.BRIDGE_SCHEMA, 'installationId': prior['installationId'],
                  'context': 'default', 'daemon': 'local-daemon',
                  'parentFloorSha256': successor['previousSha256'], 'publicationOperation': 'c' * 64,
                  'publicationSha256': 'd' * 64, 'recoveryUnitSha256': unit_digest, 'roles': roles}
        bridge_body = encoded(bridge)
        directory = self.namespace / storage.BRIDGE_DIRECTORY
        directory.mkdir(mode=0o700)
        self.write(directory / (digest(bridge_body) + '.json'), bridge_body)
        successor['schema'] = floor.SCHEMA
        successor['minimum']['reader']['version'] = 3
        successor['current']['storage'] = {'bridgeSha256': digest(bridge_body),
            'parentFloorSha256': successor['previousSha256'], 'journalSchema': 'orbis.sentinel-writer-journal.v1'}
        self.save(successor)
        return successor, bridge

    def test_v3_reopens_after_local_mount_ids_and_legacy_device_identity_change(self):
        value, _ = self.v3(installation='3' * 64)
        original = (self.namespace / floor.ARCHIVE / (value['previousSha256'] + '.json')).read_bytes()
        self.assertNotEqual(value['installationId'], self.identity)
        with mock.patch.object(storage, 'observe', side_effect=self.stable_observation), \
             mock.patch.object(floor, 'mount_id', return_value=12345), \
             mock.patch('orbis_sentinel.bootstrap_source.mount_id', return_value=12345):
            with self.reader.snapshot() as live:
                self.assertEqual(live.report.classification, 'record-consistent')
                self.assertEqual(live.compare_candidate(minimum=value['minimum'], current=value['current']).differences, ())
                self.assertEqual(digest(original), value['previousSha256'])
                with mock.patch.object(floor, 'mount_id', return_value=99999):
                    with self.assertRaises(floor.CredentialFloorError):
                        live.recheck()

    def bootstrap_v3(self):
        """Synthetic consumer fixture; the publication verifier is tested separately."""
        value, bridge = self.v3()
        parent = {'schema': 'orbis.recovery-admission-history.v1', 'installationId': self.identity,
                  'generation': 1, 'managedEver': False, 'mode': 'unmanaged', 'configSha256': 'd' * 64,
                  'planSha256': 'e' * 64, 'sentinelVersion': '0.1.0', 'writerProtocol': 1}
        previous = digest(encoded(parent))
        self.write(self.namespace / floor.ARCHIVE / (previous + '.json'), parent)
        value['previousSha256'] = value['current']['storage']['parentFloorSha256'] = previous
        bridge.update(schema=storage.ACTIVATION_BRIDGE, parentFloorSha256=previous)
        bridge_sha = self.write(self.namespace / storage.BRIDGE_DIRECTORY / (digest(encoded(bridge)) + '.json'), bridge)
        value['current']['storage']['bridgeSha256'] = bridge_sha
        self.save(value)
        return value

    def publication_reader(self, first, verify):
        from orbis_sentinel.bootstrap_publication import PublishedWitness
        @contextmanager
        def read(namespace, **arguments):
            self.assertEqual(namespace, self.namespace)
            self.assertEqual(arguments, {'recovery_directory': self.recovery, 'root': self.root, 'context': 'default',
                                        'daemon': 'local-daemon', 'history_body': encoded(first)})
            # Host and Sessions generations are independent, even when fixture
            # values happen to coincide in other bootstrap tests.
            yield PublishedWitness('1' * 64, '2' * 64, '3' * 64, '4' * 64, first['generation'], 7, verify)
        return read

    def test_bootstrap_floor_requires_published_proof_and_retains_its_recheck(self):
        from orbis_sentinel import bootstrap_publication as publication
        value = self.bootstrap_v3()
        with mock.patch.object(publication, 'read_published', side_effect=FileNotFoundError):
            self.assertEqual(self.report().classification, 'held-transition')
        verify = mock.Mock()
        with mock.patch.object(publication, 'read_published', self.publication_reader(value, verify)), \
                mock.patch.object(storage, 'observe', side_effect=self.stable_observation):
            with self.assertRaises(ValueError):
                with self.reader.snapshot() as live:
                    self.assertEqual(live.report.classification, 'record-consistent')
                    verify.assert_called()
                    verify.side_effect = ValueError('Published evidence changed')
                    live.recheck()

    def test_descendant_uses_the_original_published_child_and_cannot_change_storage(self):
        from orbis_sentinel import bootstrap_publication as publication
        first = self.bootstrap_v3()
        newest = self.successor(first)
        self.save(newest)
        with mock.patch.object(publication, 'read_published', self.publication_reader(first, mock.Mock())), \
                mock.patch.object(storage, 'observe', side_effect=self.stable_observation):
            with self.reader.snapshot() as live:
                self.assertEqual(live.report.classification, 'record-consistent')
                self.assertEqual(live.report.generation, 3)
            newest['current']['storage']['bridgeSha256'] = '9' * 64
            self.save(newest)
            self.assertEqual(self.report().classification, 'unknown')

    def test_a_restored_live_hold_closes_a_published_bootstrap_floor(self):
        from orbis_sentinel import bootstrap_publication as publication
        first = self.bootstrap_v3()
        with mock.patch.object(publication, 'read_published', self.publication_reader(first, mock.Mock())), \
                mock.patch.object(storage, 'observe', side_effect=self.stable_observation):
            self.write(self.namespace / 'credential-fence.json', {})
            self.assertEqual(self.report().classification, 'held-transition')

    def test_a_published_witness_cannot_adopt_an_ordinary_bridge(self):
        from orbis_sentinel import bootstrap_publication as publication
        first = self.bootstrap_v3()
        selected = self.namespace / storage.BRIDGE_DIRECTORY / (first['current']['storage']['bridgeSha256'] + '.json')
        bridge = floor.decode(selected.read_bytes())
        bridge['schema'] = storage.BRIDGE_SCHEMA
        new_sha = self.write(selected.parent / (digest(encoded(bridge)) + '.json'), bridge)
        first['current']['storage']['bridgeSha256'] = new_sha
        self.save(first)
        with mock.patch.object(publication, 'read_published', self.publication_reader(first, mock.Mock())), \
                mock.patch.object(storage, 'observe', side_effect=self.stable_observation):
            self.assertEqual(self.report().classification, 'unknown')

    def test_v3_recovery_self_bind_is_limited_to_fixed_unit_and_no_main_authority(self):
        value, _ = self.v3()
        native = self.stable_observation

        def bound(directory):
            result = native(directory)
            if directory.path == self.recovery:
                result.update(mountPoint=str(self.recovery), mountRoot=result['filesystemPath'])
            return result

        with mock.patch.object(storage, 'observe', side_effect=bound), \
             mock.patch.object(storage, 'in_recovery_unit', return_value=True):
            self.assertEqual(self.report().classification, 'unknown')
            with mock.patch.object(floor, '_InstallationDirectory', side_effect=AssertionError('unexpected Main read')):
                with self.reader.recovery_snapshot() as recovery:
                    self.assertEqual(recovery.report.classification, 'recovery-storage-consistent')
                    self.assertEqual(recovery.compare_candidate(minimum=value['minimum'], current=value['current']).differences,
                                     ('history-held',))
        with mock.patch.object(storage, 'observe', side_effect=bound), mock.patch.object(storage, 'in_recovery_unit', return_value=False):
            with self.reader.recovery_snapshot() as unavailable:
                self.assertEqual(unavailable.report.classification, 'unknown')

    def test_v3_unsupported_filesystem_is_an_explicit_hold(self):
        self.v3()
        with mock.patch.object(storage, 'observe', side_effect=storage.UnsupportedCredentialStorage()):
            self.assertEqual(self.report().reasons, ('unsupported-credential-storage',))

    def test_v3_copied_storage_and_bridge_tamper_fail_closed(self):
        value, _ = self.v3()
        native = self.stable_observation
        def swapped(directory):
            observed = native(directory)
            if directory.path == self.recovery:
                observed['handle'] = 'c' * 16
            return observed
        with mock.patch.object(storage, 'observe', side_effect=swapped):
            self.assertEqual(self.report().classification, 'unknown')
        bridge = self.namespace / storage.BRIDGE_DIRECTORY / (value['current']['storage']['bridgeSha256'] + '.json')
        self.write(bridge, b'false')
        with mock.patch.object(storage, 'observe', side_effect=native):
            self.assertEqual(self.report().classification, 'unknown')

    def test_v3_rechecks_installed_recovery_unit_and_blocks_v2_downgrade(self):
        value, _ = self.v3()
        with mock.patch.object(storage, 'observe', side_effect=self.stable_observation):
            with self.assertRaises(floor.CredentialFloorError):
                with self.reader.snapshot() as live:
                    self.assertEqual(live.report.classification, 'record-consistent')
                    path = floor.RECOVERY_UNIT
                    path.write_bytes(b'replacement')
                    live.recheck()
        downgraded = self.successor(value)
        downgraded['schema'] = floor.LEGACY_SCHEMA
        legacy = floor.decode((self.namespace / floor.ARCHIVE / (value['previousSha256'] + '.json')).read_bytes())
        downgraded['current']['storage'] = legacy['current']['storage']
        self.save(downgraded)
        self.assertEqual(self.report().classification, 'held-transition')
        self.save(legacy)
        self.assertIn('history-stable-storage-upgrade-required', self.report().reasons)

    def test_consistent_record_is_explicitly_not_runtime_admission(self):
        value = self.fixture(); self.save(value)
        with self.reader.snapshot() as snapshot:
            self.assertEqual(snapshot.report.classification, 'record-consistent')
            self.assertIn('publisher-runtime-and-live-state-unverified', snapshot.report.reasons)
            self.assertEqual(snapshot.compare_candidate(minimum=value['minimum'], current=value['current']).differences, ())
            self.assertFalse(hasattr(snapshot, 'allowed'))
            self.assertFalse(hasattr(snapshot.report, 'allowed'))
        with self.assertRaises(floor.CredentialFloorError): snapshot.recheck()

    def test_missing_history_is_informative_only(self):
        report = self.report()
        self.assertEqual(report.classification, 'legacy-unadmitted')
        self.assertFalse((self.namespace / floor.HISTORY).exists())
        with self.reader.snapshot() as snapshot:
            self.assertEqual(snapshot.compare_candidate(minimum={}, current={}).differences, ('history-held',))

    def test_missing_namespace_holds_and_does_not_create(self):
        self.namespace.rmdir()
        self.assertEqual(self.report().classification, 'unknown')
        self.assertFalse(self.namespace.exists())

    def test_missing_history_with_independent_anchors_holds(self):
        for path in (self.recovery / 'recovery.sqlite3', self.recovery / 'bootstrap',
                     self.envdir / 'recovery.env', self.namespace / 'recovery-admission-intent.json'):
            with self.subTest(path=path):
                self.write(path, b'preserve unknown evidence')
                self.assertEqual(self.report().classification, 'unknown')
                path.unlink()

    def test_existing_v1_and_v1_predecessor_require_upgrade(self):
        value = self.fixture()
        legacy = {key: value[key] for key in ('installationId', 'generation', 'managedEver', 'mode', 'configSha256', 'planSha256', 'sentinelVersion', 'writerProtocol')}
        legacy['schema'] = 'orbis.recovery-admission-history.v1'
        self.save(legacy)
        self.assertEqual(self.report().reasons, ('history-v1-upgrade-required',))
        successor = self.successor(legacy)
        successor.update({key: value[key] for key in ('schema', 'minimum', 'current', 'positiveNeverManaged')})
        self.save(successor)
        self.assertEqual(self.report().reasons, ('history-v1-upgrade-required',))

    def test_corrupt_or_crossed_v1_is_unknown(self):
        value = self.fixture()
        self.save({'schema': 'orbis.recovery-admission-history.v1', 'managedEver': True})
        self.assertEqual(self.report().classification, 'unknown')
        legacy = {key: value[key] for key in ('installationId', 'generation', 'managedEver', 'mode', 'configSha256', 'planSha256', 'sentinelVersion', 'writerProtocol')}
        legacy.update(schema='orbis.recovery-admission-history.v1', installationId='f' * 64)
        self.save(legacy)
        self.assertEqual(self.report().classification, 'unknown')

    def test_unknown_or_extra_schema_fields_hold(self):
        value = self.fixture()
        for change in (lambda v: v.update(schema='orbis.recovery-admission-history.v3'),
                       lambda v: v.update(allowed=True), lambda v: v['minimum'].update(unrecognized={'family': 'x', 'version': 1}),
                       lambda v: v['current'].update(counter=99)):
            with self.subTest(change=change):
                altered = copy.deepcopy(value); change(altered); self.save(altered)
                self.assertEqual(self.report().classification, 'unknown')

    def test_strict_json_rejects_duplicates_nan_and_float_generations(self):
        value = self.fixture()
        for body in (b'{"schema":"x","schema":"y"}', b'{"generation":NaN}',
                     encoded({**value, 'generation': 1.0})):
            self.save(body)
            self.assertEqual(self.report().classification, 'unknown')

    def test_root_context_daemon_or_installation_changes_hold(self):
        self.save(self.fixture())
        for context, daemon in (('other-context', 'local-daemon'), ('default', 'other-daemon')):
            reader = floor.CredentialFloorReader(self.root, context, daemon, host_state_directory=self.host)
            with reader.snapshot() as snapshot:
                self.assertEqual(snapshot.report.classification, 'unknown')

    def test_supported_contract_family_and_minimum_are_distinct(self):
        value = self.fixture(); self.save(value)
        candidate = copy.deepcopy(value['minimum']); candidate['reader']['version'] = 1
        with self.reader.snapshot() as snapshot:
            self.assertIn('minimum.reader.below-floor', snapshot.compare_candidate(minimum=candidate, current=value['current']).differences)
            candidate['reader']['version'] = floor.CONTRACTS['reader'][1] + 1
            self.assertIn('minimum.reader.unsupported', snapshot.compare_candidate(minimum=candidate, current=value['current']).differences)
            candidate['reader']['family'] = 'unrelated'
            with self.assertRaises(floor.CredentialFloorError): snapshot.compare_candidate(minimum=candidate, current=value['current'])

    def test_record_above_reader_capability_holds(self):
        value = self.fixture(); value['minimum']['reader']['version'] = floor.CONTRACTS['reader'][1] + 1; self.save(value)
        self.assertEqual(self.report().reasons, ('minimum.reader.unsupported',))

    def test_host_protocol_and_main_writer_contract_are_independent(self):
        value = self.fixture()
        value['minimum']['hostBroker']['version'] = value['writerProtocol'] = 2
        # Shape/lineage contract may represent Host2/Main1. Current Host1 reader
        # still holds that future capability; this is not runtime acceptance.
        floor.record(value, self.identity)
        self.save(value)
        self.assertEqual(self.report().reasons, ('minimum.hostBroker.unsupported',))
        for host, main, crossed in ((2, 1, 1), (1, 2, 2)):
            with self.subTest(host=host, main=main, writerProtocol=crossed):
                value['minimum']['hostBroker']['version'] = host
                value['minimum']['mainWriter']['version'] = main
                value['writerProtocol'] = crossed
                with self.assertRaises(floor.CredentialFloorError): floor.record(value, self.identity)
                self.save(value)
                self.assertEqual(self.report().classification, 'unknown')

    def test_actual_host_admission_protocol_type_and_binding_are_exact(self):
        value = self.fixture()
        path = self.host / 'credential-admission.json'
        admission = floor.decode(path.read_bytes())
        for protocol in (True, 2):
            with self.subTest(protocol=protocol):
                admission['writerProtocol'] = protocol
                sha = self.write(path, admission)
                value['configSha256'] = value['current']['configuration']['hostAdmissionSha256'] = sha
                self.save(value)
                self.assertEqual(self.report().classification, 'unknown')

    def test_exact_current_binding_cannot_be_replaced_by_higher_version(self):
        value = self.fixture(); self.save(value)
        for key in value['current']:
            if key in ('recoveryOrigin', 'storage', 'configuration', 'receipts'): continue
            with self.subTest(key=key):
                candidate = copy.deepcopy(value['current'])
                field = next(name for name in candidate[key] if name.endswith('Sha256'))
                candidate[key][field] = 'f' * 64
                with self.reader.snapshot() as snapshot:
                    self.assertEqual(snapshot.compare_candidate(minimum=value['minimum'], current=candidate).differences, ('current.' + key + '.changed',))

    def test_main_and_retained_auth_image_must_remain_equal(self):
        value = self.fixture(); value['current']['authWorker']['imageId'] = 'sha256:' + 'f' * 64; self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_contiguous_lineage_is_valid_and_preserves_exact_previous_bytes(self):
        value = self.successor(self.fixture()); self.save(value)
        self.assertEqual(self.report().classification, 'record-consistent')
        self.assertEqual(self.report().generation, 2)

    def test_missing_changed_or_skipped_predecessor_holds(self):
        value = self.successor(self.fixture()); self.save(value)
        archive = self.namespace / floor.ARCHIVE / (value['previousSha256'] + '.json')
        body = archive.read_bytes(); archive.unlink()
        self.assertEqual(self.report().classification, 'unknown')
        self.write(archive, body + b' ')
        self.assertEqual(self.report().classification, 'unknown')
        self.write(archive, body); value['generation'] = 3; self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_minimum_cannot_decrease_across_history(self):
        previous = self.fixture(); previous['minimum']['reader']['version'] = 3
        value = self.successor(previous); value['minimum']['reader']['version'] = 2; self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_sentinel_semantic_release_precedence_never_string_ordering(self):
        previous = self.fixture()
        for old, new, expected in (('0.9.0', '0.10.0', 'record-consistent'),
                                   ('0.10.0', '0.9.0', 'unknown'),
                                   ('0.1.0-rc.9', '0.1.0-rc.10', 'record-consistent'),
                                   ('0.1.0', '0.1.0-rc.11', 'unknown')):
            with self.subTest(old=old, new=new):
                previous['sentinelVersion'] = previous['current']['sentinel']['version'] = old
                value = self.successor(previous)
                value['sentinelVersion'] = value['current']['sentinel']['version'] = new
                self.save(value)
                self.assertEqual(self.report().classification, expected)

    def test_managed_ever_cannot_be_cleared(self):
        value = self.initializing(self.successor(self.fixture())); self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_config_hash_custody_and_crossed_installation_hold(self):
        value = self.fixture(); self.save(value)
        path = self.host / 'credential-admission.json'
        body = path.read_bytes(); self.write(path, body + b' ')
        self.assertEqual(self.report().classification, 'unknown')
        admission = floor.decode(body); admission['installationId'] = 'f' * 64
        sha = self.write(path, admission)
        value['configSha256'] = value['current']['configuration']['hostAdmissionSha256'] = sha
        self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_symlink_hardlink_and_public_history_hold(self):
        value = self.fixture(); self.save(value)
        path = self.namespace / floor.HISTORY
        target = self.namespace / 'preserved.json'; path.rename(target); path.symlink_to(target)
        self.assertEqual(self.report().classification, 'unknown')
        path.unlink(); os.link(target, path)
        self.assertEqual(self.report().classification, 'unknown')
        path.unlink(); target.rename(path); path.chmod(0o644)
        self.assertEqual(self.report().classification, 'unknown')

    def test_history_replacement_and_directory_alias_invalidate_context(self):
        value = self.fixture(); self.save(value)
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                replacement = self.namespace / 'replacement.json'; self.write(replacement, value)
                replacement.replace(self.namespace / floor.HISTORY)
                snapshot.recheck()
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                old = self.namespace.with_name('preserved-namespace')
                self.namespace.rename(old); self.namespace.symlink_to(old)
                snapshot.recheck()

    def test_orphaned_first_storage_temporary_holds_legacy_floor(self):
        current=self.fixture()
        self.save(current)
        pending=self.namespace/'.credential-storage-migration.json.pending'
        self.write(pending,b'incomplete owned evidence')
        with self.reader.snapshot() as snapshot:
            self.assertEqual(snapshot.report.classification,'held-transition')
            self.assertIn('history-stable-storage-upgrade-required',snapshot.report.reasons)
        self.assertEqual(pending.read_bytes(),b'incomplete owned evidence')
        self.assertEqual((self.namespace/floor.HISTORY).read_bytes(),encoded(current))

    def test_mount_drift_invalidates_held_context(self):
        self.save(self.fixture())
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                with mock.patch('orbis_sentinel.bootstrap_source.mount_id', return_value=999999): snapshot.recheck()

    def test_file_mount_alias_detected_even_with_same_file_identity(self):
        self.save(self.fixture())
        original_mount = floor.mount_id
        regular_calls = []
        def alias_only_fresh_file(fd):
            if stat.S_ISREG(os.fstat(fd).st_mode):
                regular_calls.append(fd)
                if len(regular_calls) % 2 == 0:
                    return 999999
            return original_mount(fd)
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                with mock.patch.object(floor, 'mount_id', side_effect=alias_only_fresh_file): snapshot.recheck()
        self.assertEqual(len(regular_calls), 2)

    def test_environment_parent_0755_is_protected_but_writable_parent_is_not(self):
        self.save(self.fixture()); self.envdir.chmod(0o755)
        self.assertEqual(self.report().classification, 'record-consistent')
        self.envdir.chmod(0o775)
        self.assertEqual(self.report().classification, 'unknown')

    def test_environment_parent_alias_and_replacement_invalidate_snapshot(self):
        self.save(self.fixture()); self.envdir.chmod(0o755)
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                old = self.envdir.with_name('preserved-environment')
                self.envdir.rename(old); self.envdir.symlink_to(old)
                snapshot.recheck()
        self.envdir.unlink(); old.rename(self.envdir)
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                self.envdir.rename(old); self.envdir.mkdir(mode=0o755)
                self.write(self.envdir / 'recovery.env', (old / 'recovery.env').read_bytes())
                snapshot.recheck()

    def test_mutable_journal_and_counter_data_are_not_floor_file_pins(self):
        value = self.fixture(); self.save(value)
        journal = self.namespace / 'credential-journal'
        with self.reader.snapshot() as snapshot:
            self.write(journal / 'state.json', {'generation': 29, 'counter': 100})
            self.write(self.recovery / 'recovery.sqlite3', b'not a database; not interpreted by floor reader')
            snapshot.recheck()
            self.assertEqual(snapshot.report.classification, 'record-consistent')

    def test_pending_marker_is_a_hold_never_a_reconciliation_grant(self):
        self.save(self.fixture())
        self.write(self.namespace / 'recovery-admission-intent.json', b'unknown intent must be preserved')
        with self.reader.snapshot() as snapshot:
            self.assertEqual(snapshot.report.classification, 'held-transition')
            self.assertEqual(snapshot.compare_candidate(minimum={}, current={}).differences, ('history-held',))

    def test_new_anchor_or_pending_marker_invalidates_absence_snapshot(self):
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                self.write(self.recovery / 'bootstrap', b'orphan evidence')
                snapshot.recheck()

    def test_positive_initialization_is_explicit_scoped_and_still_held(self):
        value = self.initializing(self.fixture())
        # No absence-based grant: the explicit record also cannot cross anchors.
        self.save(value)
        self.assertEqual(self.report().reasons, ('initialization-crossed-anchor',))
        (self.namespace / 'credential-journal').rmdir()
        (self.recovery / 'config.json').unlink(); (self.host / 'credential-admission.json').unlink()
        (self.envdir / 'recovery.env').unlink()
        self.assertEqual(self.report().reasons, ('positive-initialization-recorded',))
        value['positiveNeverManaged']['scope'] = 'preserve-existing-auth'; self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_positive_initialization_cannot_invent_completed_receipts(self):
        value = self.initializing(self.fixture())
        value['current']['receipts']['activationSha256'] = 'f' * 64
        self.save(value)
        self.assertEqual(self.report().classification, 'unknown')
        value['current']['receipts']['activationSha256'] = None
        value['positiveNeverManaged'] = None; self.save(value)
        self.assertEqual(self.report().classification, 'unknown')

    def test_reader_never_opens_a_writable_file(self):
        value = self.fixture(); self.save(value)
        real_open = os.open
        def read_only(path, flags, *args, **kwargs):
            self.assertEqual(flags & (os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_RDWR), 0)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(floor.os, 'open', side_effect=read_only):
            with self.reader.snapshot() as snapshot:
                self.assertEqual(snapshot.report.classification, 'record-consistent')

    def test_snapshots_are_not_portable_or_publicly_constructible(self):
        with self.assertRaises(floor.CredentialFloorError): floor.FloorSnapshot(None, None, None, None, [], None, None)
        with self.assertRaises(floor.CredentialFloorError):
            with self.reader.snapshot() as snapshot:
                with mock.patch.object(floor.os, 'getpid', return_value=os.getpid() + 1): snapshot.recheck()


if __name__ == '__main__':
    unittest.main()
