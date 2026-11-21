"""Filesystem custody and mocked HTTPS for the retained launcher path."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import fcntl
import gzip
import io
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlsplit

from orbis_sentinel import credential_floor as floor
from orbis_sentinel import credential_storage as storage
from orbis_sentinel import host_source_publication as publication
from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel import runtime


OPERATION = 'a' * 64
ACTIVATION = 'e' * 32
CORE_COMMIT = '1' * 40
INSTALLER_COMMIT = '2' * 40
IMAGE = 'sha256:' + '3' * 64
COPIED = ('orbis-host-service.py', 'orbis-release-plan.py')
REFUSAL = (publication.SourcePublicationError, OSError)


def write(path, value, mode=0o600):
    body = value if type(value) is bytes else publication.encoded(value)
    path.write_bytes(body)
    path.chmod(mode)
    return body


def record(body, length='bytes'):
    return {length: len(body), 'sha256': publication.sha(body)}


def tar(entries, *, format=tarfile.USTAR_FORMAT):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=format) as archive:
        for name, content in entries:
            entry = name if isinstance(name, tarfile.TarInfo) else tarfile.TarInfo(name)
            entry.mode = 0o600
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return gzip.compress(raw.getvalue(), mtime=0)


def release_manifest(*, full=True):
    result = {'schema': 'orbis.release.v1', 'image': 'ghcr.io/twentylines/orbis', 'tag': 'v0.8.5',
              'commit': CORE_COMMIT, 'digest': IMAGE, 'runtipiCompatibility': '4.10.1',
              'installationProtocol': 'orbis.installation-state.v1'}
    if full:
        result.update(releaseChannel='stable', updatePriority='critical', criticalThrough='v0.8.4',
                      criticalFixes=['v0.8.3', 'v0.8.4'], platforms=['linux/amd64', 'linux/arm64'],
                      dataCompatibility='orbis.data.v1', accountIdentifierCompatibility='orbis.account-identifier.v1',
                      migrationFingerprint='sha256:' + '4' * 64)
    return result


def bundle_files():
    files = {name: b'raise AssertionError("candidate code executed")\n' for name in publication._REQUIRED}
    files['scripts/orbis-release-plan.py'] = b'PINNED = "release"\n'
    files['scripts/orbis-host-service-setup.py'] += f'SCRIPTS = {COPIED!r}\n'.encode()
    files['scripts/install-orbis.py'] += b'EXPECTED_RELEASE = None\nINSTALLER = None\n'
    files['packaging/systemd/orbis-host.service'] = b'[Unit]\nDescription=Fixture Host\n'
    return files


class Response(io.BytesIO):
    def __init__(self, body, url, *, status=200):
        super().__init__(body)
        self.url, self.status = url, status

    def geturl(self):
        return self.url


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='publication-fixture-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.directory(self.base / 'sentinel', 0o755)
        self.state = self.directory(self.base / 'state')
        self.operations = self.directory(self.state / 'source-publication')
        self.host = self.directory(self.base / 'host-source')
        self.unit = self.base / 'orbis-host.service'
        self.environment = self.base / 'host-service.env'
        self.installation_root = self.directory(self.base / 'installation', 0o777)
        self.context = 'local-test'
        self.paths = {'ROOT': self.root, 'STATE': self.state, 'OPERATIONS': self.operations,
                      'HOST_SOURCE': self.host, 'HOST_UNIT': self.unit, 'HOST_ENV': self.environment}
        self.start(mock.patch.multiple(publication, **self.paths))
        self.start(mock.patch.object(sessions, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(publication, '_root'))
        self.running = self.start(mock.patch.object(publication, '_running_from'))
        self.bodies, self.targets, self.requests = {}, {}, []
        self.hook = None
        self.start(mock.patch.object(publication, '_tls'))
        self.opener = self.start(mock.patch.object(publication, 'build_opener', return_value=self))
        self.package, self.activation = self.install_sentinel()
        write(self.state / 'activation.lock', b'')
        self.files = bundle_files()

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def directory(self, path, mode=0o700):
        path.mkdir(mode=mode, parents=True, exist_ok=True)
        path.chmod(mode)
        return path

    def install_sentinel(self):
        package = self.directory(self.root / 'releases' / '0.8.5', 0o755)
        self.directory(package / 'src', 0o755)
        files = {}
        for name, body in {'bin/orbis-sentinel': b'fixture launcher\n',
                           'src/orbis_sentinel/__init__.py': b'__version__ = "0.8.5"\n',
                           'src/orbis_sentinel/runtime.py': b'fixture runtime\n',
                           'src/orbis_sentinel/host_source_publication.py': b'fixture retained verifier\n',
                           'web/empty': b''}.items():
            path = package / name
            self.directory(path.parent, 0o755)
            write(path, body, 0o755 if name.startswith('bin/') else 0o644)
            files[name] = record(body)
        body = write(package / 'release.json', {'format': 1, 'component': 'orbis-sentinel', 'version': '0.8.5',
                                                'python': '>=3.10', 'files': files}, 0o644)
        receipt = {'schema': 'orbis-sentinel.installation.v1', 'version': '0.8.5', 'sha256': '5' * 64,
                   'sourceCommit': '6' * 40, 'files': {**files, 'release.json': record(body)}}
        write(self.state / 'installed.json', receipt)
        activation = {'schema': 'orbis-sentinel.activation.v1', 'id': ACTIVATION, 'phase': 'complete',
                      'candidate': receipt, 'previous': None, 'previousUnits': {}}
        current = write(self.state / 'activation.json', activation)
        write(self.state / f'admission-{ACTIVATION}.json', {**activation, 'phase': 'prepared'})
        (self.root / 'current').symlink_to('releases/0.8.5')
        return package, current

    def open(self, request, timeout):
        locator = request.full_url
        self.requests.append((locator, timeout))
        if self.hook is not None:
            self.hook(locator)
        return Response(self.bodies[locator], self.targets.get(locator, locator))

    def prepare(self, mode='release', schema=3, *, operation=OPERATION, core=None):
        core = release_manifest() if core is None else core
        core_body = publication.encoded(core) + b'\n'
        artifact = tar(sorted(self.files.items()))
        manifest = {'schema': f'orbis.installer-bundle.v{schema}', 'archive': 'orbis-installer.tar.gz',
                    'archiveBytes': len(artifact), 'archiveSha256': publication.sha(artifact),
                    'files': {name: record(body, 'size') for name, body in self.files.items()}}
        identity = {'commit': core['commit'] if mode == 'release' else INSTALLER_COMMIT}
        if mode == 'release':
            identity = {'tag': core['tag'], **identity}
            manifest.update(tag=core['tag'], commit=core['commit'], releaseManifestSha256=publication.sha(core_body))
        else:
            manifest['installerCommit'] = INSTALLER_COMMIT
        manifest_body = publication.encoded(manifest)
        identity['manifestSha256'] = publication.sha(manifest_body)
        plan = {'schema': publication.PLAN, 'operationId': operation, 'mode': mode, 'installer': identity,
                'core': core, 'context': self.context, 'root': str(self.installation_root)}
        directory = self.directory(self.operations / operation)
        self.approve(directory, plan)
        for name in COPIED:
            path = self.host / name
            if not path.exists():
                write(path, self.files['scripts/' + name])
        if not self.unit.exists():
            write(self.unit, self.files['packaging/systemd/orbis-host.service'], 0o644)
        if not self.environment.exists():
            source = self.host / 'orbis-host-service.py'
            write(self.environment, (f'ORBIS_SERVICE_SOURCE="{source}"\nORBIS_ROOT="{self.installation_root}"\n'
                                     f'ORBIS_DOCKER_CONTEXT="{self.context}"\n').encode())
        release = 'https://github.com/twentylines/orbis/releases/download/' + core['tag'] + '/'
        launcher = self.files['scripts/install-orbis.py']
        if mode == 'release':
            base = release
            launcher_url = release + 'install-orbis.py'
            launcher = launcher.replace(b'EXPECTED_RELEASE = None', ('EXPECTED_RELEASE = ' + repr(identity)).encode())
        else:
            base = 'https://twentylines.github.io/orbis/installer/' + INSTALLER_COMMIT + '/'
            launcher_url = ('https://raw.githubusercontent.com/twentylines/orbis/' + INSTALLER_COMMIT
                            + '/scripts/install-orbis.py')
        locators = {'core': release + 'release-manifest.json', 'launcher': launcher_url,
                    'manifest': base + 'orbis-installer-manifest.json', 'archive': base + 'orbis-installer.tar.gz'}
        self.bodies.update({locators[name]: value for name, value in (('core', core_body), ('launcher', launcher),
                           ('manifest', manifest_body), ('archive', artifact))})
        return directory, plan, locators

    def approve(self, directory, plan):
        plan_body = write(directory / 'plan.json', plan)
        write(directory / 'approval.json', {'schema': publication.APPROVAL, 'operationId': plan['operationId'],
            'planSha256': publication.sha(plan_body), 'approvalId': 'd' * 64})

    def installer_copy(self, mode, operation):
        template = self.files['scripts/install-orbis.py']
        if b'INSTALLER_SOURCE_CUSTODY' not in template:
            template += b'INSTALLER_SOURCE_CUSTODY = 1\n'
            self.files['scripts/install-orbis.py'] = template
        _, earlier, locators = self.prepare(mode, 3 if mode == 'release' else 4, operation='b' * 64)
        folder = self.directory(self.base / ('installer-' + operation[:12]))
        copies = self.directory(folder / 'host-copy-custody')
        proofs = {key: self.bodies[url] for key, url in locators.items()}
        if mode == 'modular':
            proofs['launcher'] = template.replace(b'INSTALLER = None',
                ('INSTALLER = ' + repr(earlier['installer'])).encode())
        names = {'core': 'release-manifest.json', 'launcher': 'installer-source-launcher.py',
                 'manifest': 'orbis-installer-manifest.json', 'archive': 'orbis-installer.tar.gz'}
        for key, name in names.items():
            write(folder / name, proofs[key])
        selection = write(folder / 'installer-source-selection.json', {
            'schema': 'orbis.installer-source-selection.v1', 'channel': 'stable',
            'mode': mode, 'installer': earlier['installer'], 'proofs': {
                names[key]: record(value) for key, value in proofs.items()},
        })
        execution = write(folder / 'installer-source-execution.json', {
            'schema': 'orbis.installer-source-execution.v1', 'channel': 'stable',
            'selectionSha256': publication.sha(selection), 'launcherSha256': publication.sha(proofs['launcher']),
        })
        body = publication.encoded({'schema': 'orbis.host-copy-custody.v1', 'root': earlier['root'],
            'context': earlier['context'], 'selection': {'directory': str(folder), 'mode': mode,
                'installer': earlier['installer'], 'coreSha256': publication.sha(proofs['core']),
                'selectionSha256': publication.sha(selection), 'executionSha256': publication.sha(execution)},
            'installed': {'inventory': {name: publication.sha((self.host / name).read_bytes()) for name in COPIED},
                'unitSha256': publication.sha(self.unit.read_bytes()),
                'environmentSha256': publication.sha(self.environment.read_bytes())},
            'bindings': {'fileIdentities': {name: list(publication.seal((self.host / name).stat())) for name in COPIED},
                'sourceDirectory': list(publication.directory_seal(self.host.stat())),
                'unit': list(publication.seal(self.unit.stat())),
                'environment': list(publication.seal(self.environment.stat()))}}) + b'\n'
        digest = publication.sha(body)
        write(copies / f'host-copy-{digest}.json', body)
        return folder, digest, locators

    def test_root_review_stages_exact_copy_before_independent_official_approval(self):
        for mode, operation in (('release', OPERATION), ('modular', 'c' * 64)):
            with self.subTest(mode=mode):
                folder, digest, locators = self.installer_copy(mode, operation)
                directory = self.operations / operation
                result = publication.review_copy(operation, folder, digest)
                self.assertEqual(result, {'schema': publication.PLAN_CUSTODY, 'operationId': operation,
                    'planSha256': publication.sha((directory / 'plan.json').read_bytes()), 'phase': 'review-required'})
                plan = publication._json((directory / 'plan.json').read_bytes())
                self.assertEqual(plan['copyCustodySha256'], digest)
                self.assertEqual(set(os.listdir(directory)), {'plan.json', *publication._CUSTODY_FILES})
                self.assertEqual(publication.review_copy(operation, folder, digest), result)
                before = len(self.requests)
                with self.assertRaises(REFUSAL):
                    publication.verify_operation(operation)
                self.assertEqual(len(self.requests), before)
                self.approve(directory, plan)
                with publication.verify_operation(operation) as evidence:
                    receipt = evidence.observation
                    digest_at_issue = evidence.receipt_sha256
                    self.assertEqual(receipt['schema'], publication.SCHEMA_CUSTODY)
                    self.assertEqual(receipt['copyCustodySha256'], digest)
                    with self.assertRaises(publication.SourcePublicationError):
                        evidence.require_managed_admission()
                self.assertEqual([request[0] for request in self.requests[before:]], list(locators.values()))
                folder.rename(folder.with_name(folder.name + '-retired'))
                with publication.verify_operation(operation) as evidence:
                    self.assertEqual(evidence.receipt_sha256, digest_at_issue)
                self.assertEqual(len(self.requests), before + 4)
                retained = directory / 'installer-source-execution.json'
                write(retained, retained.read_bytes() + b' ')
                with self.assertRaises(REFUSAL):
                    publication.verify_operation(operation)
                self.assertEqual(len(self.requests), before + 4)

    def test_review_refuses_crossed_installed_unit_and_selected_launcher_without_plan(self):
        folder, digest, _ = self.installer_copy('modular', OPERATION)
        launcher = folder / 'installer-source-launcher.py'
        original = launcher.read_bytes()
        write(launcher, original + b'\n# drift')
        with self.assertRaises(REFUSAL):
            publication.review_copy(OPERATION, folder, digest)
        write(launcher, original)
        replacement_unit = self.base / 'same-unit'
        write(replacement_unit, self.unit.read_bytes(), 0o644)
        replacement_unit.replace(self.unit)
        with self.assertRaises(REFUSAL):
            publication.review_copy(OPERATION, folder, digest)
        self.assertFalse((self.operations / OPERATION).exists())
        self.assertEqual(self.requests, [])

    def test_review_runtime_requires_both_inputs_and_does_not_initialize_services(self):
        folder, digest, _ = self.installer_copy('release', OPERATION)
        with (mock.patch.object(runtime, 'TelemetryCollector', side_effect=AssertionError),
              mock.patch.object(sessions, 'RecoverySessions', side_effect=AssertionError),
              redirect_stdout(io.StringIO()) as stdout):
            self.assertEqual(runtime.main(['--review-host-source', OPERATION, '--installer-selection', str(folder),
                                           '--host-copy-sha256', digest]), 0)
        self.assertEqual(publication._json(stdout.getvalue().encode())['phase'], 'review-required')
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runtime.main(['--review-host-source', OPERATION, '--host-copy-sha256', digest])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            runtime.main(['--verify-host-source', OPERATION, '--host-copy-sha256', digest])

    def test_first_review_creates_protected_operation_and_resumes_before_plan_commit(self):
        folder, digest, _ = self.installer_copy('release', OPERATION)
        self.operations.rename(self.state / 'earlier-operations')
        real_write = publication._write_exact

        def interrupted(pins, directory, name, body):
            if name == 'installer-source-execution.json':
                raise OSError('fixture interrupted before plan')
            return real_write(pins, directory, name, body)

        with mock.patch.object(publication, '_write_exact', side_effect=interrupted), self.assertRaises(OSError):
            publication.review_copy(OPERATION, folder, digest)
        operation = self.operations / OPERATION
        self.assertEqual(set(os.listdir(operation)), {'copy-custody.json', 'installer-source-selection.json'})
        with self.assertRaises(REFUSAL):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])
        result = publication.review_copy(OPERATION, folder, digest)
        self.assertEqual(result['planSha256'], publication.sha((operation / 'plan.json').read_bytes()))
        self.assertFalse((operation / 'approval.json').exists())

    def test_bootstrap_reader_requires_exact_b_receipt_and_visible_main_and_host_binding(self):
        folder, digest, _ = self.installer_copy('release', OPERATION)
        publication.review_copy(OPERATION, folder, digest)
        directory = self.operations / OPERATION
        self.approve(directory, publication._json((directory / 'plan.json').read_bytes()))
        with publication.verify_operation(OPERATION) as issued:
            observation = issued.observation
            exact_receipt = issued.receipt_sha256
        core, copied = observation['associatedCore'], observation['copy']
        current = {'main': {'publicationSha256': publication.sha(publication.encoded({
            name: core[name] for name in publication._CORE_REQUIRED}))},
            'host': {name: copied[name] for name in ('inventorySha256', 'unitSha256', 'environmentSha256')}}
        arguments = {'root': self.installation_root, 'context': self.context, 'current': current,
                     'root_identity': publication.directory_seal(self.installation_root.stat()),
                     'receipt_sha256': exact_receipt}
        with publication.read_completed_for_bootstrap_review(OPERATION, **arguments) as evidence:
            self.assertEqual(evidence.receipt_sha256, exact_receipt)
            with self.assertRaises(REFUSAL):
                evidence.require_managed_admission()
        self.assertEqual(len(self.requests), 4)
        bad_options = ({'receipt_sha256': 'f' * 64}, {'context': 'other-context'}, {'root_identity': (1,)},
                       {'current': {**current, 'main': {'publicationSha256': 'f' * 64}}},
                       {'current': {**current, 'host': {**current['host'], 'unitSha256': 'f' * 64}}})
        for changes in bad_options:
            with self.subTest(changes=tuple(changes)), self.assertRaises(REFUSAL):
                publication.read_completed_for_bootstrap_review(OPERATION, **{**arguments, **changes})
        with publication.verify_operation('b' * 64) as legacy:
            old_hash = legacy.receipt_sha256
        with self.assertRaises(REFUSAL):
            publication.read_completed_for_bootstrap_review('b' * 64, **{**arguments, 'receipt_sha256': old_hash})

        name = self.host / COPIED[0]
        replacement = self.base / 'same-bytes-copy'
        write(replacement, name.read_bytes())
        replacement.replace(name)
        with self.assertRaises(REFUSAL):
            publication.read_completed_for_bootstrap_review(OPERATION, **arguments)

    def floor_reader(self, observation, *, changes=None, retained=False):
        state = self.directory(self.base / 'floor-state')
        root = self.installation_root
        namespace = self.directory(state / 'installations' / publication.sha(os.fsencode(str(root))))
        journal = self.directory(namespace / 'credential-journal')
        recovery = self.directory(self.base / 'recovery')
        host_state = self.directory(self.base / 'host-state')
        environment = self.base / 'recovery.env'
        unit = self.base / 'orbis-sentinel-recovery.service'
        unit_sha256 = publication.sha(write(unit, b'[Service]\nProtectHome=yes\n', 0o644))
        for key, value in {'STATE_ROOT': state, 'RECOVERY_ROOT': recovery, 'RECOVERY_ENV': environment, 'RECOVERY_UNIT': unit}.items():
            self.start(mock.patch.object(floor, key, value))
        reader = floor.CredentialFloorReader(root, self.context, 'fixture-daemon', host_state_directory=host_state)
        installation_id = publication.sha(publication.encoded({'root': str(root), 'context': self.context,
            'daemon': reader.daemon_id, 'rootIdentity': publication.directory_seal(root.stat())}))
        origin = 'https://recovery.example'
        config = {'schema': 'orbis.sentinel-recovery-config.v1', 'directory': str(recovery), 'origin': origin,
                  'imageId': IMAGE, 'listenPort': 9443, 'statusSocket': '/run/orbis-sentinel/api.sock'}
        config_path = recovery / 'config.json'
        config_hash = publication.sha(write(config_path, config))
        admission = {'schema': 'orbis.host.credential-admission.v1', 'root': str(root), 'context': self.context,
                     'installationId': installation_id, 'mode': 'managed', 'origin': origin, 'writerProtocol': 1,
                     'recoveryEpoch': '7' * 64, 'runtimeDirectory': str(self.base / 'retained-recovery-runtime'),
                     'runtimeFiles': dict.fromkeys(('__init__.py', 'writer_broker.py', 'writer_control.py',
                         'writer_journal.py', 'recovery_sessions.py', 'recovery_config.py'), '8' * 64),
                     'recoveryConfig': str(config_path), 'recoveryConfigSha256': config_hash,
                     'journalDirectory': str(journal)}
        configuration = {'recoveryConfigSha256': config_hash,
                         'hostAdmissionSha256': publication.sha(write(host_state / 'credential-admission.json', admission)),
                         'recoveryEnvironmentSha256': publication.sha(write(environment, b'FIXTURE=1\n'))}

        def storage(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                return {'identity': list(publication.directory_seal(os.fstat(fd))), 'mountId': publication.mount_id(fd)}
            finally:
                os.close(fd)

        copied = observation['copy']
        core = observation['associatedCore']
        installed_publication = {'schema': 'orbis.release.v1', 'image': 'ghcr.io/twentylines/orbis',
                                 'tag': core['tag'], 'commit': core['commit'], 'digest': core['digest'],
                                 'runtipiCompatibility': '4.10.1'}
        if retained:
            installed_publication.update(runtipiCompatibility=core['runtipiCompatibility'],
                                         installationProtocol=core['installationProtocol'])
        current = {'main': {'imageId': IMAGE, 'creationSha256': '1' * 64,
                            'publicationSha256': publication.sha(publication.encoded(installed_publication))},
                   'host': {key: copied[key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')},
                   'sentinel': {'version': '0.8.5', **dict.fromkeys(
                       ('inventorySha256', 'runtimeSha256', 'unitSha256', 'environmentSha256'), '2' * 64)},
                   'authWorker': {'imageId': IMAGE, 'anchorSha256': '3' * 64, 'capabilitiesSha256': '4' * 64},
                   'sourceExporter': {'imageId': IMAGE, 'programSha256': '5' * 64, 'capabilitiesSha256': '6' * 64},
                   'recoveryOrigin': origin, 'configuration': configuration,
                   'storage': {'namespace': storage(namespace), 'journal': storage(journal), 'recovery': storage(recovery),
                               'journalSchema': 'orbis.sentinel-writer-journal.v1'},
                   'receipts': dict.fromkeys(('bootstrapSha256', 'sourceSha256', 'activationSha256'), '7' * 64)}
        current['sentinel']['unitSha256'] = unit_sha256
        if changes:
            group, key = changes
            current[group][key] = '0' * 64
        history = {'schema': floor.LEGACY_SCHEMA, 'installationId': installation_id, 'generation': 1, 'managedEver': True,
                   'mode': 'managed', 'configSha256': configuration['hostAdmissionSha256'], 'planSha256': 'a' * 64,
                   'sentinelVersion': '0.8.5', 'writerProtocol': 1, 'previousSha256': None, 'current': current,
                   'minimum': {name: {'family': family, 'version': version}
                               for name, (family, version) in floor.CONTRACTS.items()}, 'positiveNeverManaged': None}
        write(namespace / floor.HISTORY, history)
        return reader


    def portable_storage(self, directory):
        observed = os.fstat(directory.fd)
        return {'path': str(directory.path), 'filesystem': 'ext4', 'uuid': 'a' * 32,
                'handle': f'{observed.st_ino:016x}', 'owner': [observed.st_uid, observed.st_gid, observed.st_mode],
                'filesystemPath': str(directory.path), 'mountPoint': '/', 'mountRoot': '/'}

    def test_v3_proposal_uses_real_offline_publisher_floor_join_and_exact_previous_bytes(self):
        directory, _, _ = self.prepare()
        with publication.verify_operation(OPERATION) as evidence:
            reader = self.floor_reader(evidence.observation)
            publisher_receipt = evidence.receipt_sha256
        self.requests.clear()
        with mock.patch.object(storage, 'observe', side_effect=self.portable_storage):
            with reader.snapshot() as snapshot:
                with floor.prepare_storage_upgrade(snapshot, publication_operation=OPERATION) as upgrade:
                    bridge, plan, successor = map(publication._json, (upgrade.bridge, upgrade.plan, upgrade.history))
                    self.assertEqual(bridge['publicationSha256'], publisher_receipt)
                    self.assertEqual(plan['publisherReceiptSha256'], publisher_receipt)
                    self.assertEqual(plan['bridgeSha256'], publication.sha(upgrade.bridge))
                    self.assertEqual(successor['schema'], floor.SCHEMA)
                    self.assertEqual(successor['planSha256'], publication.sha(upgrade.plan))
                    self.assertEqual(successor['previousSha256'], publication.sha(upgrade.predecessor))
                    self.assertEqual(successor['installationId'], snapshot._value['installationId'])
                    self.assertEqual(successor['minimum']['reader']['version'], 3)
                    self.assertEqual(set(bridge['roles']), set(storage.ROLES))
                    self.assertNotIn(b'mountId', upgrade.bridge)
                    self.assertFalse((snapshot._directories['namespace'].path / storage.BRIDGE_DIRECTORY).exists())
                    self.assertFalse(hasattr(upgrade, 'allowed'))
        self.assertEqual(self.requests, [])
        write(directory / 'proof-launcher.bin', b'different publisher bytes')
        with mock.patch.object(storage, 'observe', side_effect=self.portable_storage):
            with reader.snapshot() as snapshot:
                with self.assertRaises(REFUSAL):
                    with floor.prepare_storage_upgrade(snapshot, publication_operation=OPERATION):
                        self.fail('tampered receipt cannot mint a bridge')

    def test_publisher_bound_storage_proposal_changes_only_reviewed_restart_creation_binding(self):
        self.prepare()
        with publication.verify_operation(OPERATION) as evidence:
            reader=self.floor_reader(evidence.observation)
        with mock.patch.object(storage,'observe',side_effect=self.portable_storage), reader.snapshot() as snapshot:
            prior=snapshot._value['current']['main']
            transition={'fromPolicy':'unless-stopped','toPolicy':'no',
                        'beforeSha256':prior['creationSha256'],'afterSha256':'d'*64}
            with floor.prepare_storage_upgrade(snapshot,publication_operation=OPERATION,creation_transition=transition) as packet:
                self.assertEqual(floor.decode(packet.predecessor)['current']['main'],prior)
                self.assertEqual(floor.decode(packet.plan)['mainCreationTransition'],transition)
                self.assertEqual(floor.decode(packet.history)['current']['main'],{**prior,'creationSha256':'d'*64})
            wrong={**transition,'beforeSha256':'0'*64}
            with self.assertRaises(floor.CredentialFloorError):
                with floor.prepare_storage_upgrade(snapshot,publication_operation=OPERATION,creation_transition=wrong):
                    self.fail('crossed immutable creation evidence cannot issue')

    def test_exact_transition_verifier_rechecks_real_issuer_before_after_and_on_resume(self):
        directory, _, _ = self.prepare()
        with publication.verify_operation(OPERATION) as evidence:
            reader = self.floor_reader(evidence.observation)
        with mock.patch.object(storage, 'observe', side_effect=self.portable_storage):
            with reader.snapshot() as snapshot:
                path = snapshot._directories['namespace'].path
                with floor.prepare_storage_upgrade(snapshot, publication_operation=OPERATION) as upgrade:
                    pass
            with reader.verify_storage_upgrade(upgrade, publication_operation=OPERATION) as recheck:
                archive = self.directory(path / floor.ARCHIVE)
                bridge = self.directory(path / storage.BRIDGE_DIRECTORY)
                write(archive / (publication.sha(upgrade.predecessor) + '.json'), upgrade.predecessor)
                write(bridge / (publication.sha(upgrade.bridge) + '.json'), upgrade.bridge)
                recheck()
                write(path / floor.HISTORY, upgrade.history)
                recheck()
            with reader.verify_storage_upgrade(upgrade, publication_operation=OPERATION) as recheck:
                recheck()
            with reader.snapshot() as snapshot:
                self.assertEqual(snapshot.report.classification, 'record-consistent')
                self.assertEqual(snapshot.report.history_sha256, publication.sha(upgrade.history))
                self.assertEqual(snapshot.report.generation, 2)
            bridge_path = bridge / (publication.sha(upgrade.bridge) + '.json')
            write(bridge_path, b'changed persisted bridge')
            with self.assertRaises(floor.CredentialFloorError):
                with reader.verify_storage_upgrade(upgrade, publication_operation=OPERATION):
                    self.fail('published history requires the actual exact bridge')
            write(bridge_path, upgrade.bridge)
            write(directory / 'proof-launcher.bin', b'changed exact issuer proof')
            with self.assertRaises(REFUSAL):
                with reader.verify_storage_upgrade(upgrade, publication_operation=OPERATION):
                    self.fail('changed publisher proof cannot resume migration')

    def test_v3_proposal_rejects_reobserved_v2_in_a_different_namespace(self):
        self.prepare()
        with publication.verify_operation(OPERATION) as evidence:
            reader = self.floor_reader(evidence.observation)
        with mock.patch.object(floor, 'mount_id', return_value=224466):
            with reader.snapshot() as snapshot:
                self.assertEqual(snapshot.report.classification, 'unknown')
                with self.assertRaises(floor.CredentialFloorError):
                    with floor.prepare_storage_upgrade(snapshot, publication_operation=OPERATION):
                        self.fail('unproven legacy mounts cannot be rebound')

    def test_release_and_modular_profiles_use_fixed_origins_and_distinct_identities(self):
        for index, (mode, schema) in enumerate((('release', 1), ('release', 3), ('modular', 2), ('modular', 4))):
            with self.subTest(mode=mode, schema=schema):
                operation = str(index) * 64
                directory, plan, locators = self.prepare(mode, schema, operation=operation,
                    core=release_manifest(full=schema in (3, 4)))
                self.targets[locators['core']] = (publication.CDN +
                    '/github-production-release-asset-2e65/213/abcd-1234?fixture=unrecorded')
                self.requests.clear()
                with publication.verify_operation(operation) as evidence:
                    receipt = evidence.observation
                    self.assertEqual(evidence.receipt_sha256, publication.sha((directory / 'receipt.json').read_bytes()))
                    self.assertEqual(receipt['associatedCore'], plan['core'])
                    self.assertEqual(receipt['manifest']['schema'], f'orbis.installer-bundle.v{schema}')
                    self.assertEqual(receipt['installer']['commit'], CORE_COMMIT if mode == 'release' else INSTALLER_COMMIT)
                    self.assertEqual(receipt['launcherKind'], 'release-launcher' if mode == 'release' else 'committed-template')
                    self.assertEqual(receipt['proofs']['core']['origin'], publication.CDN)
                    self.assertEqual(set(receipt['copy']['inventory']), set(COPIED))
                    self.assertEqual(self.requests, [(locator, 15) for locator in locators.values()])
                    self.assertNotIn(b'unrecorded', (directory / 'receipt.json').read_bytes())
                    with self.assertRaises(publication.SourcePublicationError):
                        evidence.require_managed_admission()
                self.running.assert_called_with(self.package)

    def test_crossed_release_identity_and_changed_approval_stop_before_transport(self):
        directory, plan, _ = self.prepare()
        invalid = copy.deepcopy(plan)
        invalid['installer']['commit'] = INSTALLER_COMMIT
        self.approve(directory, invalid)
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        write(directory / 'plan.json', plan)
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])
        self.assertFalse((directory / 'intent.json').exists())

    def test_modular_template_must_match_the_official_bundle_and_be_unrendered(self):
        directory, _, locators = self.prepare('modular', 4)
        self.bodies[locators['launcher']] += b'# unrelated official-template fixture\n'
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertFalse((directory / 'complete.json').exists())

    def test_release_literal_alone_and_duplicate_publication_fields_cannot_issue(self):
        directory, _, locators = self.prepare()
        original = self.bodies[locators['launcher']]
        self.bodies[locators['launcher']] += b'# unrelated release launcher fixture\n'
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.bodies[locators['launcher']] = original
        self.bodies[locators['core']] = self.bodies[locators['core']].replace(b'{', b'{"tag":"v0.8.5",', 1)
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertFalse((directory / 'complete.json').exists())

    def test_same_bytes_from_a_different_project_or_insecure_redirect_cannot_issue(self):
        directory, _, locators = self.prepare()
        for target in ('http://github.com/twentylines/orbis/releases/download/v0.8.5/release-manifest.json',
                       'https://github.com/other/orbis/releases/download/v0.8.5/release-manifest.json',
                       'https://github.com/twentylines/orbis/releases/download/v0.8.6/release-manifest.json',
                       'https://release-assets.githubusercontent.com/unrelated/path',
                       'https://github.com@other.invalid/twentylines/orbis/release-manifest.json',
                       'https://github.com:443/twentylines/orbis/releases/download/v0.8.5/release-manifest.json'):
            with self.subTest(target=target):
                self.targets[locators['core']] = target
                with self.assertRaises(publication.SourcePublicationError):
                    publication.verify_operation(OPERATION)
                self.assertFalse((directory / 'complete.json').exists())

    def test_copy_replacement_during_transport_and_between_attempts_refuses(self):
        directory, _, _ = self.prepare()
        original = self.host / COPIED[0]

        def replace(_):
            self.hook = None
            candidate = self.host.parent / 'replacement'
            write(candidate, original.read_bytes())
            candidate.replace(original)

        self.hook = replace
        with self.assertRaises(REFUSAL):
            publication.verify_operation(OPERATION)
        self.assertTrue((directory / 'intent.json').is_file())
        self.assertFalse((directory / 'complete.json').exists())
        self.requests.clear()
        with self.assertRaises(REFUSAL):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])

    def test_root_unit_and_selector_changes_invalidate_held_evidence(self):
        for index, mutation in enumerate(('installation-root', 'unit', 'selector')):
            with self.subTest(mutation=mutation):
                operation = str(index) * 64
                self.prepare(operation=operation)
                path = {'installation-root': self.installation_root, 'unit': self.unit, 'selector': self.root / 'current'}[mutation]
                backup = self.base / 'moved'
                with publication.verify_operation(operation) as evidence:
                    path.rename(backup)
                    try:
                        if mutation == 'installation-root':
                            self.directory(path, 0o777)
                        elif mutation == 'unit':
                            write(path, backup.read_bytes(), 0o644)
                        else:
                            path.symlink_to('releases/0.8.5')
                        with self.assertRaises(REFUSAL):
                            evidence.recheck()
                    finally:
                        if mutation == 'installation-root':
                            path.rmdir()
                        else:
                            path.unlink()
                        backup.rename(path)

    def test_unsafe_copy_paths_modes_and_package_extras_hold_before_network(self):
        directory, _, _ = self.prepare()
        path = self.host / COPIED[0]
        saved = self.base / 'saved'
        path.rename(saved)
        for form in ('symlink', 'hardlink', 'wrong-mode'):
            with self.subTest(form=form):
                if form == 'symlink':
                    path.symlink_to(saved)
                elif form == 'hardlink':
                    os.link(saved, path)
                else:
                    write(path, saved.read_bytes(), 0o644)
                try:
                    with self.assertRaises(REFUSAL):
                        publication.verify_operation(OPERATION)
                    self.assertEqual(self.requests, [])
                    self.assertFalse((directory / 'intent.json').exists())
                finally:
                    path.unlink()
        saved.rename(path)
        self.directory(self.package / 'src' / 'unlisted')
        with self.assertRaises(REFUSAL):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])

    def test_first_issuer_requires_complete_retained_package_activation_and_exact_bin(self):
        directory, _, _ = self.prepare()
        activation = self.state / 'activation.json'
        write(activation, {**publication._json(self.activation), 'phase': 'prepared'})
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        write(activation, self.activation)
        launcher = self.package / 'bin/orbis-sentinel'
        write(launcher, b'tampered retained binary fixture', 0o755)
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])
        self.assertFalse((directory / 'intent.json').exists())

    def test_partial_archive_write_retries_exact_intent_and_retains_finished_proofs(self):
        directory, _, _ = self.prepare()
        write_exact, os_write = publication._write_exact, os.write

        def interrupt(pins, operation, name, body):
            if name != 'proof-archive.bin':
                return write_exact(pins, operation, name, body)
            calls = iter((True, False))

            def write_prefix(fd, data):
                if next(calls):
                    return os_write(fd, data[:19])
                raise OSError('fixture interrupted mid-write')

            with mock.patch.object(publication.os, 'write', side_effect=write_prefix):
                return write_exact(pins, operation, name, body)

        with mock.patch.object(publication, '_write_exact', side_effect=interrupt):
            with self.assertRaises(OSError):
                publication.verify_operation(OPERATION)
        pending, = directory.glob('.proof-archive.bin.*.pending')
        self.assertEqual(pending.stat().st_size, 19)
        self.assertFalse((directory / 'complete.json').exists())
        proof = directory / 'proof-core.bin'
        inode = proof.stat().st_ino
        with publication.verify_operation(OPERATION) as result:
            digest = result.receipt_sha256
        self.assertFalse(pending.exists())
        self.assertEqual(proof.stat().st_ino, inode)
        self.requests.clear()
        with publication.verify_operation(OPERATION) as retried:
            self.assertEqual(retried.receipt_sha256, digest)
        self.assertEqual(self.requests, [])

    def test_partial_unknown_bytes_and_crossed_retry_preserve_intent(self):
        directory, plan, _ = self.prepare()
        write_exact = publication._write_exact

        def interrupt(pins, operation, name, body):
            if name == 'complete.json':
                pending = directory / f'.complete.json.{publication.sha(body)}.pending'
                write(pending, b'foreign bytes')
                raise OSError('fixture interrupted before completion')
            return write_exact(pins, operation, name, body)

        with mock.patch.object(publication, '_write_exact', side_effect=interrupt):
            with self.assertRaises(OSError):
                publication.verify_operation(OPERATION)
        with self.assertRaises(REFUSAL):
            publication.read_completed(OPERATION, floor_snapshot=object())
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        pending, = directory.glob('.complete.json.*.pending')
        self.assertEqual(pending.read_bytes(), b'foreign bytes')
        self.assertTrue((directory / 'receipt.json').is_file())
        self.assertFalse((directory / 'complete.json').exists())
        crossed = copy.deepcopy(plan)
        crossed['core']['digest'] = 'sha256:' + 'f' * 64
        self.approve(directory, crossed)
        self.requests.clear()
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertEqual(self.requests, [])

    def test_partial_intent_name_binds_copy_before_the_first_byte(self):
        directory, _, _ = self.prepare()
        with mock.patch.object(publication.os, 'write', side_effect=OSError('fixture interrupted before intent bytes')):
            with self.assertRaises(OSError):
                publication.verify_operation(OPERATION)
        pending, = directory.glob('.intent.json.*.pending')
        self.assertEqual(pending.read_bytes(), b'')
        self.assertFalse((directory / 'intent.json').exists())
        original = self.host / COPIED[0]
        candidate = self.base / 'replacement'
        write(candidate, original.read_bytes())
        candidate.replace(original)
        with self.assertRaises(publication.SourcePublicationError):
            publication.verify_operation(OPERATION)
        self.assertEqual(tuple(directory.glob('.intent.json.*.pending')), (pending,))
        self.assertFalse((directory / 'intent.json').exists())
        self.assertEqual(self.requests, [])

    def test_offline_real_floor_holds_original_archived_lineage_across_selector_and_namespace_changes(self):
        self.prepare('modular', 4)
        with publication.verify_operation(OPERATION) as issued:
            observation, digest = issued.observation, issued.receipt_sha256
        reader = self.floor_reader(observation)
        write(self.state / f'result-{ACTIVATION}.json', self.activation)
        write(self.state / 'activation.json', b'incompatible current activation')
        (self.state / 'installed.json').unlink()
        (self.root / 'current').unlink()
        self.requests.clear()
        self.running.reset_mock()
        with reader.snapshot() as snapshot, mock.patch.object(publication, 'mount_id', return_value=73):
            self.assertEqual(snapshot.report.classification, 'record-consistent')
            evidence = publication.read_completed(OPERATION, floor_snapshot=snapshot)
            try:
                self.assertEqual(evidence.receipt_sha256, digest)
                self.assertEqual(evidence.observation['producer']['activationId'], ACTIVATION)
                self.assertEqual(self.requests, [])
                self.running.assert_not_called()
            except BaseException:
                evidence.close()
                raise
        try:
            with self.assertRaises(ValueError):
                evidence.recheck()
        finally:
            evidence.close()

    def test_offline_refuses_an_original_archive_with_changed_activation_or_payload(self):
        self.prepare()
        with publication.verify_operation(OPERATION) as issued:
            reader = self.floor_reader(issued.observation)
        result = self.state / f'result-{ACTIVATION}.json'
        write(result, self.activation + b'\n')
        with reader.snapshot() as snapshot:
            with self.assertRaises(publication.SourcePublicationError):
                publication.read_completed(OPERATION, floor_snapshot=snapshot)
            write(result, self.activation)
            write(self.package / 'bin/orbis-sentinel', b'changed original payload', 0o755)
            with self.assertRaises(publication.SourcePublicationError):
                publication.read_completed(OPERATION, floor_snapshot=snapshot)

    def test_offline_refuses_floor_host_and_core_mismatch_and_opaque_forgery(self):
        self.prepare()
        with publication.verify_operation(OPERATION) as issued:
            observation = issued.observation
        for changes in (('host', 'inventorySha256'), ('host', 'unitSha256'),
                        ('host', 'environmentSha256'), ('main', 'publicationSha256')):
            with self.subTest(changes=changes):
                reader = self.floor_reader(observation, changes=changes)
                with reader.snapshot() as snapshot:
                    self.assertEqual(snapshot.report.classification, 'record-consistent')
                    with self.assertRaises(publication.SourcePublicationError):
                        publication.read_completed(OPERATION, floor_snapshot=snapshot)
        with self.assertRaises(publication.SourcePublicationError):
            publication.read_completed(OPERATION, floor_snapshot=SimpleNamespace(report=SimpleNamespace()))
        with self.assertRaises(publication.SourcePublicationError):
            publication.PublishedSourceEvidence(object(), None, observation, 'f' * 64)

    def test_offline_binds_existing_ordinary_and_retained_host_publication_projections(self):
        self.prepare(core={**release_manifest(), 'runtipiCompatibility': 'v4.10.1'})
        with publication.verify_operation(OPERATION) as issued:
            observation, digest = issued.observation, issued.receipt_sha256
        for retained in (False, True):
            with self.subTest(retained=retained):
                reader = self.floor_reader(observation, retained=retained)
                with reader.snapshot() as snapshot:
                    with publication.read_completed(OPERATION, floor_snapshot=snapshot) as evidence:
                        self.assertEqual(evidence.receipt_sha256, digest)

    def test_offline_requires_original_intent_and_proof_bytes_even_with_current_lineage(self):
        directory, _, _ = self.prepare()
        with publication.verify_operation(OPERATION) as issued:
            reader = self.floor_reader(issued.observation)
        with reader.snapshot() as snapshot:
            for name in ('intent.json', 'proof-launcher.bin', 'proof-archive.bin'):
                with self.subTest(name=name):
                    path = directory / name
                    original = path.read_bytes()
                    write(path, original[:-1] + b'!')
                    try:
                        with self.assertRaises(REFUSAL):
                            publication.read_completed(OPERATION, floor_snapshot=snapshot)
                    finally:
                        write(path, original)
            with publication.read_completed(OPERATION, floor_snapshot=snapshot) as evidence:
                evidence.recheck()
                original_mount = publication.mount_id
                host_inode = (self.host / COPIED[0]).stat().st_ino

                def bind_mount(fd):
                    return 900 if os.fstat(fd).st_ino == host_inode else original_mount(fd)

                with mock.patch.object(publication, 'mount_id', side_effect=bind_mount):
                    with self.assertRaises(publication.SourcePublicationError):
                        evidence.recheck()

    def test_evidence_failed_context_entry_closes_owned_file_descriptors(self):
        self.prepare()
        evidence = publication.verify_operation(OPERATION)
        self.addCleanup(evidence.close)
        fd = evidence._pins.files[self.host / COPIED[0]][0]
        candidate = self.base / 'replacement'
        write(candidate, (self.host / COPIED[0]).read_bytes())
        candidate.replace(self.host / COPIED[0])
        with self.assertRaises(REFUSAL):
            with evidence:
                self.fail('changed evidence entered successfully')
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_active_package_and_same_operation_locks_hold_before_transport(self):
        directory, _, _ = self.prepare()
        for path, flags in ((self.state / 'activation.lock', os.O_RDONLY), (directory, os.O_RDONLY | os.O_DIRECTORY)):
            with self.subTest(path=path.name):
                fd = os.open(path, flags)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(BlockingIOError):
                        publication.verify_operation(OPERATION)
                finally:
                    os.close(fd)
        self.assertEqual(self.requests, [])

    def test_runtime_issuer_dispatch_uses_no_status_recovery_or_network_configuration_owner(self):
        self.prepare()
        with mock.patch.object(runtime, 'TelemetryCollector', side_effect=AssertionError), \
                mock.patch.object(runtime, 'ObserverCollector', side_effect=AssertionError), \
                mock.patch.object(runtime, 'SentinelServer', side_effect=AssertionError), \
                mock.patch.object(floor.RecoveryConfig, '__init__', side_effect=AssertionError), \
                mock.patch.object(floor.RecoveryConfig, '_validate', side_effect=AssertionError), \
                mock.patch.object(sessions, 'RecoverySessions', side_effect=AssertionError), \
                redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(runtime.main(['--verify-host-source', OPERATION]), 0)
        self.assertEqual(publication._json(stdout.getvalue().encode())['operationId'], OPERATION)
        requests = len(self.requests)
        for arguments in (['--systemd-socket'], ['--socket', '/unavailable'], ['--recovery-profile', '/unused'],
                          ['--disk-path', '/'], ['--observer-socket', '/unused'], ['--observer-socket', ''],
                          ['--status'], ['--origin', 'https://ignored.invalid']):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                runtime.main(['--verify-host-source', OPERATION, *arguments])
            self.assertEqual(error.exception.code, 2)
        with redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(runtime.main(['--verify-host-source', '../not-an-operation']), 1)
        self.assertNotIn('not-an-operation', stderr.getvalue())
        self.assertEqual(len(self.requests), requests)


class FormatTests(unittest.TestCase):
    def test_qualified_invocation_requires_exact_retained_bin_isolated_import_and_no_bytecode(self):
        base = Path('/opt/orbis-sentinel/releases/0.8.5')
        valid = SimpleNamespace(argv=[str(base / 'bin/orbis-sentinel')], flags=SimpleNamespace(isolated=1),
                                dont_write_bytecode=True, pycache_prefix=None)
        source = str(base / 'src/orbis_sentinel/host_source_publication.py')
        with mock.patch.multiple(publication, sys=valid, __file__=source):
            publication._running_from(base)
        for invalid in (dict(argv=['/opt/orbis-sentinel/current/bin/orbis-sentinel']),
                        dict(flags=SimpleNamespace(isolated=0)), dict(pycache_prefix='/unused'),
                        dict(dont_write_bytecode=False)):
            configured = SimpleNamespace(**{**vars(valid), **invalid})
            with self.subTest(invalid=invalid), mock.patch.multiple(publication, sys=configured, __file__=source), \
                    self.assertRaises(publication.SourcePublicationError):
                publication._running_from(base)

    def test_redirects_validate_before_following_and_bound_hops(self):
        route = publication.RELEASES + 'v0.8.5/install-orbis.py'
        redirect = publication._Redirects(route)
        request = publication.Request(route)
        asset = publication.CDN + '/github-production-release-asset-2e65/123/abcd-ef?fixture=discard'
        for _ in range(4):
            self.assertEqual(redirect.redirect_request(request, None, 302, 'fixture', {}, asset).full_url, asset)
        with self.assertRaises(publication.SourcePublicationError):
            redirect.redirect_request(request, None, 302, 'fixture', {}, asset)
        for locator in (publication.SITE + 'installer/' + INSTALLER_COMMIT + '/orbis-installer.tar.gz',
                        publication.RAW + INSTALLER_COMMIT + '/scripts/install-orbis.py'):
            with self.subTest(locator=locator), self.assertRaises(publication.SourcePublicationError):
                publication._Redirects(locator).redirect_request(publication.Request(locator), None, 302, 'fixture', {}, asset)

    def test_http_response_bound_and_proxy_config(self):
        target = publication.RELEASES + 'v0.8.5/install-orbis.py'
        for status, body in ((200, b'12345'), (206, b'1234'), (200, b'')):
            opener = mock.Mock()
            opener.open.return_value = Response(body, target, status=status)
            with mock.patch.object(publication, '_tls'), mock.patch.object(publication, 'build_opener',
                    return_value=opener) as build, self.assertRaises(publication.SourcePublicationError):
                publication._fetch(target, 4)
            self.assertEqual(build.call_args.args[0].proxies, {})
        with mock.patch.object(publication, 'build_opener') as build:
            for locator in (target + '?unexpected=1', target.replace('/twentylines/', '/different/'),
                            target.replace('/install-orbis.py', '/unrecognized')):
                with self.subTest(locator=locator), self.assertRaises(publication.SourcePublicationError):
                    publication._fetch(locator, 4)
            build.assert_not_called()

    def test_manifest_profiles_are_strict_and_release_channel_follows_published_tag(self):
        core = release_manifest()
        publication._core(core)
        publication._core(release_manifest(full=False))
        nightly = {**core, 'tag': 'v0.8.5-rc.1', 'releaseChannel': 'nightly'}
        publication._core(nightly)
        for changes in ({'unknown': 'metadata'}, {'migrationFingerprint': '4' * 64}, {'runtipiCompatibility': '4.11.0'},
                        {'tag': 'v0.8.5-experimental'}, {'tag': 'v0.08.5'}, {'releaseChannel': 'nightly'},
                        {'criticalThrough': 'v0.8.6'}, {'criticalFixes': ['v0.8.4', 'v0.8.4']},
                        {'installationProtocol': 'orbis.installation-state.v2'}):
            with self.subTest(changes=changes), self.assertRaises(publication.SourcePublicationError):
                publication._core({**core, **changes})
        entries = {name: record(body, 'size') for name, body in bundle_files().items()}
        for index in range(67):
            suffix = chr(97 + index // 26) + chr(97 + index % 26)
            entries[f'scripts/orbis-fixture-{suffix}.py'] = record(b'', 'size')
        manifest = {'schema': 'orbis.installer-bundle.v1', 'tag': core['tag'], 'commit': CORE_COMMIT,
                    'archive': 'orbis-installer.tar.gz', 'archiveBytes': 1, 'archiveSha256': '7' * 64,
                    'releaseManifestSha256': '8' * 64, 'files': entries}
        for changes in ({}, {'schema': 'orbis.installer-bundle.v4'}, {'schema': 'orbis.installer-bundle.v3', 'unknown': 1}):
            body = publication.encoded({**manifest, **changes})
            with self.subTest(changes=changes), self.assertRaises(publication.SourcePublicationError):
                publication._manifest(body, 'release', {'tag': core['tag'], 'commit': CORE_COMMIT,
                                                        'manifestSha256': publication.sha(body)})

    def test_bundle_manifest_count_limits_are_versioned_and_mode_specific(self):
        required = bundle_files()
        self.assertEqual(publication.MAX_FILES, 128)
        for mode, versions, wrong_version in (('release', (1, 3, 5), 6), ('modular', (2, 4, 6), 5)):
            identity = {'commit': CORE_COMMIT, 'tag': 'v0.8.5'}
            binding = ({**identity, 'releaseManifestSha256': '8' * 64} if mode == 'release'
                       else {'installerCommit': CORE_COMMIT})
            for version, limit in zip(versions, (66, 128, 160)):
                schema = f'orbis.installer-bundle.v{version}'
                with self.subTest(mode=mode, schema=schema):
                    files = required.copy()
                    for index in range(limit - len(required)):
                        suffix = chr(97 + index // 26) + chr(97 + index % 26)
                        files[f'scripts/orbis-fixture-{suffix}.py'] = b''
                    archive = io.BytesIO()
                    with gzip.GzipFile(fileobj=archive, mode='wb', mtime=0) as compressed:
                        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                            for name, content in sorted(files.items()):
                                entry = tarfile.TarInfo(name)
                                entry.size = len(content)
                                tar.addfile(entry, io.BytesIO(content))
                    archive_bytes = archive.getvalue()
                    manifest = {**binding, 'schema': schema, 'archive': 'orbis-installer.tar.gz',
                                'archiveBytes': len(archive_bytes), 'archiveSha256': publication.sha(archive_bytes),
                                'files': {name: record(content, 'size') for name, content in files.items()}}
                    body = publication.encoded(manifest)
                    verified = publication._manifest(body, mode, {**identity, 'manifestSha256': publication.sha(body)})
                    self.assertEqual(publication._archive(archive_bytes, verified), files)
                    for invalid in ({**manifest, 'schema': f'orbis.installer-bundle.v{wrong_version}'},
                                    {**manifest, 'files': {**manifest['files'],
                                                           'scripts/orbis-over-limit.py': record(b'', 'size')}}):
                        body = publication.encoded(invalid)
                        with self.assertRaises(publication.SourcePublicationError):
                            publication._manifest(body, mode, {**identity, 'manifestSha256': publication.sha(body)})

    def test_strict_json_and_ast_reject_ambiguous_literals(self):
        for invalid in (b'{"a":1,"a":1}', b'{"a":NaN}', b'{"a":1.0}', b'{"a":"\xff"}'):
            with self.subTest(invalid=invalid), self.assertRaises(publication.SourcePublicationError):
                publication._json(invalid)
        source = f'SCRIPTS = {COPIED!r}\n'.encode()
        for mutation in (b'SCRIPTS = ()\n', b'SCRIPTS += ()\n', b'SCRIPTS[0] = 1\n',
                         b'def change():\n    global SCRIPTS\n    SCRIPTS = ()\n',
                         b'SCRIPTS.append("new.py")\n', b'del SCRIPTS\n'):
            with self.subTest(mutation=mutation), self.assertRaises(publication.SourcePublicationError):
                publication._literal(source + mutation, 'SCRIPTS')
        with self.assertRaises(publication.SourcePublicationError):
            publication._literal(b'EXPECTED_RELEASE = {"tag":"a","tag":"b"}', 'EXPECTED_RELEASE')
        for members in ((COPIED[0], COPIED[0]), (COPIED[0], []), (COPIED[0], '../outside.py')):
            files = {**bundle_files(), 'scripts/orbis-host-service-setup.py': f'SCRIPTS = {members!r}'.encode()}
            with self.subTest(members=members), self.assertRaises(publication.SourcePublicationError):
                publication._scripts(files)

    def test_physical_archive_refuses_duplicates_aliases_traversal_and_inflation(self):
        files = bundle_files()
        entries = sorted(files.items())

        def inspect(body):
            return publication._archive(body, {'archiveBytes': len(body), 'archiveSha256': publication.sha(body),
                'files': {name: record(content, 'size') for name, content in files.items()}})

        self.assertEqual(inspect(tar(entries)), files)
        special = []
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.GNUTYPE_SPARSE):
            entry = tarfile.TarInfo(entries[0][0])
            entry.type = kind
            entry.linkname = 'scripts/orbis-host-service.py'
            special.append(tar([(entry, b''), *entries[1:]]))
        for artifact in (tar(entries + entries[:1]), tar(entries[1:]), tar([('../escape.py', b''), *entries[1:]]),
                         tar([('/absolute.py', b''), *entries[1:]]), tar(entries, format=tarfile.GNU_FORMAT),
                         gzip.compress(gzip.decompress(tar(entries)) + b'bad', mtime=0), *special):
            with self.subTest(artifact_size=len(artifact)), self.assertRaises(publication.SourcePublicationError):
                inspect(artifact)
        with mock.patch.object(publication, 'MAX_TAR', 4096), self.assertRaises(publication.SourcePublicationError):
            inspect(tar(entries))


if __name__ == '__main__':
    unittest.main()
