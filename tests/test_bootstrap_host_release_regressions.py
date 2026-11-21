"""Publication release durability and scope checks using protected local fixtures."""

from contextlib import contextmanager, ExitStack
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_host_release as release
from orbis_sentinel import bootstrap_publication as publication
from orbis_sentinel import bootstrap_source as source
from orbis_sentinel import credential_floor as floor
import test_bootstrap_host_release


class HostReleaseRegressions(unittest.TestCase):
    def setUp(self):
        self.case = case = test_bootstrap_host_release.HostReleaseTests('runTest')
        self.addCleanup(case.doCleanups)
        case.setUp()
        self.fixture = case.fixture
        self.namespace = self.fixture.namespace

    def test_release_rename_sync_failure_is_repaired_before_publish(self):
        path = self.namespace / publication.RELEASE_FILE
        info = self.namespace.stat()
        original = os.fsync
        synced = []

        def sync(fd):
            current = os.fstat(fd)
            if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino) and path.exists():
                synced.append(True)
                if len(synced) == 1:
                    raise OSError('Interrupted release directory sync')
            original(fd)

        call = self.case.client.call
        def control(operation, arguments):
            if operation == 'bootstrap-paired-publication-publish':
                self.assertGreater(len(synced), 1)
            return call(operation, arguments)

        with mock.patch.object(os, 'fsync', side_effect=sync):
            with self.assertRaisesRegex(OSError, 'Interrupted release'):
                self.case.run_release()
            self.assertTrue(path.exists())
            self.assertEqual(self.fixture.rows(), self.case.original_rows)
            self.case.client.call = control
            self.case.run_release()
            self.case.assert_published()
        self.assertGreater(len(synced), 1)

    def test_saved_ready_rechecks_both_pending_dependencies_before_retirement(self):
        self.case.fail_write = release.READY_FILE
        with self.assertRaises(OSError):
            self.case.run_release()
        calls = list(self.case.calls)
        for name in (publication.QUALIFICATION_FILE, publication.FENCE):
            with self.subTest(name=name):
                pending = self.namespace / ('.' + name + '.pending')
                self.fixture.fixture.write(pending, (self.namespace / name).read_bytes())
                try:
                    with self.assertRaises(ValueError):
                        self.case.run_release()
                    self.assertEqual(self.case.calls, calls)
                    for active in (publication.FENCE, publication.INTENT):
                        self.assertTrue((self.namespace / active).exists())
                    self.assertFalse((self.namespace / publication.RELEASE_FILE).exists())
                    self.assertEqual(self.fixture.rows(), self.case.original_rows)
                finally:
                    pending.unlink()
        self.case.run_release()
        self.case.assert_published()

    def test_real_lifecycle_gate_holds_every_interrupted_release_prefix(self):
        core = Path(os.environ['ORBIS_RECOVERY_TEST_CORE']) / 'scripts/orbis-host-credential-fence.py'
        spec = importlib.util.spec_from_file_location('_release_gate_regression', core)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        host = SimpleNamespace(AUTHORITY=SimpleNamespace(LAYOUT=SimpleNamespace(
            selected_path=lambda root, role: self.namespace / publication.FENCE,
            legacy_path=lambda root, role: root.parent / ('.' + root.name + '.orbis-credential-fence.json'),
            namespace=lambda root: self.namespace)))
        self.case.fail_finish = True
        with self.assertRaises(OSError):
            self.case.run_release()
        with self.assertRaises(ValueError):
            gate.require_clear(host, Path(self.fixture.review['root']))
        self.assertTrue((self.namespace / release.PUBLICATION_HOLD).exists())
        self.case.fail_write = publication.RELEASE_FILE
        with self.assertRaises(OSError):
            self.case.run_release()
        self.assertFalse((self.namespace / publication.INTENT).exists())
        with self.assertRaises(ValueError):
            gate.require_clear(host, Path(self.fixture.review['root']))
        self.case.lose_reply = 'publish'
        with self.assertRaises(OSError):
            self.case.run_release()
        with self.assertRaises(ValueError):
            gate.require_clear(host, Path(self.fixture.review['root']))
        reader = floor.CredentialFloorReader(self.fixture.review['root'], self.fixture.review['context'],
            self.fixture.review['daemon'], host_state_directory=self.fixture.fixture.base)
        self.assertIn(release.PUBLICATION_HOLD, reader._pending(self.namespace))
        self.case.run_release()
        self.assertFalse((self.namespace / release.PUBLICATION_HOLD).exists())
        self.assertIsNone(gate.require_clear(host, Path(self.fixture.review['root'])))
        self.case.assert_published()

    def test_live_scope_requires_layout_worker_candidate_and_host_idle(self):
        fixture, case = self.fixture, self.case
        layout = {'fixture': 'current layout'}
        review = {**fixture.review, 'layoutSha256': source.digest(source.encoded(layout)),
                  'host': {**fixture.review['host'], 'inventorySha256': source.digest(source.encoded({}))}}
        packet = fixture.packet
        worker = source.decode((fixture.fixture.operation / 'activation-history.json').read_bytes())['current']['authWorker']

        @contextmanager
        def held_runtime(**kwargs):
            yield review['runtime'], {}, mock.Mock()

        @contextmanager
        def recovery(*args, **kwargs):
            yield {**review['recovery'], 'process': {'pid': 4321}}, mock.Mock()

        custody = {'sourceFiles': {}, 'unitSha256': review['host']['unitSha256'],
                   'environmentSha256': review['host']['environmentSha256']}
        idle = mock.Mock()
        read_layout = mock.Mock(return_value=layout)
        supervisor = SimpleNamespace(_held_runtime=held_runtime, bootstrap_recovery=recovery,
            _main=mock.Mock(return_value=(packet['installationId'], review['main'], packet['daemon'])),
            _host_stopped=mock.Mock(return_value={'custody': custody, 'systemdSha256': review['host']['effectiveSha256']}))
        admission = SimpleNamespace(supervisor=supervisor, _journal=mock.Mock(return_value=review['journal']),
            layout=SimpleNamespace(read=read_layout), service=SimpleNamespace(require_credential_idle=idle),
            host=SimpleNamespace(CREDENTIAL_FENCE=SimpleNamespace(BOOTSTRAP_PUBLICATION_PROTOCOL=1,
                BOOTSTRAP_PUBLICATION_HOLD=release.PUBLICATION_HOLD)))
        product = SimpleNamespace(RECOVERY_SETUP='fixture marker', C=SimpleNamespace(PinnedFile=mock.Mock(
            return_value=SimpleNamespace(body=b'fixture marker', verify=mock.Mock(), close=mock.Mock()))))
        (self.namespace / 'credential-journal').mkdir(mode=0o700)
        root = SimpleNamespace(path=Path(review['root']))
        guard = object()
        writer = release.HostPublicationRelease(case.actor)
        with (source.PrivateDirectory(self.namespace) as namespace,
              source.PrivateDirectory(fixture.fixture.operation) as directory,
              mock.patch.object(release, 'RootBootstrapControlClient', return_value=case.client) as client,
              mock.patch.object(release.storage, 'verify_role'),
              mock.patch.object(case.actor, '_qualified_worker', return_value=worker) as qualified,
              mock.patch.object(release, 'require_retained_worker', return_value=worker) as retained):
            with ExitStack() as resources, writer._live(resources, review, packet, admission, product, root,
                    namespace, mock.Mock(), guard, directory) as observed:
                self.assertIs(observed[0], case.client)
                observed[2]()
                for target in (read_layout, retained, idle):
                    target.side_effect = ValueError('fixture changed live scope')
                    with self.assertRaisesRegex(ValueError, 'changed live scope'):
                        observed[2]()
                    target.side_effect = None
                observed[2]()
            self.assertEqual(client.call_args.kwargs['expected_pid'], 4321)
            idle.assert_called_with(guard)
            qualified.assert_called_once()
            admission.host.CREDENTIAL_FENCE.BOOTSTRAP_PUBLICATION_PROTOCOL = None
            with ExitStack() as resources, self.assertRaises(ValueError):
                with writer._live(resources, review, packet, admission, product, root, namespace,
                        mock.Mock(), guard, directory):
                    self.fail('older lifecycle helper accepted')
            admission.host.CREDENTIAL_FENCE.BOOTSTRAP_PUBLICATION_PROTOCOL = 1
            for changed in ({**worker, 'anchorSha256': '0' * 64},):
                qualified.return_value = changed
                with ExitStack() as resources, self.assertRaises(ValueError):
                    with writer._live(resources, review, packet, admission, product, root, namespace,
                            mock.Mock(), guard, directory):
                        self.fail('candidate worker mismatch accepted')

