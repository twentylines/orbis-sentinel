"""Portable config-last join using protected fixture files and the real Root socket."""
from contextlib import contextmanager, nullcontext, redirect_stdout, redirect_stderr
import importlib.util
import io
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_control, bootstrap_host_transition as writer, bootstrap_source as source
from orbis_sentinel import credential_floor as floor, credential_storage as storage, recovery_listener_install, recovery_sessions, runtime
from orbis_sentinel.bootstrap_control import RootBootstrapControlClient
from orbis_sentinel.bootstrap_source import digest, encoded
import test_recovery_bootstrap


def load_orbis(parent, name):
    spec = importlib.util.spec_from_file_location('_bootstrap_test_' + name, parent / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def portable_write(_, directory, name, body, *, previous):
    def read(filename):
        try:
            fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'rb') as stream:
            return stream.read()

    temporary = '.' + name + '.pending'
    if read(name) != previous:
        raise ValueError('Fixture predecessor changed')
    staged = read(temporary)
    if staged is None:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    elif staged != body:
        raise ValueError('Fixture pending bytes changed')
    os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)


class HostActivationTests(unittest.TestCase):
    def setUp(self):
        original = test_recovery_bootstrap.HeldStageTests()
        original.setUp()
        self.addCleanup(original.doCleanups)
        self.original, self.fixture = original, original.fixture
        f, review = self.fixture, self.original.review
        f.now = time.time_ns() // 1_000_000
        self.request = '8' * 64
        self.namespace, self.host = f.captures.parent, original.host
        scripts = os.getenv('ORBIS_HOST_ACTIVATION_FIXTURE_SCRIPTS')
        if scripts:
            self.product = load_orbis(Path(scripts), 'orbis-host-recovery-admission')
            self.authority = load_orbis(Path(scripts), 'orbis-host-retained-authority')
            self.start(mock.patch.object(self.product, 'OWNER', os.getuid()))
            self.start(mock.patch.object(self.authority, 'OWNER', os.getuid()))
        else:
            self.product = SimpleNamespace(_write_storage=portable_write)
            self.authority = None
        self.calls = []
        self.exporter = {'syntheticPortableExporter': 1}
        self.activation_exporter = None
        self.enterprise_worker = {'imageId': review['main']['imageId'], 'anchorSha256': '4' * 64,
                                  'capabilitiesSha256': '5' * 64}
        self.previous_config = self.host.joinpath(writer.CONFIG).read_bytes() + b'\n'
        self.previous_history = json.loads(self.namespace.joinpath(floor.HISTORY).read_bytes())
        self.previous_history.update(sentinelVersion=review['previousSentinelVersion'], writerProtocol=1, planSha256='a' * 64,
                                     configSha256=digest(self.previous_config))
        self._prior_and_review()
        capture = f.capture

        def with_capability(phase, challenge, *, raw=None, change=None):
            def enrich(witness):
                capability = self.activation_exporter if phase == 'activation' and self.activation_exporter is not None else self.exporter
                witness['descriptor']['exporter']['capabilitySha256'] = digest(encoded(capability))
                if change:
                    change(witness)
                witness['descriptorSha256'] = digest(encoded(witness['descriptor']))
            return capture(phase, challenge, raw=raw, change=enrich)

        self.start(mock.patch.object(f, 'capture', side_effect=with_capability))
        self.start(mock.patch.object(floor, 'RECOVERY_ROOT', f.root))
        self.start(mock.patch.object(bootstrap_control, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(RootBootstrapControlClient, '_peer', return_value=True))
        self.actor = self.new_actor()
        self.wrapped = self.product._write_storage
        self.failure = None

        def write(authority, directory, name, body, *, previous):
            self.wrapped(authority, directory, name, body, previous=previous)
            self.calls.append((name, body))
            if self.failure is not None and self.failure(name, body):
                self.failure = None
                raise OSError('fixture loses its process after durability')

        self.start(mock.patch.object(self.product, '_write_storage', side_effect=write))

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def _prior_and_review(self):
        f, review = self.fixture, self.original.review
        body = encoded(self.previous_history) + b'\n'
        f.write(self.host / writer.CONFIG, self.previous_config)
        f.write(self.namespace / floor.HISTORY, body)
        review.update(hostHistorySha256=digest(body), previousAdmissionSha256=digest(self.previous_config),
                      previousWriterProtocol=self.previous_history['writerProtocol'])
        self.original.review_sha = digest(encoded(review))
        self.previous_history_body = body
        f.write(f.operation / 'review-plan.json', encoded(review))
        approval_path = f.operation / 'review-approval.json'
        f.write(approval_path, encoded({**json.loads(approval_path.read_bytes()), 'reviewSha256': self.original.review_sha}))
        f.plan.update(reviewSha256=self.original.review_sha, hostHistorySha256=review['hostHistorySha256'])
        f.plan_sha = digest(encoded(f.plan))
        f.write(f.operation / 'plan.json', encoded(f.plan))
        f.approval.update(planSha256=f.plan_sha)
        f.write(f.operation / 'approval.json', encoded(f.approval))

    def new_actor(self):
        f, review = self.fixture, self.original.review
        actor = writer.HostActivation(mock.Mock())
        actor.client = RootBootstrapControlClient(str(self.original.path), timeout=3)
        admission = SimpleNamespace(authority=self.authority, _bootstrap_predecessor=lambda *args: None)

        @contextmanager
        def guarded(operation, review_sha, plan_sha):
            self.assertEqual((operation, review_sha, plan_sha), (f.op, self.original.review_sha, f.plan_sha))
            with source.PrivateDirectory(f.operation) as directory, source.PrivateDirectory(self.namespace) as namespace, source.PrivateDirectory(self.host) as host:
                def verify():
                    self.assertEqual((self.namespace / 'credential-fence.json').read_bytes(), self.fence())
                    for directory_pin in (directory, namespace, host):
                        directory_pin.verify()
                verify()
                yield directory, review, f.plan, admission, self.product, SimpleNamespace(CAPABILITY=self.exporter), namespace, host, self.enterprise_worker, verify
                verify()

        self.start(mock.patch.object(actor, '_guarded', side_effect=guarded))
        return actor

    def fence(self):
        review, f = self.original.review, self.fixture
        return encoded({'schema': 'orbis.host-credential-fence.v1', 'operationId': f.op,
                        'root': review['root'], 'context': review['context'], 'admissionBinding': self.original.review_sha}) + b'\n'

    def acknowledge(self):
        f = self.fixture
        self.original.exercise('complete')
        args = {'operationId': f.op, 'planSha256': f.plan_sha}
        client = self.actor.client
        client.call('bootstrap-key-prepare', args)
        material = f.delivery()
        client.call('bootstrap-ack', {**args, 'deliveryEpoch': material['epoch'], 'recoveryKey': material['recoveryKey']})
        f.write(self.namespace / 'credential-fence.json', self.fence())

    def prepare(self):
        f = self.fixture
        self.acknowledge()
        self.args = (f.op, self.original.review_sha, f.plan_sha)
        issued = self.actor.prepare(*self.args, request=self.request)
        self.assertEqual(issued, self.actor.prepare(*self.args, request=self.request))
        self.assertFalse((f.operation / 'activation-approval.json').exists())
        self.assertFalse((self.namespace / writer.INTENT).exists())
        approval = encoded({'schema': 'orbis.sentinel-bootstrap-activation-approval.v1', 'operationId': f.op,
                            'installationId': f.installation, 'packetSha256': issued['packetSha256'],
                            'activationRequestId': self.request, 'approvalId': '9' * 64})
        self.consent = {'packet_sha': issued['packetSha256'], 'approval_sha': digest(approval)}
        f.write(f.operation / 'activation-approval.json', approval)

    def collect(self, outcome='complete'):
        f = self.fixture
        self.prepare()
        result = self.actor.arm(*self.args, **self.consent)
        self.assertEqual(result, self.actor.arm(*self.args, **self.consent))
        request = {'operationId': f.op, 'planSha256': f.plan_sha, 'packetSha256': self.consent['packet_sha'],
                   'requestId': self.request}
        challenge = self.actor.client.call('bootstrap-held-activation-challenge', request)
        self.original.exercise(outcome, activating=(self.request, challenge, self.consent['packet_sha'], result['intentSha256']))

    def assert_complete(self, result):
        f = self.fixture
        self.assertEqual(result['phase'], 'host-config-committed-held')
        self.assertEqual(result['generation'], self.previous_history['generation'] + 1)
        self.assertEqual(result['installationId'], f.installation)
        archived = self.namespace / floor.ARCHIVE / (digest(self.previous_history_body) + '.json')
        self.assertEqual(archived.read_bytes(), self.previous_history_body)
        archived_config = self.namespace / source.CONFIG_ARCHIVE / (digest(self.previous_config) + '.json')
        self.assertEqual(archived_config.read_bytes(), self.previous_config)
        self.assertEqual((self.host / writer.CONFIG).read_bytes(), (f.operation / 'activation-config.json').read_bytes())
        self.assertEqual((self.namespace / floor.HISTORY).read_bytes(), (f.operation / 'activation-history.json').read_bytes())
        self.assertEqual((self.namespace / 'credential-fence.json').read_bytes(), self.fence())
        self.assertTrue((self.namespace / writer.INTENT).exists())
        self.assertEqual(f.store._db.execute('SELECT active FROM identities').fetchone()[0], 0)
        self.assertEqual(f.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)
        with self.assertRaises(recovery_sessions.RecoverySessionError):
            f.store.authentication_options()
        with self.assertRaises(ValueError):
            f.engine.held_activation_receipt(operation_id=f.op, plan_sha256=f.plan_sha, packet_sha256=self.consent['packet_sha'])

    def test_real_root_projection_intent_terminal_and_config_last(self):
        self.collect()
        result = self.actor.commit(*self.args, **self.consent)
        self.assert_complete(result)
        names = [name for name, _ in self.calls]
        self.assertLess(names.index(floor.HISTORY), names.index(writer.CONFIG))
        self.assertLess(names.index(writer.CONFIG), names.index(source.ACTIVATION_COMPLETE))
        attempts = len(self.calls)
        self.assertEqual(self.new_actor().commit(*self.args, **self.consent), result)
        self.assertEqual(len(self.calls), attempts)

    def test_builtin_receipt_is_rechecked_in_root_writer_before_any_host_effect(self):
        review = self.original.review
        (self.namespace/'credential-journal').mkdir(mode=0o700)
        supervisor = SimpleNamespace(
            _held_runtime=lambda **_:nullcontext((review['runtime'],{},lambda:None)),
            bootstrap_recovery=lambda *_:nullcontext((review['recovery'],lambda:None)))
        admission = SimpleNamespace(supervisor=supervisor,
                                    service=SimpleNamespace(state_dir=self.host))
        verify = mock.Mock()
        calls = []
        def receipt(directory, actual):
            calls.append((directory,actual))
            if len(calls) > 1:
                raise ValueError('Fixture active edge changed')
            return {'pairedSha256':'1'*64}
        with (mock.patch.object(recovery_listener_install,'read_setup_receipt',side_effect=receipt),
              mock.patch.object(self.actor,'_qualified_worker',return_value=self.enterprise_worker),
              self.assertRaisesRegex(ValueError,'active edge changed')):
            with self.actor._observed(review,admission,self.product,None,mock.Mock(),verify):
                self.fail('Stale paired receipt reached the Root writer')
        self.assertEqual(calls,[(floor.RECOVERY_ROOT,review)]*2)
        self.assertEqual(self.calls,[])
        self.assertEqual((self.host/writer.CONFIG).read_bytes(),self.previous_config)

    def test_restricted_owner_rechecks_transport_for_projection_and_reconciliation(self):
        f = self.fixture
        self.collect()
        kwargs = {'operation_id':f.op,'plan_sha256':f.plan_sha,'packet_sha256':self.consent['packet_sha']}
        self.assertEqual(f.engine.held_activation_reconcile(**kwargs)['phase'],'activation-committed')
        with mock.patch.object(f.engine,'_listener_setup_check',side_effect=ValueError('Fixture stale edge invocation')):
            with self.assertRaisesRegex(ValueError,'stale edge'):
                f.engine.held_activation_reconcile(**kwargs)
        self.assertEqual(self.calls[-1][0],writer.INTENT)

    def test_restricted_owner_rechecks_transport_before_activation_projection(self):
        f = self.fixture
        self.acknowledge()
        kwargs = {'operation_id':f.op,'plan_sha256':f.plan_sha,'request_id':self.request}
        self.assertTrue(f.engine.held_activation_projection(**kwargs)['projectedCommitSha256'])
        with mock.patch.object(f.engine,'_listener_setup_check',side_effect=ValueError('Fixture stale edge invocation')):
            with self.assertRaisesRegex(ValueError,'stale edge'):
                f.engine.held_activation_projection(**kwargs)
        self.assertFalse((self.namespace/writer.INTENT).exists())

    def test_every_durable_boundary_resumes_same_predecessor(self):
        self.collect()
        packet = json.loads((self.fixture.operation / 'activation-packet.json').read_bytes())
        boundaries = [(source.ACTIVATION_PROGRESS, 'terminal-verified'),
                      (digest(self.previous_history_body) + '.json', None), (digest(self.previous_config) + '.json', None),
                      (source.ACTIVATION_PROGRESS, 'predecessor-archived'),
                      (packet['candidate']['bridgeSha256'] + '.json', None), (source.ACTIVATION_PROGRESS, 'bridge-ready'),
                      (floor.HISTORY, None), (source.ACTIVATION_PROGRESS, 'history-ready'),
                      (writer.CONFIG, None), (source.ACTIVATION_PROGRESS, 'config-verified'),
                      (source.ACTIVATION_COMPLETE, None), (source.ACTIVATION_PROGRESS, 'complete')]
        for name, phase in boundaries:
            with self.subTest(name=name, phase=phase):
                self.failure = lambda actual, body: actual == name and (phase is None or json.loads(body)['phase'] == phase)
                with self.assertRaisesRegex(OSError, 'fixture loses'):
                    self.new_actor().commit(*self.args, **self.consent)
        self.assert_complete(self.new_actor().commit(*self.args, **self.consent))

    def test_preserves_foreign_pending_config_and_resumes_exact_owned_temporary(self):
        self.collect()
        f = self.fixture
        self.failure = lambda name, body: name == source.ACTIVATION_PROGRESS and json.loads(body)['phase'] == 'history-ready'
        with self.assertRaises(OSError):
            self.actor.commit(*self.args, **self.consent)
        pending = self.host / ('.' + writer.CONFIG + '.pending')
        f.write(pending, b'incomplete private output')
        with self.assertRaises((ValueError, RuntimeError)):
            self.new_actor().commit(*self.args, **self.consent)
        self.assertEqual(pending.read_bytes(), b'incomplete private output')
        self.assertEqual((self.host / writer.CONFIG).read_bytes(), self.previous_config)
        pending.rename(self.host / 'preserved-fixture-temporary')
        f.write(pending, (f.operation / 'activation-config.json').read_bytes())
        self.assert_complete(self.new_actor().commit(*self.args, **self.consent))

    def test_changed_fresh_exporter_keeps_private_terminal_without_host_progress(self):
        self.activation_exporter = {'syntheticPortableExporter': 2}
        self.collect()
        with self.assertRaises(RuntimeError):
            self.actor.commit(*self.args, **self.consent)
        self.assertTrue((self.fixture.operation / 'held-activation-terminal.json').exists())
        self.assertFalse((self.namespace / source.ACTIVATION_PROGRESS).exists())
        self.assertEqual((self.host / writer.CONFIG).read_bytes(), self.previous_config)

    def test_unproven_terminal_and_wrong_approval_cannot_start_host_commit(self):
        self.collect('lost')
        attempts = len(self.calls)
        for consent in (self.consent, {**self.consent, 'approval_sha': '0' * 64}):
            with self.assertRaises((ValueError, RuntimeError)):
                self.actor.commit(*self.args, **consent)
        self.assertEqual(len(self.calls), attempts)
        self.assertFalse((self.namespace / source.ACTIVATION_PROGRESS).exists())
        self.assertEqual((self.host / writer.CONFIG).read_bytes(), self.previous_config)

    def test_unsupported_predecessor_floor_refuses_before_new_candidate_files(self):
        self.previous_history['writerProtocol'] = floor.CONTRACTS['hostBroker'][1] + 1
        self._prior_and_review()
        self.acknowledge()
        f = self.fixture
        with self.assertRaises(ValueError):
            self.actor.prepare(f.op, self.original.review_sha, f.plan_sha, request=self.request)
        self.assertFalse((f.operation / 'activation-packet.json').exists())
        self.assertFalse((self.namespace / writer.INTENT).exists())

    def test_no_inherited_contract_floor_can_be_dropped(self):
        review = self.original.review
        minima = source.v1_contract_minima(review, self.previous_history_body, self.previous_config)
        self.assertEqual(set(minima), set(floor.CONTRACTS))
        for name, baseline in minima.items():
            with self.subTest(contract=name), mock.patch.dict(floor.CONTRACTS, {name: (floor.CONTRACTS[name][0], baseline - 1)}):
                with self.assertRaises(ValueError):
                    source.v1_contract_minima(review, self.previous_history_body, self.previous_config)


class RetainedExecutionTests(unittest.TestCase):
    def test_config_last_worker_requires_exact_protected_receipt_and_real_listener_capability(self):
        capability = {'syntheticPortableAuthCapability': 1}
        receipt = {'imageId': 'sha256:' + 'a' * 64, 'anchorSha256': 'b' * 64,
                   'capabilitiesSha256': digest(encoded(capability))}
        client = mock.Mock()
        client.call.return_value = capability
        product = SimpleNamespace(_capability=lambda value: value)
        modules = {'writer_control': SimpleNamespace(WriterControlClient=mock.Mock(return_value=client))}
        namespace, review, docker = object(), object(), object()
        with mock.patch.object(writer, 'require_retained_worker', return_value=receipt) as retained:
            self.assertEqual(writer.HostActivation._qualified_worker(namespace, review, docker, product, modules), receipt)
            retained.assert_called_once_with(namespace, review, docker)
            client.call.assert_called_once_with('operator-capability', {})
            client.call.return_value = {'syntheticPortableAuthCapability': 2}
            with self.assertRaises(ValueError):
                writer.HostActivation._qualified_worker(namespace, review, docker, product, modules)
        client.reset_mock()
        with mock.patch.object(writer, 'require_retained_worker', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                writer.HostActivation._qualified_worker(namespace, review, docker, product, modules)
        client.call.assert_not_called()

    def test_only_exact_root_command_accepts_its_required_hashes(self):
        required = ['--bootstrap-operation', '1' * 64, '--review-sha256', '2' * 64, '--plan-sha256', '3' * 64]
        with mock.patch.object(runtime, '_run_host_activation', return_value=0) as call:
            self.assertEqual(runtime.main(['--bootstrap', 'prepare-activation', *required, '--request-id', '4' * 64]), 0)
            self.assertEqual(runtime.main(['--bootstrap', 'commit-activation', *required,
                                           '--activation-packet-sha256', '5' * 64,
                                           '--activation-approval-sha256', '6' * 64]), 0)
            for extra in (['--request-id', '4' * 64], ['--activation-packet-sha256', '5' * 64]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    runtime.main(['--bootstrap', 'commit-activation', *required, *extra])
            self.assertEqual(call.call_count, 2)

    def test_dispatch_executes_only_exact_manifest_pinned_writer_bytes(self):
        from orbis_sentinel import collector_execution, host_source_publication as publication
        body = b'def run(*args, verify_package, **kwargs):\n    verify_package()\n    return {"phase":"synthetic-fixed-source"}\n'
        member = 'src/orbis_sentinel/bootstrap_host_transition.py'
        producer = {'installation': {'version': '1.0.0', 'files': {member: {'bytes': len(body), 'sha256': digest(body)}}}}
        pins = mock.Mock()
        pins.file.return_value = body
        args = ('prepare-activation', '1' * 64, '2' * 64, '3' * 64)
        with (mock.patch.object(collector_execution, '_root'), mock.patch.object(publication, '_Pins', return_value=pins),
              mock.patch.object(publication, '_activation_lock'), mock.patch.object(publication, '_producer', return_value=producer),
              redirect_stderr(io.StringIO())):
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runtime._run_host_activation(*args, request='4' * 64, packet=None, approval=None), 0)
                self.assertEqual(json.loads(output.getvalue()), {'phase': 'synthetic-fixed-source'})
            pins.file.assert_called_with(publication.ROOT / 'releases/1.0.0' / member, len(body), 0o644)
            pins.file.return_value = body + b' '
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runtime._run_host_activation(*args, request='4' * 64, packet=None, approval=None), 1)
                self.assertEqual(output.getvalue(), '')
            producer['installation']['files'].clear()
            self.assertEqual(runtime._run_host_activation(*args, request='4' * 64, packet=None, approval=None), 1)
