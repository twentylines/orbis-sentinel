"""Portable owned Docker/lifecycle seams for the real retained provisioner."""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import recovery_sessions, recovery_worker, recovery_worker_provision as provision, runtime
from orbis_sentinel.bootstrap_source import PrivateDirectory, digest, encoded
import test_bootstrap_host_transition


IMAGE = 'sha256:' + 'a' * 64
CAPABILITY = {'schema': 'orbis.sentinel-authentication-worker.v1', 'version': 1, 'methods': ['password', 'passkey'],
              'role': 'operator', 'maxIdentityBytes': 65536, 'maxRequestBytes': 32768, 'deadlineMs': 10000,
              'databaseRequired': False, 'mutations': 'none', 'grantsAuthority': False,
              'identityContentProof': 'orbis.sentinel-identity-content.v1',
              'effectiveIdentityContentProof': 'orbis.sentinel-effective-identity-content.v1',
              'passkeyCounterProof': 'orbis.sentinel-passkey-counter.v1'}


class Docker:
    def __init__(self):
        self.containers = {}
        self.creates = []
        self.starts = []
        self.removals = []
        self.lose_create_role = None
        self.lose_probe_result = False
        self.result = dict(CAPABILITY)
        self.image = {'Id': IMAGE, 'Config': {'Labels': {
            'org.opencontainers.image.source': 'https://github.com/twentylines/orbis',
            'io.orbis.credential-writer-protocol': 'orbis.credentials.v1'}}, 'RootFS': {'Layers': ['sha256:' + 'b' * 64]}}

    def run(self, arguments, **_):
        command = arguments[0]
        if command == 'image':
            return encoded(self.image)
        if command == 'ps':
            selector = arguments[arguments.index('--filter') + 1]
            if selector.startswith('name=^/'):
                found = [key for key, item in self.containers.items() if item['Name'] == '/' + selector[7:-1]]
            elif selector.startswith('id='):
                found = [key for key in self.containers if key == selector[3:]]
            else:
                raise AssertionError('Unexpected Docker selector')
            return ('\n'.join(found) + '\n').encode() if found else b''
        if command == 'inspect':
            return encoded(self.containers[arguments[-1]])
        if command == 'create':
            name = arguments[arguments.index('--name') + 1]
            labels = dict(arguments[index + 1].split('=', 1) for index, item in enumerate(arguments) if item == '--label')
            owner = labels[provision.OWNER_LABEL]
            anchor = provision.ANCHOR_LABEL in labels
            expected = recovery_worker.capability_create_arguments(name, list(f'{key}={value}' for key, value in labels.items()), IMAGE)
            if arguments != expected or '--mount' in arguments or '--pull=never' not in arguments:
                raise AssertionError('Wrong immutable capability profile')
            identity = str(len(self.creates) + 1) * 64
            self.creates.append((name, identity, owner, anchor))
            self.containers[identity] = {'Id': identity, 'Name': '/' + name, 'Image': IMAGE, 'Mounts': [],
                'Path': '/usr/local/bin/node', 'Args': ['/app/sentinel-recovery-auth.mjs', '--capability'],
                'Config': {'Image': IMAGE, 'Labels': labels, 'Entrypoint': ['/usr/local/bin/node'],
                           'Cmd': ['/app/sentinel-recovery-auth.mjs', '--capability'], 'User': '0:0',
                           'Healthcheck': {'Test': ['NONE']}, 'OpenStdin': True},
                'HostConfig': {'PublishAllPorts': False, 'Privileged': False, 'ReadonlyRootfs': True, 'AutoRemove': False,
                               'NetworkMode': 'none', 'IpcMode': 'none', 'CapDrop': ['ALL'],
                               'SecurityOpt': ['no-new-privileges'], 'LogConfig': {'Type': 'none'},
                               'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'PidsLimit': 64,
                               'Memory': 512 * 1024 * 1024, 'NanoCpus': 1000000000},
                'State': {'Running': False, 'Paused': False, 'Restarting': False, 'Dead': False,
                          'Status': 'created', 'Pid': 0, 'ExitCode': 0}}
            if self.lose_create_role == ('anchor' if anchor else 'probe'):
                self.lose_create_role = None
                raise OSError('Lost create reply in fixture')
            return (identity + '\n').encode()
        if command == 'start':
            identity = arguments[-1]
            item = self.containers[identity]
            if provision.ANCHOR_LABEL in item['Config']['Labels']:
                raise AssertionError('The anchor must never start')
            self.starts.append(identity)
            item['State']['Status'] = 'exited'
            if self.lose_probe_result:
                raise OSError('Lost probe result in fixture')
            return encoded(self.result)
        if command == 'rm':
            identity = arguments[-1]
            if self.containers[identity]['State']['Status'] != 'exited':
                raise AssertionError('The retained anchor must never be removed')
            self.removals.append(identity)
            del self.containers[identity]
            return identity.encode()
        raise AssertionError('Unexpected Docker action')


class HostGuard:
    """Visible persistent guard, standing in for the tested Host lock primitive."""
    def __init__(self, namespace):
        self.path = namespace / 'credential-fence.json'

    def read(self):
        return json.loads(self.path.read_bytes()) if self.path.exists() else None

    def check(self, operation, binding):
        if self.read() != {'operationId': operation, 'admissionBinding': binding}:
            raise ValueError('Fixture crossed Host hold')

    def begin(self, operation, binding):
        expected = {'operationId': operation, 'admissionBinding': binding}
        if self.read() not in (None, expected):
            raise ValueError('Fixture holder differs')
        self.path.write_bytes(encoded(expected))
        self.path.chmod(0o600)

    def finish(self, operation, binding, *, verify_completed):
        if self.read() is not None:
            self.check(operation, binding)
        if verify_completed() is not True:
            raise ValueError('Fixture completion proof missing')
        if self.path.exists():
            self.path.unlink()


class WorkerProvisionTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix='worker-provision-')
        self.addCleanup(work.cleanup)
        self.namespace = Path(work.name).resolve()
        self.namespace.chmod(0o700)
        self.start(mock.patch.object(recovery_sessions, '_OWNER_UID', os.getuid()))
        self.docker = Docker()
        self.guard = HostGuard(self.namespace)
        self.operation, self.publication_sha = 'b' * 64, 'c' * 64
        self.review = {'root': str(self.namespace / 'masked-main'), 'context': 'local', 'daemon': 'approved-fixture',
                       'installationId': 'd' * 64, 'origin': 'https://recovery.example',
                       'publisher': {'operationId': self.operation, 'receiptSha256': self.publication_sha},
                       'main': {'imageId': IMAGE, 'id': 'e' * 64}, 'runtime': {'inventorySha256': 'f' * 64},
                       'hostHistorySha256': '1' * 64, 'previousAdmissionSha256': '2' * 64,
                       'storage': {'installation': {'object': 1}, 'namespace': {'object': 2}, 'journal': {'object': 3}}}
        self.plan = {'schema': provision.PLAN,
                     'scope': {key: self.review[key] for key in ('installationId', 'root', 'context', 'daemon', 'origin')},
                     'publication': self.review['publisher'], 'main': self.review['main'], 'runtime': self.review['runtime'],
                     'historySha256': self.review['hostHistorySha256'], 'configSha256': self.review['previousAdmissionSha256'],
                     'imageId': IMAGE, 'profileSha256': provision._profile_sha(IMAGE), 'storage': self.review['storage'],
                     'imageDefinitionSha256': provision._image_facts(self.docker, IMAGE)}
        self.fail_write = None
        self.fail_after_write = None

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def actor(self):
        actor = provision.WorkerProvision(mock.Mock())
        admission = SimpleNamespace(authority=None)

        def write(authority, directory, name, body, *, previous):
            if self.fail_write is not None:
                self.fail_write(directory, name, body)
            test_bootstrap_host_transition.portable_write(authority, directory, name, body, previous=previous)
            if self.fail_after_write is not None and self.fail_after_write(name, body):
                self.fail_after_write = None
                raise OSError('Lost worker journal reply in fixture')

        @contextmanager
        def scope(operation, receipt_sha):
            if (operation, receipt_sha) != (self.operation, self.publication_sha):
                raise ValueError('Fixture rejected crossed publisher receipt')
            with PrivateDirectory(self.namespace) as namespace:
                def verify():
                    namespace.verify()
                    if provision._image_facts(self.docker, IMAGE) != self.plan['imageDefinitionSha256']:
                        raise ValueError('Fixture immutable image changed')
                verify()
                yield namespace, admission, SimpleNamespace(_write_storage=write), self.guard, self.plan, self.docker, verify
                verify()

        self.start(mock.patch.object(actor, '_scope', side_effect=scope))
        return actor

    def prepare(self):
        actor = self.actor()
        result = actor.review(self.operation, self.publication_sha)
        self.assertEqual(result, actor.review(self.operation, self.publication_sha))
        directory = self.namespace / provision.OPERATIONS / self.operation
        self.assertFalse((directory / 'approval.json').exists())
        self.assertEqual(self.docker.creates, [])
        approval = {'schema': provision.APPROVAL, 'publisherOperationId': self.operation,
                    'installationId': self.review['installationId'], 'reviewSha256': result['reviewSha256'], 'approvalId': '3' * 64}
        body = encoded(approval)
        (directory / 'approval.json').write_bytes(body)
        (directory / 'approval.json').chmod(0o600)
        return (self.operation, self.publication_sha, result['reviewSha256'], digest(body))

    def require(self, review=None):
        with PrivateDirectory(self.namespace) as namespace:
            return provision.require_retained_worker(namespace, review or self.review, self.docker)

    def test_real_provisioner_has_one_inert_anchor_and_one_cleaned_probe(self):
        args = self.prepare()
        result = self.actor().apply(*args)
        self.assertEqual(self.actor().apply(*args), result)
        self.assertEqual(self.docker.starts, ['2' * 64])
        self.assertEqual(self.docker.removals, self.docker.starts)
        self.assertEqual(len(self.docker.creates), 2)
        self.assertEqual(list(self.docker.containers), ['1' * 64])
        self.assertEqual(self.docker.containers['1' * 64]['State']['Status'], 'created')
        self.assertIsNone(self.guard.read())
        self.assertEqual(self.require()['capabilitiesSha256'], digest(encoded(CAPABILITY)))
        crossed = {**self.review, 'daemon': 'another-daemon'}
        with self.assertRaises(ValueError):
            self.require(crossed)
        self.docker.containers['1' * 64]['HostConfig']['NetworkMode'] = 'bridge'
        with self.assertRaises(ValueError):
            self.require()

    def test_exact_lost_create_results_resume_without_duplicate_effects(self):
        args = self.prepare()
        for role in ('anchor', 'probe'):
            with self.subTest(role=role):
                self.docker.lose_create_role = role
                with self.assertRaisesRegex(OSError, 'Lost create reply'):
                    self.actor().apply(*args)
                self.assertIsNotNone(self.guard.read())
        self.actor().apply(*args)
        self.assertEqual(len(self.docker.creates), 2)
        self.assertEqual(len(self.docker.starts), 1)
        self.assertIsNone(self.guard.read())

    def test_uncertain_create_without_an_owned_container_replays_no_effect(self):
        args = self.prepare()
        self.fail_after_write = lambda name, body: name == 'intent.json' and json.loads(body)['phase'] == 'anchor-creating'
        with self.assertRaisesRegex(OSError, 'Lost worker journal reply'):
            self.actor().apply(*args)
        with self.assertRaises(ValueError):
            self.actor().apply(*args)
        self.assertEqual(self.docker.creates, [])
        self.assertIsNotNone(self.guard.read())

    def test_receipt_write_loss_reuses_exact_probe_cleanup(self):
        args = self.prepare()
        self.fail_after_write = lambda name, body: name == IMAGE[7:] + '.json'
        with self.assertRaisesRegex(OSError, 'Lost worker journal reply'):
            self.actor().apply(*args)
        self.assertIsNotNone(self.guard.read())
        result = self.actor().apply(*args)
        self.assertEqual(self.actor().apply(*args), result)
        self.assertEqual(len(self.docker.creates), 2)
        self.assertEqual(len(self.docker.starts), 1)
        self.assertEqual(len(self.docker.removals), 1)
        self.assertIsNone(self.guard.read())

    def test_unowned_existing_anchor_and_crossed_approval_refuse_before_provision(self):
        args = self.prepare()
        with self.assertRaises(ValueError):
            self.actor().apply(*args[:-1], '8' * 64)
        anchor = provision._anchor_name(IMAGE)
        self.docker.run(provision._capability_command(anchor, IMAGE, '5' * 64, anchor=True))
        with self.assertRaises(ValueError):
            self.actor().apply(*args)
        self.assertEqual(len(self.docker.creates), 1)
        self.assertEqual(self.docker.starts, [])
        self.assertEqual(self.docker.removals, [])
        self.assertIsNone(self.guard.read())

    def test_pending_intent_without_its_original_fence_is_never_adopted(self):
        args = self.prepare()
        base = provision._operation_base(self.plan, args[2], args[3])
        partial = {**base, 'phase': 'intent', 'nonce': '4' * 64, 'anchorId': None,
                   'anchorSha256': None, 'probeId': None, 'capability': None}
        staged = self.namespace / provision.OPERATIONS / self.operation / '.intent.json.pending'
        staged.write_bytes(encoded(partial))
        staged.chmod(0o600)
        with self.assertRaises(ValueError):
            self.actor().apply(*args)
        self.assertIsNone(self.guard.read())
        self.assertEqual(staged.read_bytes(), encoded(partial))
        self.assertEqual(self.docker.creates, [])

    def test_probe_exit_without_result_holds_and_never_replays_start(self):
        args = self.prepare()
        self.docker.lose_probe_result = True
        with self.assertRaisesRegex(OSError, 'Lost probe result'):
            self.actor().apply(*args)
        with self.assertRaises(ValueError):
            self.actor().apply(*args)
        self.assertEqual(len(self.docker.starts), 1)
        self.assertEqual(self.docker.removals, [])
        self.assertIsNotNone(self.guard.read())
        self.assertFalse((self.namespace / provision.RECEIPTS).exists())

    def test_exact_durable_probe_output_temporary_is_reconciled(self):
        args = self.prepare()

        def fail(directory, name, body):
            if name != 'intent.json' or json.loads(body)['phase'] != 'probe-verified':
                return
            descriptor = os.open('.intent.json.pending', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, 'wb') as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            self.fail_write = None
            raise OSError('Lost probe journal rename in fixture')

        self.fail_write = fail
        with self.assertRaisesRegex(OSError, 'Lost probe journal rename'):
            self.actor().apply(*args)
        self.actor().apply(*args)
        self.assertEqual(len(self.docker.starts), 1)
        self.assertEqual(len(self.docker.removals), 1)
        self.assertIsNone(self.guard.read())

    def test_unsafe_probe_capability_cannot_publish_receipt(self):
        args = self.prepare()
        self.docker.result['grantsAuthority'] = True
        with self.assertRaises(recovery_worker.RecoveryWorkerError):
            self.actor().apply(*args)
        self.assertIsNotNone(self.guard.read())
        self.assertFalse((self.namespace / provision.RECEIPTS).exists())


class DispatcherTests(unittest.TestCase):
    def test_competing_publication_evidence_refuses_before_opening_host_copy(self):
        from orbis_sentinel import host_source_publication as publication

        @contextmanager
        def publisher_check(operation, bind):
            self.assertEqual(operation, '1' * 64)
            evidence = SimpleNamespace(receipt_sha256='3' * 64,
                                       observation={'schema': publication.SCHEMA_CUSTODY})
            bind(None, evidence)
            yield evidence

        with (mock.patch.object(publication, '_completed', side_effect=publisher_check),
              mock.patch.object(provision.CollectorExecutionInventory, 'open_installed') as copied):
            with self.assertRaises(ValueError):
                provision.WorkerProvision(mock.Mock()).review('1' * 64, '2' * 64)
            copied.assert_not_called()

    def test_only_fixed_worker_commands_dispatch_with_exact_scope(self):
        base = ['--publisher-receipt-sha256', '1' * 64]
        approval = ['--worker-review-sha256', '2' * 64, '--worker-approval-sha256', '3' * 64]
        with mock.patch.object(runtime, '_run_worker_provision', return_value=0) as call:
            self.assertEqual(runtime.main(['--review-recovery-worker', '4' * 64, *base]), 0)
            self.assertEqual(runtime.main(['--apply-recovery-worker', '4' * 64, *base, *approval]), 0)
            for cmd in (['--review-recovery-worker', '4' * 64, *base, *approval],
                        ['--apply-recovery-worker', '4' * 64, *base], ['--systemd-socket', *base]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    runtime.main(cmd)
            self.assertEqual(call.call_count, 2)

    def test_worker_dispatch_executes_only_exact_installed_member(self):
        from orbis_sentinel import collector_execution, host_source_publication as publication
        body = b'def run(*args,verify_package):\n    verify_package()\n    return {"phase":"owned-fixture"}\n'
        member = 'src/orbis_sentinel/recovery_worker_provision.py'
        producer = {'installation': {'version': '1.0.0', 'files': {member: {'bytes': len(body), 'sha256': digest(body)}}}}
        pins = mock.Mock()
        pins.file.return_value = body
        with (mock.patch.object(collector_execution, '_root'), mock.patch.object(publication, '_Pins', return_value=pins),
              mock.patch.object(publication, '_activation_lock'), mock.patch.object(publication, '_producer', return_value=producer),
              redirect_stderr(io.StringIO())):
            args = ('review', '1' * 64, '2' * 64, None, None)
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(runtime._run_worker_provision(*args), 0)
                self.assertEqual(json.loads(output.getvalue())['phase'], 'owned-fixture')
            pins.file.assert_called_with(publication.ROOT / 'releases/1.0.0' / member, len(body), 0o644)
            pins.file.return_value = body + b' '
            self.assertEqual(runtime._run_worker_provision(*args), 1)
