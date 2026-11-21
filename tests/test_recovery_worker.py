import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel import recovery_worker as worker

IMAGE = 'sha256:' + 'a' * 64
CID = 'b' * 64
DIGEST = 'c' * 64
CAPABILITY = {'schema':'orbis.sentinel-authentication-worker.v1','version':1,'methods':['password','passkey'],
              'role':'operator','maxIdentityBytes':65536,'maxRequestBytes':32768,'deadlineMs':10000,
              'databaseRequired':False,'mutations':'none','grantsAuthority':False,
              'identityContentProof':'orbis.sentinel-identity-content.v1',
              'effectiveIdentityContentProof':'orbis.sentinel-effective-identity-content.v1',
              'passkeyCounterProof':'orbis.sentinel-passkey-counter.v1'}


class DockerFixture:
    """Docker protocol fixture; native QA supplies the actual daemon and crypto."""
    def __init__(self):
        self.calls = []
        self.present = False
        self.running = False
        self.exit_code = 0
        self.volumes = None
        self.mismatch = False
        self.failure = None
        self.result = b'{"syntheticResult":true}'

    def run(self, args, **options):
        self.calls.append((list(args), options))
        verb = args[0]
        if self.failure == verb:
            if verb == 'create':
                self.present = True
            raise RuntimeError('synthetic-secret-must-not-escape')
        if verb == 'image':
            return 0, (json.dumps(IMAGE) + '\n' + json.dumps(self.volumes) + '\n').encode()
        if verb == 'create':
            self.name = args[args.index('--name') + 1]
            self.nonce = args[args.index('--label') + 1].split('=', 1)[1]
            self.present = True
            return 0, (CID + '\n').encode()
        if verb == 'inspect':
            return 0, ('\n'.join(json.dumps(x) for x in (CID, '/' + self.name, IMAGE,
                     'wrong-owner' if self.mismatch else self.nonce, self.running, self.exit_code)) + '\n').encode()
        if verb == 'start':
            return 0, self.result
        if verb == 'rm':
            self.present = False
            return 0, (CID + '\n').encode()
        if verb == 'ps':
            return 0, (CID + '\n').encode() if self.present else b''
        raise AssertionError('Unexpected Docker verb')


class RecoveryWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for target, name, value in ((sessions, '_OWNER_UID', os.getuid()), (worker, '_OWNER_UID', os.getuid()),
                                    (worker.sys, 'platform', 'linux')):
            patch = mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.store = sessions.RecoverySessions(self.temp.name)
        self.addCleanup(self.store.close)
        self.runner = DockerFixture()
        self.adapter = self.open()
        self.directory = os.path.join(self.temp.name, 'profiles', DIGEST)

    def open(self):
        value = worker.RecoveryWorker(self.store, image_id=IMAGE, runner=self.runner)
        self.addCleanup(value.close)
        return value

    def invoke(self, adapter=None):
        return (adapter or self.adapter).inspect(self.directory, DIGEST)

    def receipt(self):
        return Path(self.temp.name) / 'credential-worker' / 'state.json'

    def test_capability_uses_actual_owned_worker_without_identity_mount_or_credentials(self):
        self.runner.result=json.dumps(CAPABILITY).encode()
        self.assertEqual(self.adapter.capability(),CAPABILITY)
        create=next(args for args,_ in self.runner.calls if args[0]=='create')
        self.assertEqual(create[-2:],[worker._SCRIPT,'--capability'])
        self.assertNotIn('--mount',create);self.assertNotIn(DIGEST,create)
        start=next(options for args,options in self.runner.calls if args[0]=='start')
        self.assertEqual(start['body'],b'')
        self.assertFalse(self.runner.present);self.assertEqual(json.loads(self.receipt().read_bytes())['phase'],'clean')

    def test_incomplete_old_bool_or_extra_capability_is_cleaned_and_refused(self):
        for changes in ({'version':True},{'version':1.0},{'passkeyCounterProof':None},
                        {'effectiveIdentityContentProof':'old'},{'grantsAuthority':True},{'extra':True}):
            self.runner.result=json.dumps(dict(CAPABILITY,**changes)).encode()
            with self.subTest(changes=changes),self.assertRaises(worker.RecoveryWorkerError):self.adapter.capability()
            self.assertFalse(self.runner.present);self.assertEqual(json.loads(self.receipt().read_bytes())['phase'],'clean')

    def test_capability_cleanup_failure_never_returns_qualification(self):
        self.runner.result=json.dumps(CAPABILITY).encode();self.runner.failure='rm'
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):self.adapter.capability()
        self.assertEqual(json.loads(self.receipt().read_bytes())['phase'],'created')

    def test_credentials_only_use_stdin_and_result_requires_verified_cleanup(self):
        challenge = secrets.token_urlsafe(32)
        credentials = {'method': 'password', 'password': 'synthetic-secret-must-not-escape'}
        self.assertEqual(self.adapter.verify(self.directory, DIGEST, challenge, credentials), {'syntheticResult': True})
        args = self.runner.calls[1][0]
        self.assertIn('--network=none', args)
        self.assertIn('--log-driver=none', args)
        self.assertIn('--pull=never', args)
        self.assertIn('--read-only', args)
        self.assertEqual(args[-3:], ['--verify', DIGEST, challenge])
        start = next(options for args, options in self.runner.calls if args[0] == 'start')
        self.assertEqual(json.loads(start['body']), credentials)
        self.assertNotIn(credentials['password'], repr([args for args, _ in self.runner.calls]))
        self.assertNotIn(credentials['password'], self.receipt().read_text())
        self.assertEqual(json.loads(self.receipt().read_text())['phase'], 'clean')
        self.assertFalse(self.runner.present)
        self.assertEqual(self.receipt().stat().st_mode & 0o777, 0o600)

    def test_description_has_larger_bounded_output_and_empty_stdin(self):
        self.invoke()
        start = next(options for args, options in self.runner.calls if args[0] == 'start')
        self.assertEqual(start['body'], b'')
        self.assertEqual(start['limit'], 32768)

    def test_content_proof_uses_same_bounded_owned_worker_and_cleanup(self):
        self.assertEqual(self.adapter.inspect_content(self.directory, DIGEST), {'syntheticResult': True})
        create = next(args for args, _ in self.runner.calls if args[0] == 'create')
        self.assertEqual(create[-2:], ['--describe-content', DIGEST])
        start = next(options for args, options in self.runner.calls if args[0] == 'start')
        self.assertEqual(start['body'], b'')
        self.assertEqual(start['limit'], 32768)
        self.assertFalse(self.runner.present)
        self.assertEqual(json.loads(self.receipt().read_text())['phase'], 'clean')

    def test_ambiguous_create_is_durable_hold_even_after_container_disappears(self):
        self.runner.failure = 'create'
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke()
        self.assertEqual(json.loads(self.receipt().read_text())['phase'], 'intent')
        self.runner.present = False
        self.runner.failure = None
        before = len(self.runner.calls)
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke(self.open())
        self.assertEqual(len(self.runner.calls), before)

    def test_start_failure_cleans_owned_child_and_allows_next_attempt(self):
        self.runner.failure = 'start'
        with self.assertRaisesRegex(worker.RecoveryWorkerError, '^The recovery credential worker is unavailable'):
            self.invoke()
        self.assertFalse(self.runner.present)
        self.assertEqual(json.loads(self.receipt().read_text())['phase'], 'clean')
        self.runner.failure = None
        self.invoke()

    def test_wrong_owner_never_gets_started_or_removed_and_remains_held(self):
        self.runner.mismatch = True
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke()
        self.assertFalse(any(args[0] in ('rm', 'start') for args, _ in self.runner.calls))
        self.assertTrue(self.runner.present)

    def test_remove_failure_never_returns_crypto_result(self):
        self.runner.failure = 'rm'
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke()
        self.assertEqual(json.loads(self.receipt().read_text())['phase'], 'created')
        self.runner.failure = None
        before = len(self.runner.calls)
        self.invoke(self.open())
        new = [args[0] for args, _ in self.runner.calls[before:]]
        self.assertLess(new.index('rm'), new.index('create'))

    def test_nonzero_or_still_running_worker_is_cleaned_without_result(self):
        for field, value in (('exit_code', 7), ('running', True)):
            with self.subTest(field=field):
                setattr(self.runner, field, value)
                with self.assertRaises(worker.RecoveryWorkerError):
                    self.invoke()
                self.assertFalse(self.runner.present)
                setattr(self.runner, field, 0 if field == 'exit_code' else False)

    def test_invalid_output_is_cleaned_before_error(self):
        for output in (b'{"a":1,"a":2}', b'[]', b'not JSON', b'{"x":NaN}'):
            self.runner.result = output
            with self.assertRaises(worker.RecoveryWorkerError):
                self.invoke()
            self.assertFalse(self.runner.present)

    def test_image_volumes_are_rejected_before_creating_any_child(self):
        self.runner.volumes = {'/data': {}}
        with self.assertRaises(worker.RecoveryWorkerError):
            self.invoke()
        self.assertFalse(any(args[0] == 'create' for args, _ in self.runner.calls))

    def test_paths_image_and_input_limits_fail_before_daemon_work(self):
        for path, digest in (('/outside', DIGEST), (self.directory, '../identity'), (self.directory + '/..', DIGEST)):
            with self.assertRaises(worker.RecoveryWorkerError):
                self.adapter.inspect(path, digest)
        with self.assertRaises(worker.RecoveryWorkerError):
            worker.RecoveryWorker(self.store, image_id='mutable:latest')
        with self.assertRaises(worker.RecoveryWorkerError):
            self.adapter.verify(self.directory, DIGEST, secrets.token_urlsafe(32), {'password': 'x' * 32768})
        self.assertFalse(self.runner.calls)

    def test_unfinished_receipt_write_and_unsafe_modes_withhold_work(self):
        self.invoke()
        directory = self.receipt().parent
        (directory / 'pending.json').write_text('{}')
        before = len(self.runner.calls)
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke()
        self.assertEqual(len(self.runner.calls), before)
        (directory / 'pending.json').unlink()
        self.receipt().chmod(0o644)
        with self.assertRaises(worker.RecoveryWorkerCleanupRequired):
            self.invoke()

    def test_failed_flush_cannot_qualify_intent_or_retry(self):
        self.invoke()
        before = len(self.runner.calls)
        with mock.patch.object(worker.os, 'fsync', side_effect=OSError('synthetic flush failure')):
            with self.assertRaises(worker.RecoveryWorkerError):
                self.invoke()
        self.assertEqual(len(self.runner.calls), before)
        self.invoke()


class DockerPipeTests(unittest.TestCase):
    def run_child(self, source, *, body=b'', limit=8192, timeout=2):
        original = subprocess.Popen
        command = []
        def child(args, **options):
            command.append((args, options))
            return original([sys.executable, '-c', source], **options)
        with mock.patch.object(worker.subprocess, 'Popen', side_effect=child):
            result = worker._Docker('/synthetic-private-config').run(['start', 'synthetic-child'], body=body, limit=limit, timeout=timeout)
        self.assertEqual(command[0][0][:5], ['/usr/bin/docker', '--config', '/synthetic-private-config', '--host', 'unix:///var/run/docker.sock'])
        self.assertNotIn('HOME', command[0][1]['env'])
        return result

    def test_bidirectional_large_input_does_not_deadlock(self):
        result = self.run_child('import sys; sys.stderr.write("notice"); body=sys.stdin.buffer.read(); sys.stdout.buffer.write(body)', body=b'x' * 32768, limit=32768)
        self.assertEqual(result, (0, b'x' * 32768))

    def test_output_and_stderr_overflow_and_deadline_are_bounded(self):
        for source in ('import sys; sys.stdout.write("x"*9000)', 'import sys; sys.stderr.write("secret"*1000)',
                       'import time; time.sleep(10)'):
            with self.subTest(source=source), self.assertRaisesRegex(worker.RecoveryWorkerError, '^The recovery credential worker is unavailable'):
                self.run_child(source, timeout=0.3)
