from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest import mock

from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_worker as worker
import test_recovery_worker as worker_fixture


class RecoveryConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        for module, name, value in ((sessions, '_OWNER_UID', os.getuid()), (worker, '_OWNER_UID', os.getuid()),
                                    (worker.sys, 'platform', 'linux')):
            patch = mock.patch.object(module, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.now = 1_800_000_000_000
        self.origin = 'https://recovery.example'
        self.store = sessions.RecoverySessions(self.temp.name, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.catalog = profiles.RecoveryProfiles(self.store, inspect=self.describe, verify=self.proof)
        self.addCleanup(self.catalog.close)
        self.prepared = self.catalog.prepare(json.dumps({'revision': 'b' * 64}).encode())
        self.active = self.describe(str(Path(self.temp.name) / 'profiles' / self.prepared.digest), self.prepared.digest)
        status = self.store.operator_status()
        pending = self.catalog.begin(self.prepared, expected_generation=status['generation'], expected_revision=status['revision'])
        self.catalog.complete(self.prepared, change_token=pending['changeToken'], expected_generation=pending['generation'])
        key = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=key['revision'], recovery_key=key['recoveryKey'], expected_revision=None)
        self.key = key['recoveryKey']

    def describe(self, directory, digest):
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest,
                'revision': json.loads((Path(directory) / 'identity.json').read_bytes())['revision'], 'accountId': 1,
                'origin': self.origin, 'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {}}

    def proof(self, _directory, digest, challenge, _credentials):
        return {'schema': 'orbis.sentinel-authentication.v1', 'verified': True, 'accountId': 1,
                'revision': self.active['revision'], 'identitySha256': digest, 'challenge': challenge,
                'method': 'password', 'verifiedAtMs': self.now, 'totpStep': None, 'credential': None}

    def login(self):
        binding = secrets.token_urlsafe(32)
        nonce = self.store.challenge(method='password', origin=self.origin, browser_binding=binding)['challenge']
        return self.store.complete(challenge=nonce, browser_binding=binding, origin=self.origin,
                                   verifier=lambda digest, issued: self.catalog.verify(digest, issued, {'method': 'password'}))

    def key_login(self):
        binding = secrets.token_urlsafe(32)
        nonce = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)['challenge']
        return self.store.complete_recovery_key(challenge=nonce, browser_binding=binding, origin=self.origin, recovery_key=self.key)

    def gate(self, action):
        entered, release = threading.Event(), threading.Event()
        def blocked(*args):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError('Synthetic worker did not release')
            return action(*args)
        return entered, release, blocked

    def assert_key_works(self, pool):
        result = pool.submit(self.key_login).result(timeout=2)
        self.assertEqual(self.store.session(token=result['token'], origin=self.origin)['method'], 'recovery-key')

    def test_key_authentication_completes_while_operator_profile_verification_is_blocked(self):
        entered, release, blocked = self.gate(self.proof)
        self.catalog._verify_worker = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.login)
            try:
                self.assertTrue(entered.wait(timeout=2))
                self.assert_key_works(pool)
                self.assertFalse(pending.done())
            finally:
                release.set()
            self.assertEqual(self.store.session(token=pending.result(timeout=2)['token'], origin=self.origin)['method'], 'password')

    def test_key_authentication_completes_during_preparation_and_inspected_activation(self):
        entered, release, blocked = self.gate(self.describe)
        self.catalog._inspect = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            prepared = pool.submit(self.catalog.prepare, json.dumps({'revision': 'c' * 64}).encode())
            try:
                self.assertTrue(entered.wait(timeout=2))
                self.assert_key_works(pool)
            finally:
                release.set()
            candidate = prepared.result(timeout=2)
        self.catalog._inspect = self.describe
        status = self.store.operator_status()
        change = self.catalog.begin(candidate, expected_generation=status['generation'], expected_revision=status['revision'])
        entered, release, blocked = self.gate(self.describe)
        self.catalog._inspect = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            activation = pool.submit(self.catalog.complete, candidate, change_token=change['changeToken'], expected_generation=change['generation'])
            try:
                self.assertTrue(entered.wait(timeout=2))
                self.assert_key_works(pool)
            finally:
                release.set()
            self.assertEqual(activation.result(timeout=2)['state'], 'enrolled')

    def test_revocation_during_blocked_crypto_prevents_late_session_and_keeps_key_working(self):
        entered, release, blocked = self.gate(self.proof)
        self.catalog._verify_worker = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.login)
            try:
                self.assertTrue(entered.wait(timeout=2))
                pool.submit(self.store.revoke).result(timeout=2)
                self.assert_key_works(pool)
            finally:
                release.set()
            with self.assertRaises(sessions.RecoverySessionError):
                pending.result(timeout=2)

    def test_replaced_enrollment_during_inspection_cannot_activate_old_generation(self):
        candidate = self.catalog.prepare(json.dumps({'revision': 'c' * 64}).encode())
        status = self.store.operator_status()
        change = self.catalog.begin(candidate, expected_generation=status['generation'], expected_revision=status['revision'])
        entered, release, blocked = self.gate(self.describe)
        self.catalog._inspect = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.catalog.complete, candidate, change_token=change['changeToken'], expected_generation=change['generation'])
            try:
                self.assertTrue(entered.wait(timeout=2))
                pool.submit(self.store.revoke).result(timeout=2)
                state = self.store.operator_status()
                replacement = pool.submit(self.store.begin_operator_enrollment, expected_generation=state['generation'],
                    expected_revision=state['revision'], identity_sha256='d' * 64, origin=self.origin).result(timeout=2)
                self.assert_key_works(pool)
            finally:
                release.set()
            with self.assertRaises(profiles.RecoveryProfileError):
                pending.result(timeout=2)
        self.assertEqual(self.store.operator_status()['generation'], replacement['generation'])
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def gated_worker(self):
        runner = worker_fixture.DockerFixture()
        adapter = worker.RecoveryWorker(self.store, image_id=worker_fixture.IMAGE, runner=runner)
        self.addCleanup(adapter.close)
        entered, release = threading.Event(), threading.Event()
        original = runner.run
        def run(args, **options):
            if args[0] == 'create':
                runner.result = json.dumps(self.proof(None, self.prepared.digest, args[-1], {})).encode()
            if args[0] == 'start':
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError('Synthetic Docker attach did not release')
            return original(args, **options)
        runner.run = run
        self.catalog._verify_worker = adapter.verify
        return adapter, runner, entered, release

    def test_key_authentication_completes_while_real_adapter_transport_is_blocked(self):
        _, runner, entered, release = self.gated_worker()
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.login)
            try:
                self.assertTrue(entered.wait(timeout=2))
                self.assert_key_works(pool)
            finally:
                release.set()
            pending.result(timeout=2)
        self.assertFalse(runner.present)
        self.assertEqual(json.loads((Path(self.temp.name) / 'credential-worker/state.json').read_text())['phase'], 'clean')

    def test_shutdown_keeps_resources_until_owned_worker_cleanup_and_withholds_late_session(self):
        _, runner, entered, release = self.gated_worker()
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.login)
            try:
                self.assertTrue(entered.wait(timeout=2))
                closing = pool.submit(self.store.close)
                with self.store._idle:
                    self.assertTrue(self.store._idle.wait_for(lambda: self.store._closing, timeout=2))
                    self.assertFalse(self.store._closed)
                    self.assertTrue(self.store._directories)
                self.assertFalse(closing.done())
            finally:
                release.set()
            with self.assertRaises(sessions.RecoverySessionError):
                pending.result(timeout=2)
            closing.result(timeout=2)
        self.assertTrue(self.store._closed)
        self.assertFalse(runner.present)
        self.assertEqual(json.loads((Path(self.temp.name) / 'credential-worker/state.json').read_text())['phase'], 'clean')

    def test_close_from_borrowing_callback_is_rejected_without_deadlock(self):
        original = self.catalog._verify_worker
        def verify(*args):
            with self.assertRaises(sessions.RecoverySessionError):
                self.store.close()
            return original(*args)
        self.catalog._verify_worker = verify
        self.login()
        self.assertFalse(self.store._closing)
        self.assertFalse(self.store._borrowers)

    def test_catalog_and_worker_serialization_are_shared_by_instances(self):
        self.assertIs(self.catalog._store._profile_mutex, self.store._profile_mutex)
        adapter, runner, entered, release = self.gated_worker()
        another = worker.RecoveryWorker(self.store, image_id=worker_fixture.IMAGE, runner=runner)
        self.addCleanup(another.close)
        directory = str(Path(self.temp.name) / 'profiles' / self.prepared.digest)
        scheduled = threading.Event()
        def inspect():
            scheduled.set()
            return another.inspect(directory, self.prepared.digest)
        with ThreadPoolExecutor(max_workers=3) as pool:
            first = pool.submit(self.login)
            try:
                self.assertTrue(entered.wait(timeout=2))
                second = pool.submit(inspect)
                self.assertTrue(scheduled.wait(timeout=2))
                self.assertFalse(second.done())
                self.assertEqual(sum(args[0] == 'create' for args, _ in runner.calls), 1)
                self.assert_key_works(pool)
            finally:
                release.set()
            first.result(timeout=2)
            second.result(timeout=2)
        self.assertFalse(runner.present)
