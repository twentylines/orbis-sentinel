import copy
import os
import secrets
import tempfile
import threading
import unittest
from unittest import mock

from orbis_sentinel import recovery_sessions as recovery


class RecoverySessionsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.owner = mock.patch.object(recovery, '_OWNER_UID', os.getuid())
        self.owner.start()
        self.addCleanup(self.owner.stop)
        self.now = 1_800_000_000_000
        self.binding = secrets.token_urlsafe(32)
        self.origin = 'https://orbis.example'
        self.profile = {'identitySha256': 'a' * 64, 'revision': 'b' * 64, 'accountId': 1,
                        'origin': self.origin, 'totpEnabled': False, 'requireTotpAfterPasskey': False,
                        'credentials': {'credential': 3}}
        self.store = self.open()
        self.store.enroll(self.profile)

    def open(self):
        store = recovery.RecoverySessions(self.temp.name, clock=lambda: self.now)
        self.addCleanup(store.close)
        return store

    def challenge(self, method='password'):
        return self.store.challenge(method=method, origin=self.origin, browser_binding=self.binding)['challenge']

    def proof(self, challenge, method='password', **changes):
        value = {'schema': 'orbis.sentinel-authentication.v1', 'verified': True, 'accountId': 1,
                 'revision': self.profile['revision'], 'identitySha256': self.profile['identitySha256'],
                 'challenge': challenge, 'method': method, 'verifiedAtMs': self.now,
                 'totpStep': None, 'credential': None if method == 'password' else
                 {'id': 'credential', 'previousCounter': 3, 'newCounter': 4}}
        return {**value, **changes}

    def complete(self, challenge=None, method='password', **changes):
        challenge = challenge or self.challenge(method)
        return self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin,
                                   verifier=lambda digest, issued: self.proof(issued, method, **changes))

    def session(self, result, **changes):
        return self.store.session(token=result['token'], origin=self.origin, **changes)

    def test_password_session_csrf_logout_and_no_host_authority(self):
        result = self.complete()
        self.assertEqual(self.session(result)['accountId'], 1)
        self.assertEqual(self.session(result, csrf=result['csrfToken'], fresh=True)['method'], 'password')
        self.assertNotIn('operation', result)
        self.assertNotIn('grant', result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result, csrf=secrets.token_urlsafe(32))
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result, fresh=True)
        self.store.logout(token=result['token'], origin=self.origin, csrf=result['csrfToken'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)

    def test_tokens_and_csrf_are_never_persisted_as_plaintext(self):
        challenge = self.challenge()
        result = self.complete(challenge)
        with open(os.path.join(self.temp.name, 'recovery.sqlite3'), 'rb') as stream:
            body = stream.read()
        for raw in (challenge, self.binding, result['token'], result['csrfToken']):
            self.assertNotIn(raw.encode(), body)
        self.assertEqual(self.store._db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
        self.assertEqual(self.store._db.execute('PRAGMA synchronous').fetchone()[0], 3)
        self.assertEqual(self.store._db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_browser_binding_and_origin_are_checked_before_native_crypto(self):
        challenge = self.challenge()
        verifier = mock.Mock()
        for origin, binding in [('https://other.example', self.binding), (self.origin, secrets.token_urlsafe(32))]:
            with self.assertRaises(recovery.RecoverySessionError):
                self.store.complete(challenge=challenge, browser_binding=binding, origin=origin, verifier=verifier)
        verifier.assert_not_called()
        self.complete(challenge)

    def test_one_use_challenge_is_consumed_before_worker_failure(self):
        challenge = self.challenge()
        with self.assertRaises(RuntimeError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin,
                                verifier=mock.Mock(side_effect=RuntimeError('worker died')))
        verifier = mock.Mock()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verifier)
        verifier.assert_not_called()

    def test_expired_and_future_challenges_cannot_reach_crypto(self):
        for delta in (120_001, -1):
            challenge = self.challenge()
            self.now += delta
            with self.assertRaises(recovery.RecoverySessionError):
                self.complete(challenge)
            self.now -= delta

    def test_strict_proof_binding_rejects_forgery_or_extra_authority(self):
        variants = [{'accountId': 2}, {'accountId': True}, {'revision': 'c' * 64}, {'identitySha256': 'c' * 64},
                    {'challenge': secrets.token_urlsafe(32)}, {'method': 'passkey'}, {'verified': False},
                    {'verifiedAtMs': self.now + 1}, {'verifiedAtMs': self.now - 5001}, {'grant': 'restart'},
                    {'totpStep': self.now // 30_000}, {'credential': {'id': 'credential'}}]
        for changes in variants:
            with self.subTest(changes=changes):
                self.now += 60_001
                with self.assertRaises(recovery.RecoverySessionError):
                    challenge = self.challenge()
                    self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin,
                                        verifier=lambda *_: {**self.proof(challenge), **changes})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_native_failure_is_consumed_without_creating_a_session(self):
        challenge = self.challenge()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin,
                                verifier=lambda *_: {'schema': 'orbis.sentinel-authentication.v1', 'verified': False})
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(challenge)

    def test_persistent_rate_limit_is_applied_before_crypto_and_survives_reopen(self):
        for _ in range(10):
            with self.assertRaises(recovery.RecoverySessionError):
                self.complete(verified=False)
        challenge = self.challenge()
        verifier = mock.Mock()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verifier)
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete()
        self.now += 60_000
        self.assertEqual(self.session(self.complete())['accountId'], 1)
        verifier.assert_not_called()

    def test_totp_replay_is_blocked_across_password_passkey_and_owner_restart(self):
        self.profile.update(revision='c' * 64, identitySha256='d' * 64, totpEnabled=True, requireTotpAfterPasskey=True)
        self.store.enroll(self.profile)
        step = self.now // 30_000
        self.complete(totpStep=step)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(method='passkey', totpStep=step)
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(totpStep=step)
        self.now += 30_000
        self.complete(method='passkey', totpStep=self.now // 30_000)

    def test_passkey_opt_out_does_not_bypass_password_second_factor(self):
        self.profile.update(revision='c' * 64, identitySha256='d' * 64, totpEnabled=True)
        self.store.enroll(self.profile)
        self.complete(method='passkey')
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete()
        self.complete(totpStep=self.now // 30_000)

    def test_passkey_counter_is_durable_beyond_the_enrolled_snapshot(self):
        self.complete(method='passkey')
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(method='passkey')
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(method='passkey')
        self.complete(method='passkey', credential={'id': 'credential', 'previousCounter': 3, 'newCounter': 5})
        self.assertEqual(self.store._db.execute('SELECT counter FROM counters').fetchone()[0], 5)

    def test_zero_counter_authenticator_is_supported_with_single_use_challenges(self):
        self.profile.update(revision='c' * 64, identitySha256='d' * 64, credentials={'zero': 0})
        self.store.enroll(self.profile)
        for _ in range(2):
            self.complete(method='passkey', credential={'id': 'zero', 'previousCounter': 0, 'newCounter': 0})

    def test_revocation_and_reenrollment_invalidate_pending_and_active_sessions(self):
        result, challenge = self.complete(), self.challenge()
        previous = copy.deepcopy(self.profile)
        self.profile.update(revision='c' * 64, identitySha256='d' * 64)
        self.store.enroll(self.profile)
        for action in (lambda: self.session(result), lambda: self.complete(challenge), lambda: self.store.enroll(previous)):
            with self.assertRaises(recovery.RecoverySessionError):
                action()
        self.store.revoke()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.enroll(self.profile)
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()

    def test_idempotent_enrollment_preserves_session_and_counter(self):
        result = self.complete(method='passkey')
        self.store.enroll(self.profile)
        self.session(result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(method='passkey')
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.enroll({**self.profile, 'accountId': 2})

    def test_revision_change_does_not_erase_factor_or_credential_replay_history(self):
        self.profile.update(revision='c' * 64, identitySha256='d' * 64, totpEnabled=True)
        self.store.enroll(self.profile)
        self.complete(totpStep=self.now // 30_000)
        self.complete(method='passkey')
        self.profile.update(revision='e' * 64, identitySha256='f' * 64)
        self.store.enroll(self.profile)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(totpStep=self.now // 30_000)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(method='passkey')

    def test_new_owner_invalidates_all_old_sessions_and_challenges(self):
        result, challenge = self.complete(), self.challenge()
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete(challenge)
        self.complete()

    def test_idle_absolute_freshness_and_clock_rollback_limits(self):
        result = self.complete()
        self.now += 120_001
        self.assertFalse(self.session(result)['fresh'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result, csrf=result['csrfToken'], fresh=True)
        self.now += 900_001
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        self.now += 60_000
        result = self.complete()
        for _ in range(4):
            self.now += 899_999
            self.session(result)
        self.now += 10
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        result = self.complete()
        self.now -= 1
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)

    def test_parallel_replay_reaches_native_verifier_only_once(self):
        challenge = self.challenge()
        called = []
        result = []
        def verify(_digest, issued):
            called.append(issued)
            return self.proof(issued)
        def run():
            try:
                result.append(self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verify))
            except recovery.RecoverySessionError:
                result.append(None)
        threads = [threading.Thread(target=run) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(called, [challenge])
        self.assertEqual(sum(x is not None for x in result), 1)

    def test_worker_cannot_finish_against_a_superseded_identity(self):
        challenge = self.challenge()
        def verify(_digest, issued):
            proof = self.proof(issued)
            self.profile.update(revision='c' * 64, identitySha256='d' * 64)
            self.store.enroll(self.profile)
            return proof
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verify)

    def test_lifetime_lock_file_replacement_permissions_and_closed_store(self):
        with self.assertRaises(BlockingIOError):
            self.open()
        path = os.path.join(self.temp.name, 'recovery.sqlite3')
        os.chmod(path, 0o644)
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()
        os.chmod(path, 0o600)
        os.rename(path, path + '.retained')
        with open(path, 'wb') as stream:
            stream.write(b'replaced')
        os.chmod(path, 0o600)
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()
        self.store.close()
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()

    def test_queue_and_session_limits_are_bounded(self):
        for _ in range(32):
            self.challenge()
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()
        self.now += 120_001
        for index in range(16):
            if index % 8 == 0:
                self.now += 60_000
            self.complete()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 16)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete()
        self.now += 900_001
        self.complete()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)

    def test_existing_unsafe_journal_and_linked_database_are_rejected(self):
        self.store.close()
        db = os.path.join(self.temp.name, 'recovery.sqlite3')
        linked = db + '.linked'
        os.link(db, linked)
        with self.assertRaises(recovery.RecoverySessionError):
            self.open()
        os.unlink(linked)
        journal = db + '-journal'
        os.symlink(db, journal)
        with self.assertRaises(OSError):
            self.open()
        os.unlink(journal)
        with open(journal, 'wb') as stream:
            stream.write(b'unsafe')
        os.chmod(journal, 0o644)
        with self.assertRaises(recovery.RecoverySessionError):
            self.open()
        os.unlink(journal)
        self.store = self.open()

    def test_invalid_profile_and_noncanonical_tokens_are_rejected(self):
        for changes in ({'origin': 'https://orbis.example/path'}, {'origin': 'https://user@orbis.example'},
                        {'accountId': True}, {'totpEnabled': 1}, {'credentials': {'key': -1}}, {'grant': 'reboot'}):
            with self.subTest(changes=changes), self.assertRaises(recovery.RecoverySessionError):
                self.store.enroll({**self.profile, **changes})
        for token in ('', 'a' * 44, 'a' * 42 + 'B', ['value']):
            with self.assertRaises(recovery.RecoverySessionError):
                self.store.session(token=token, origin=self.origin)


if __name__ == '__main__':
    unittest.main()
