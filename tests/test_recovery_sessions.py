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

    def prepare_key(self, expected_revision=None):
        return self.store.prepare_recovery_key(origin=self.origin, expected_revision=expected_revision)

    def activate_key(self, pending, expected_revision=None):
        self.store.activate_recovery_key(revision=pending['revision'], recovery_key=pending['recoveryKey'],
                                         expected_revision=expected_revision)

    def key_session(self, key, challenge=None, **changes):
        return self.store.complete_recovery_key(challenge=challenge or self.challenge('recovery-key'),
                                                browser_binding=self.binding, origin=self.origin,
                                                recovery_key=key, **changes)

    def test_recovery_key_is_an_independent_principal_without_orbis_identity(self):
        pending = self.prepare_key()
        self.activate_key(pending)
        operator = self.complete()
        key = self.key_session(pending['recoveryKey'])
        self.store.revoke()
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(operator)
        session = self.session(key, csrf=key['csrfToken'], fresh=True)
        self.assertEqual(session['method'], 'recovery-key')
        self.assertEqual(session['principal'], 'recovery-key')
        self.assertIsNone(session['accountId'])
        self.assertEqual(self.session(self.key_session(pending['recoveryKey']))['principal'], 'recovery-key')
        options = self.store.authentication_options()
        self.assertFalse(options['password'])
        self.assertTrue(options['recoveryKey'])
        self.assertEqual(options['credentialIds'], [])
        self.assertEqual(options['totp'], {'password': False, 'passkey': False})

    def test_preparing_or_losing_a_replacement_does_not_revoke_the_working_key(self):
        current = self.prepare_key()
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge('recovery-key')
        self.activate_key(current)
        result = self.key_session(current['recoveryKey'])
        replacement = self.prepare_key(current['revision'])
        self.assertEqual(self.session(result)['method'], 'recovery-key')
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(replacement['recoveryKey'])
        self.assertEqual(self.session(self.key_session(current['recoveryKey']))['method'], 'recovery-key')
        self.now += 600_001
        with self.assertRaises(recovery.RecoverySessionError):
            self.activate_key(replacement, current['revision'])
        self.assertEqual(self.session(result)['method'], 'recovery-key')

    def test_rotation_requires_possession_and_revokes_only_key_authority(self):
        current = self.prepare_key()
        self.activate_key(current)
        operator = self.complete()
        result = self.key_session(current['recoveryKey'])
        challenge = self.challenge('recovery-key')
        replacement = self.prepare_key(current['revision'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.activate_recovery_key(revision=replacement['revision'], recovery_key=current['recoveryKey'],
                                             expected_revision=current['revision'])
        self.assertEqual(self.session(result)['method'], 'recovery-key')
        self.activate_key(replacement, current['revision'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(current['recoveryKey'], challenge=challenge)
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(current['recoveryKey'])
        self.assertEqual(self.session(operator)['principal'], 'orbis-operator')
        self.assertEqual(self.session(self.key_session(replacement['recoveryKey']))['method'], 'recovery-key')

    def test_key_rotation_rejects_stale_activation_and_preparation(self):
        first = self.prepare_key()
        rival = self.prepare_key()
        self.activate_key(first)
        with self.assertRaises(recovery.RecoverySessionError):
            self.activate_key(rival, first['revision'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.prepare_key()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.revoke_recovery_key(expected_revision=rival['revision'])
        self.assertEqual(self.session(self.key_session(first['recoveryKey']))['method'], 'recovery-key')

    def test_key_revocation_preserves_orbis_sign_in_and_sessions(self):
        key = self.prepare_key()
        self.activate_key(key)
        operator = self.complete()
        result = self.key_session(key['recoveryKey'])
        self.store.revoke_recovery_key(expected_revision=key['revision'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge('recovery-key')
        self.assertEqual(self.session(operator)['accountId'], 1)
        self.assertEqual(self.session(self.complete())['accountId'], 1)

    def test_main_account_reenrollment_preserves_key_sessions_and_challenges(self):
        key = self.prepare_key()
        self.activate_key(key)
        result = self.key_session(key['recoveryKey'])
        challenge = self.challenge('recovery-key')
        self.profile = {**self.profile, 'revision': 'c' * 64, 'accountId': 2, 'totpEnabled': True}
        self.store.enroll(self.profile)
        self.assertEqual(self.session(result)['method'], 'recovery-key')
        self.assertEqual(self.session(self.key_session(key['recoveryKey'], challenge=challenge))['method'], 'recovery-key')

    def test_key_secret_is_canonical_random_and_only_its_digest_is_persisted(self):
        key = self.prepare_key()
        self.assertRegex(key['recoveryKey'], r'^orbis-recovery-[A-Za-z0-9_-]{43}$')
        self.activate_key(key)
        self.key_session(key['recoveryKey'])
        with open(os.path.join(self.temp.name, 'recovery.sqlite3'), 'rb') as stream:
            self.assertNotIn(key['recoveryKey'].encode(), stream.read())
        options = self.store.authentication_options()
        self.assertNotIn('digest', options)
        self.assertNotIn('revision', options)

    def test_wrong_or_malformed_key_consumes_the_challenge_before_comparison(self):
        key = self.prepare_key()
        self.activate_key(key)
        for value in (None, 123, '', 'arbitrary', key['recoveryKey'] + '=', 'orbis-recovery-' + secrets.token_urlsafe(32)):
            challenge = self.challenge('recovery-key')
            with self.assertRaises(recovery.RecoverySessionError):
                self.key_session(value, challenge=challenge)
            with self.assertRaises(recovery.RecoverySessionError):
                self.key_session(key['recoveryKey'], challenge=challenge)

    def test_native_proofs_and_key_secrets_cannot_be_exchanged_between_methods(self):
        key = self.prepare_key()
        self.activate_key(key)
        verifier = mock.Mock()
        challenge = self.challenge('recovery-key')
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verifier)
        verifier.assert_not_called()
        self.key_session(key['recoveryKey'], challenge=challenge)
        challenge = self.challenge('password')
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(key['recoveryKey'], challenge=challenge)
        self.complete(challenge)

    def test_recovery_key_never_bypasses_browser_binding_origin_csrf_or_idle_expiry(self):
        key = self.prepare_key()
        self.activate_key(key)
        challenge = self.challenge('recovery-key')
        for origin, binding in [('https://other.example', self.binding), (self.origin, secrets.token_urlsafe(32))]:
            with self.assertRaises(recovery.RecoverySessionError):
                self.store.complete_recovery_key(challenge=challenge, browser_binding=binding, origin=origin, recovery_key=key['recoveryKey'])
        result = self.key_session(key['recoveryKey'], challenge=challenge)
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result, csrf=secrets.token_urlsafe(32), fresh=True)
        self.now += 900_001
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        self.store.logout(token=result['token'], origin=self.origin, csrf=result['csrfToken'])

    def test_key_state_and_rate_limit_survive_restart_without_retaining_browser_authority(self):
        key = self.prepare_key()
        self.activate_key(key)
        result = self.key_session(key['recoveryKey'])
        self.store.revoke()
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        for _ in range(9):
            with self.assertRaises(recovery.RecoverySessionError):
                self.key_session('invalid')
        self.store.close()
        self.store = self.open()
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(key['recoveryKey'])
        self.now += 60_001
        self.assertEqual(self.session(self.key_session(key['recoveryKey']))['method'], 'recovery-key')

    def test_failed_orbis_attempts_do_not_lock_the_independent_key(self):
        key = self.prepare_key()
        self.activate_key(key)
        for _ in range(10):
            with self.assertRaises(recovery.RecoverySessionError):
                self.complete(verified=False)
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete()
        self.assertEqual(self.session(self.key_session(key['recoveryKey']))['method'], 'recovery-key')

    def test_main_and_emergency_queue_and_session_limits_do_not_exhaust_each_other(self):
        key = self.prepare_key()
        self.activate_key(key)
        for _ in range(32):
            self.challenge()
        key_challenge = self.challenge('recovery-key')
        self.key_session(key['recoveryKey'], challenge=key_challenge)
        self.now += 120_001
        operators = []
        for index in range(16):
            if index % 8 == 0:
                self.now += 60_000
            operators.append(self.complete())
        for _ in range(3):
            self.assertEqual(self.session(self.key_session(key['recoveryKey']))['method'], 'recovery-key')
        with self.assertRaises(recovery.RecoverySessionError):
            self.key_session(key['recoveryKey'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.complete()
        self.store.logout(token=operators[0]['token'], origin=self.origin, csrf=operators[0]['csrfToken'])
        self.assertEqual(self.session(self.complete())['principal'], 'orbis-operator')
        for _ in range(8):
            self.challenge('recovery-key')
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge('recovery-key')
        self.challenge('password')
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 20)

    def test_enrollment_and_key_origins_cannot_silently_diverge(self):
        for origin in ('http://orbis.example', 'https://@orbis.example', 'https://orbis.example/', 'https://other.example'):
            with self.assertRaises(recovery.RecoverySessionError):
                self.store.prepare_recovery_key(origin=origin, expected_revision=None)
        key = self.prepare_key()
        self.activate_key(key)
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.enroll({**self.profile, 'revision': 'c' * 64, 'origin': 'https://other.example'})
        self.assertEqual(self.session(self.key_session(key['recoveryKey']))['method'], 'recovery-key')

    def begin_enrollment(self, **changes):
        status = self.store.operator_status()
        return self.store.begin_operator_enrollment(expected_generation=status['generation'],
                                                    expected_revision=status['revision'],
                                                    identity_sha256=changes.get('identity_sha256', 'c' * 64), origin=self.origin)

    def finish_enrollment(self, pending, **changes):
        profile = {**self.profile, 'identitySha256': 'c' * 64, 'revision': 'd' * 64, **changes}
        return self.store.complete_operator_enrollment(profile, change_token=pending['changeToken'], expected_generation=pending['generation'])

    def test_operator_enrollment_status_distinguishes_absence_revocation_and_unavailable_storage(self):
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': self.profile['revision'], 'state': 'enrolled'})
        self.store.revoke()
        self.assertEqual(self.store.operator_status(), {'generation': 2, 'revision': None, 'state': 'revoked'})
        self.store.close()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.operator_status()
        with tempfile.TemporaryDirectory() as directory:
            fresh = recovery.RecoverySessions(directory, clock=lambda: self.now)
            self.addCleanup(fresh.close)
            self.assertEqual(fresh.operator_status(), {'generation': 0, 'revision': None, 'state': 'never-enrolled'})

    def test_begin_enrollment_durably_revokes_operator_before_main_mutation_and_preserves_key(self):
        key = self.prepare_key()
        self.activate_key(key)
        operator, emergency = self.complete(), self.key_session(key['recoveryKey'])
        challenge = self.challenge('passkey')
        pending = self.begin_enrollment()
        self.assertEqual(self.store.operator_status(), {'generation': pending['generation'], 'revision': None, 'state': 'pending'})
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(operator)
        verifier = mock.Mock()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verifier)
        verifier.assert_not_called()
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()
        self.assertEqual(self.session(emergency)['principal'], 'recovery-key')
        self.assertEqual(self.session(self.key_session(key['recoveryKey']))['principal'], 'recovery-key')
        with open(os.path.join(self.temp.name, 'recovery.sqlite3'), 'rb') as stream:
            self.assertNotIn(pending['changeToken'].encode(), stream.read())

    def test_completion_is_bound_to_the_planned_profile_origin_generation_and_single_use_nonce(self):
        pending = self.begin_enrollment()
        for changes in ({'identitySha256': 'e' * 64}, {'origin': 'https://other.example'}, {'revision': self.profile['revision']}):
            with self.assertRaises(recovery.RecoverySessionError):
                self.finish_enrollment(pending, **changes)
        for token, generation in [(secrets.token_urlsafe(32), pending['generation']),
                                  (pending['changeToken'], pending['generation'] + 1)]:
            with self.assertRaises(recovery.RecoverySessionError):
                self.finish_enrollment({'changeToken': token, 'generation': generation})
        result = self.finish_enrollment(pending)
        self.assertEqual(result, {'generation': pending['generation'] + 1, 'revision': 'd' * 64, 'state': 'enrolled'})
        with self.assertRaises(recovery.RecoverySessionError):
            self.finish_enrollment(pending)
        self.profile = {**self.profile, 'identitySha256': 'c' * 64, 'revision': 'd' * 64}
        self.assertEqual(self.session(self.complete())['principal'], 'orbis-operator')

    def test_stale_or_wrong_origin_begin_does_not_revoke_a_valid_operator(self):
        result = self.complete()
        status = self.store.operator_status()
        arguments = {'expected_generation': status['generation'], 'expected_revision': status['revision'],
                     'identity_sha256': 'c' * 64, 'origin': self.origin}
        for changes in ({'expected_generation': 0}, {'expected_generation': True}, {'expected_revision': 'e' * 64},
                        {'identity_sha256': 'untrusted'}, {'origin': 'https://other.example'}):
            with self.assertRaises(recovery.RecoverySessionError):
                self.store.begin_operator_enrollment(**{**arguments, **changes})
            self.assertEqual(self.session(result)['accountId'], 1)
            self.assertEqual(self.store.operator_status(), status)

    def test_competing_begin_can_create_only_one_pending_enrollment(self):
        status = self.store.operator_status()
        barrier, results = threading.Barrier(2), []
        def begin():
            barrier.wait(timeout=3)
            try:
                result = self.store.begin_operator_enrollment(expected_generation=status['generation'], expected_revision=status['revision'],
                                                               identity_sha256='c' * 64, origin=self.origin)
                results.append(result)
            except recovery.RecoverySessionError:
                results.append(None)
        threads = [threading.Thread(target=begin) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sum(result is not None for result in results), 1)
        self.finish_enrollment(next(result for result in results if result is not None))

    def test_crash_reopen_retains_pending_revocation_until_explicit_bound_completion(self):
        pending = self.begin_enrollment()
        self.store.close()
        self.store = self.open()
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        with self.assertRaises(recovery.RecoverySessionError):
            self.challenge()
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin_enrollment()
        self.finish_enrollment(pending)

    def test_legacy_enroll_cannot_override_pending_and_revocation_invalidates_its_nonce(self):
        pending = self.begin_enrollment()
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.enroll({**self.profile, 'revision': 'e' * 64})
        self.store.revoke()
        with self.assertRaises(recovery.RecoverySessionError):
            self.finish_enrollment(pending)
        self.assertEqual(self.store.operator_status()['state'], 'revoked')
        replacement = self.begin_enrollment()
        self.finish_enrollment(replacement)

    def test_idempotent_enrollment_preserves_generation_but_each_changed_identity_advances_it(self):
        status = self.store.operator_status()
        self.store.enroll(self.profile)
        self.assertEqual(self.store.operator_status(), status)
        self.store.enroll({**self.profile, 'revision': 'c' * 64})
        self.assertEqual(self.store.operator_status()['generation'], status['generation'] + 1)

    def description(self, **changes):
        return {'schema': 'orbis.sentinel-identity-description.v1', **self.profile,
                'identitySha256': 'c' * 64, 'revision': 'd' * 64, **changes}

    def inspect_enrollment(self, pending, inspector):
        return self.store.inspect_operator_enrollment(change_token=pending['changeToken'],
                                                      expected_generation=pending['generation'], inspector=inspector)

    def test_planned_digest_is_selected_by_root_and_inspected_before_atomic_activation(self):
        pending = self.begin_enrollment()
        inspector = mock.Mock(return_value=self.description())
        result = self.inspect_enrollment(pending, inspector)
        inspector.assert_called_once_with('c' * 64)
        self.assertEqual(result['state'], 'enrolled')
        inspector.reset_mock()
        with self.assertRaises(recovery.RecoverySessionError):
            self.inspect_enrollment(pending, inspector)
        inspector.assert_not_called()

    def test_inspector_failure_or_unexpected_proof_never_activates_operator_or_leaks_a_key(self):
        key = self.prepare_key()
        self.activate_key(key)
        emergency = self.key_session(key['recoveryKey'])
        pending = self.begin_enrollment()
        with self.assertRaises(RuntimeError):
            self.inspect_enrollment(pending, mock.Mock(side_effect=RuntimeError('worker unavailable')))
        for value in (self.description(identitySha256='e' * 64), self.description(passwordHash='untrusted'),
                      self.description(schema='orbis.sentinel-authentication.v1'), self.description(accountId=True), None):
            with self.assertRaises(recovery.RecoverySessionError):
                self.inspect_enrollment(pending, mock.Mock(return_value=value))
            self.assertEqual(self.store.operator_status()['state'], 'pending')
            self.assertEqual(self.session(emergency)['principal'], 'recovery-key')
        self.inspect_enrollment(pending, lambda digest: self.description())

    def test_revocation_during_inspection_cannot_activate_a_superseded_pending_identity(self):
        pending = self.begin_enrollment()
        def inspector(digest):
            self.store.revoke()
            return self.description()
        with self.assertRaises(recovery.RecoverySessionError):
            self.inspect_enrollment(pending, inspector)
        self.assertEqual(self.store.operator_status()['state'], 'revoked')

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

    def test_expired_logout_is_atomic_idempotent_and_still_requires_the_matching_csrf(self):
        result = self.complete()
        self.now += 900_001
        with self.assertRaises(recovery.RecoverySessionError):
            self.session(result)
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.logout(token=result['token'], origin=self.origin, csrf=secrets.token_urlsafe(32))
        self.store.logout(token=result['token'], origin=self.origin, csrf=result['csrfToken'])
        self.store.logout(token=result['token'], origin=self.origin, csrf=result['csrfToken'])
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

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

    def test_shutdown_waits_for_inflight_verification_before_releasing_store_ownership(self):
        challenge = self.challenge()
        entered, release, closing, closed = (threading.Event() for _ in range(4))
        results, failures = [], []
        def verify(_digest, issued):
            entered.set()
            if not release.wait(timeout=3):
                raise RuntimeError('Verification test did not release')
            return self.proof(issued)
        def authenticate():
            try:
                results.append(self.store.complete(challenge=challenge, browser_binding=self.binding, origin=self.origin, verifier=verify))
            except recovery.RecoverySessionError:
                failures.append(True)
        def close():
            closing.set()
            self.store.close()
            closed.set()
        auth = threading.Thread(target=authenticate)
        stop = threading.Thread(target=close)
        auth.start()
        try:
            self.assertTrue(entered.wait(timeout=2))
            stop.start()
            self.assertTrue(closing.wait(timeout=2))
            self.assertFalse(closed.wait(timeout=0.05))
        finally:
            release.set()
            auth.join(timeout=3)
            if stop.ident is not None:
                stop.join(timeout=3)
        self.assertTrue(closed.is_set())
        self.assertEqual(results, [])
        self.assertEqual(failures, [True])
        self.store = self.open()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

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
