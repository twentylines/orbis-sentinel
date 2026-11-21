"""Supervisor retry receipts do not establish Main credential-writer quiescence."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as recovery


class PreparedBeginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='prepared-')
        self.addCleanup(self.temp.cleanup)
        for module in (recovery, control):
            patch = mock.patch.object(module, '_OWNER_UID', os.getuid())
            patch.start()
            self.addCleanup(patch.stop)
        self.origin = 'https://recovery.example'
        self.old = {'identitySha256': 'a' * 64, 'revision': 'b' * 64, 'accountId': 1,
                    'origin': self.origin, 'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {}}
        self.target = {**self.old, 'identitySha256': 'c' * 64, 'revision': 'd' * 64}
        self.token = secrets.token_urlsafe(32)
        self.store = self.open()
        self.store.enroll(self.old)
        self.arguments = dict(expected_generation=1, expected_revision=self.old['revision'],
                              identity_sha256=self.target['identitySha256'], origin=self.origin, change_token=self.token)

    def open(self):
        store = recovery.RecoverySessions(self.temp.name)
        self.addCleanup(store.close)
        return store

    def begin(self, **changes):
        return self.store.begin_prepared_operator_enrollment(**{**self.arguments, **changes})

    def test_lost_response_retry_survives_restart_and_never_persists_raw_token(self):
        self.assertEqual(self.begin(), {'generation': 2})
        self.store.close()
        self.store = self.open()
        self.assertEqual(self.begin(), {'generation': 2})
        self.assertEqual(self.store.operator_status(), {'generation': 2, 'revision': None, 'state': 'pending'})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 1)
        self.assertNotIn(self.token.encode(), Path(self.temp.name, 'recovery.sqlite3').read_bytes())
        self.assertNotIn(self.token, json.dumps([tuple(r) for r in self.store._db.execute('SELECT * FROM operator_prepared_begins')]))
        self.assertEqual(self.store.complete_operator_enrollment(self.target, expected_generation=2, change_token=self.token)['revision'], self.target['revision'])

    def test_every_changed_argument_refuses_and_leaves_the_exact_pending_operation(self):
        self.begin()
        for changes in ({'expected_generation': 2}, {'expected_revision': None}, {'identity_sha256': 'e' * 64},
                        {'origin': 'https://other.example'}, {'change_token': secrets.token_urlsafe(32)}):
            with self.subTest(fields=list(changes)):
                with self.assertRaises(recovery.RecoverySessionError):
                    self.begin(**changes)
                self.assertEqual(self.store.operator_status()['generation'], 2)
        self.assertEqual(self.begin(), {'generation': 2})

    def test_completed_revoked_and_superseded_receipts_never_restart_enrollment(self):
        self.begin()
        self.store.complete_operator_enrollment(self.target, expected_generation=2, change_token=self.token)
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin()
        self.store.revoke_operator(expected_generation=3, expected_revision=self.target['revision'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin()
        next_token = secrets.token_urlsafe(32)
        next_args = {**self.arguments, 'expected_generation': 4, 'expected_revision': None,
                     'identity_sha256': 'e' * 64, 'change_token': next_token}
        self.assertEqual(self.store.begin_prepared_operator_enrollment(**next_args), {'generation': 5})
        # The original token remains consumed even after a different receipt exists.
        self.store.revoke_operator(expected_generation=5, expected_revision=None)
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin(expected_generation=6, expected_revision=None)
        self.assertEqual(self.store.operator_status()['generation'], 6)

    def test_legacy_pending_change_cannot_be_adopted_as_a_prepared_retry(self):
        legacy = self.store.begin_operator_enrollment(**{key: value for key, value in self.arguments.items() if key != 'change_token'})
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin(change_token=legacy['changeToken'])
        self.assertEqual(self.store.operator_status()['generation'], 2)
        self.store.complete_operator_enrollment(self.target, expected_generation=2, change_token=legacy['changeToken'])

    def test_invalid_token_and_capacity_hold_before_revoking_current_authority(self):
        for token in (None, True, '', 'x' * 42, '=' * 43, 'x' * 43):
            with self.subTest(token_type=type(token).__name__):
                with self.assertRaises(recovery.RecoverySessionError):
                    self.begin(change_token=token)
        self.store._db.executemany('INSERT INTO operator_prepared_begins VALUES (?,?,?)',
                                  [(hashlib.sha256(str(i).encode()).hexdigest(), 'f' * 64, i + 1) for i in range(1024)])
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin()
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': self.old['revision'], 'state': 'enrolled'})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 1024)

    def test_exact_retry_still_succeeds_at_receipt_capacity(self):
        self.begin()
        self.store._db.executemany('INSERT INTO operator_prepared_begins VALUES (?,?,?)',
                                  [(hashlib.sha256(str(i).encode()).hexdigest(), 'f' * 64, i + 1) for i in range(1023)])
        self.assertEqual(self.begin(), {'generation': 2})

    def test_legacy_store_migration_preserves_enrollment_and_adds_only_receipts(self):
        self.store.close()
        database = Path(self.temp.name, 'recovery.sqlite3')
        with closing(sqlite3.connect(database)) as old, old:
            old.execute('DROP TABLE operator_prepared_begins')
        self.store = self.open()
        self.assertEqual(self.store.operator_status()['revision'], self.old['revision'])
        self.assertEqual(self.begin(), {'generation': 2})

    def test_root_control_reinspects_profile_and_preserves_key_session_on_retry(self):
        key = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=key['revision'], recovery_key=key['recoveryKey'], expected_revision=None)
        binding = secrets.token_urlsafe(32)
        challenge = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)
        session = self.store.complete_recovery_key(challenge=challenge['challenge'], origin=self.origin,
                                                   browser_binding=binding, recovery_key=key['recoveryKey'])
        body = b'{"syntheticPreparedIdentity":true}'
        digest = hashlib.sha256(body).hexdigest()
        target = {**self.target, 'identitySha256': digest}
        inspector = mock.Mock(return_value={'schema': 'orbis.sentinel-identity-description.v1', **target})
        custody = profiles.RecoveryProfiles(self.store, inspect=inspector, verify=mock.Mock())
        self.addCleanup(custody.close)
        app = control.RecoveryControl(sessions=self.store, profiles=custody, origin=self.origin)
        def call(operation, arguments):
            return app.handle({'schema': control._SCHEMA, 'operation': operation, 'arguments': arguments})
        self.assertTrue(call('operator-stage', {'identityBase64': base64.b64encode(body).decode()})['ok'])
        args = {'expectedGeneration': 1, 'expectedRevision': self.old['revision'], 'identitySha256': digest, 'changeToken': self.token}
        first = call('operator-begin-prepared', args)
        self.assertEqual(first['result'], {'generation': 2})
        self.assertEqual(call('operator-begin-prepared', args), first)
        self.assertNotIn(self.token, json.dumps(first))
        self.assertFalse(call('operator-begin-prepared', {**args, 'changeToken': None})['ok'])
        self.assertEqual(self.store.session(token=session['token'], origin=self.origin, touch=False)['method'], 'recovery-key')
        inspector.return_value = {**inspector.return_value, 'origin': 'https://other.example'}
        self.assertFalse(call('operator-begin-prepared', args)['ok'])
        self.assertEqual(self.store.operator_status()['generation'], 2)
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def test_concurrent_exact_requests_create_one_pending_receipt(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.begin(), range(2)))
        self.assertEqual(results, [{'generation': 2}, {'generation': 2}])
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 1)
        self.assertEqual(self.store.operator_status()['generation'], 2)

    def test_concurrent_different_tokens_cannot_both_begin_from_one_baseline(self):
        def attempt(token):
            try:
                return self.begin(change_token=token)
            except recovery.RecoverySessionError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [self.token, secrets.token_urlsafe(32)]))
        self.assertEqual(results.count({'generation': 2}), 1)
        self.assertEqual(results.count(None), 1)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 1)

    def test_receipt_insert_and_commit_failure_roll_back_revocation_atomically(self):
        self.store._db.execute("CREATE TRIGGER refuse_receipt BEFORE INSERT ON operator_prepared_begins BEGIN SELECT RAISE(ABORT, 'fixture refusal'); END")
        with self.assertRaises(sqlite3.DatabaseError):
            self.begin()
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': self.old['revision'], 'state': 'enrolled'})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 0)
        self.store._db.execute('DROP TRIGGER refuse_receipt')
        def deny_commit(action, first, *_):
            return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and first == 'COMMIT' else sqlite3.SQLITE_OK
        self.store._db.set_authorizer(deny_commit)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                self.begin()
        finally:
            self.store._db.set_authorizer(None)
        self.store.close()
        self.store = self.open()
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': self.old['revision'], 'state': 'enrolled'})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 0)

    def test_invalid_generation_and_corrupt_receipt_refuse_without_repair(self):
        for generation in (True, 1.0, -1, 9_007_199_254_740_989):
            with self.subTest(generation_type=type(generation).__name__):
                with self.assertRaises(recovery.RecoverySessionError):
                    self.begin(expected_generation=generation)
        self.assertEqual(self.store.operator_status()['revision'], self.old['revision'])
        self.begin()
        self.store._db.execute("UPDATE operator_prepared_begins SET request='corrupt'")
        with self.assertRaises(recovery.RecoverySessionError):
            self.begin()
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        self.assertEqual(self.store._db.execute('SELECT request FROM operator_prepared_begins').fetchone()[0], 'corrupt')

    def test_inactive_revision_antirollback_guard_is_unchanged(self):
        self.begin(identity_sha256=self.old['identitySha256'])
        with self.assertRaises(recovery.RecoverySessionError):
            self.store.complete_operator_enrollment(self.old, expected_generation=2, change_token=self.token)
        self.assertEqual(self.store.operator_status()['state'], 'pending')
