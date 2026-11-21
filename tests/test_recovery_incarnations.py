"""Root protocol proof; the inspector fixture is not a native crypto claim."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_incarnations as incarnations
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions


class IncarnationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='incarnation-')
        self.addCleanup(self.temp.cleanup)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.origin = 'https://recovery.example'
        self.token = secrets.token_urlsafe(32)
        self.open()
        self.original = self.profiles.prepare(self.body('a'))
        self.store.enroll(json.loads(self.original._metadata))

    def body(self, revision, secret='synthetic-private-value', origin=None):
        return json.dumps({'revision': revision * 64, 'passwordHash': secret,
                           'origin': origin or self.origin, 'counter': 3}).encode()

    def read(self, directory, digest):
        body = Path(directory, 'identity.json').read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        return json.loads(body)

    def description(self, directory, digest):
        value = self.read(directory, digest)
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest,
                'revision': value['revision'], 'accountId': 1, 'origin': value['origin'],
                'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {}}

    def content(self, directory, digest):
        value = self.read(directory, digest)
        content = {key: item for key, item in value.items() if key != 'revision'}
        return {'schema': incarnations._SCHEMA, 'identitySha256': digest,
                'contentSha256': hashlib.sha256(incarnations._encoded(content).encode()).hexdigest(),
                'description': self.description(directory, digest)}

    def open(self):
        self.store = sessions.RecoverySessions(self.temp.name)
        self.addCleanup(self.store.close)
        self.profiles = profiles.RecoveryProfiles(self.store, inspect=self.description, verify=lambda *args: None)
        self.addCleanup(self.profiles.close)
        self.inspect = mock.Mock(side_effect=self.content)
        self.factory = incarnations.RecoveryIncarnations(self.store, self.profiles, inspect=self.inspect, origin=self.origin)

    def stage(self, body=None, **changes):
        args = dict(expected_generation=1, expected_revision='a' * 64, change_token=self.token)
        return self.factory.stage(body or self.body('b'), **{**args, **changes})

    def complete(self, body=None, generation=2):
        return self.factory.complete(body or self.body('b'), change_token=self.token, expected_generation=generation)

    def test_same_content_can_return_after_retirement_with_new_root_revision(self):
        first = self.stage(self.body('a'))
        self.assertNotEqual(first['revision'], 'a' * 64)
        self.assertNotEqual(first['sourceSha256'], first['identitySha256'])
        self.assertEqual(self.factory.begin(change_token=self.token), {'generation': 2})
        self.assertEqual(self.complete(self.body('a'))['revision'], first['revision'])
        self.assertEqual(self.store._db.execute('SELECT active FROM identities WHERE revision=?', ('a' * 64,)).fetchone()[0], 0)
        with self.assertRaises(sessions.RecoverySessionError):
            self.store.enroll(json.loads(self.original._metadata))
        token = secrets.token_urlsafe(32)
        second = self.stage(self.body('a'), expected_generation=3, expected_revision=first['revision'], change_token=token)
        self.assertNotEqual(first['revision'], second['revision'])
        self.assertEqual(self.factory.begin(change_token=token), {'generation': 4})
        self.assertEqual(self.factory.complete(self.body('a'), change_token=token, expected_generation=4)['revision'], second['revision'])

    def test_exact_stage_retry_and_pending_retry_survive_restart_without_raw_token(self):
        first = self.stage()
        self.assertEqual(self.stage(), first)
        self.factory.begin(change_token=self.token)
        self.profiles.close()
        self.store.close()
        self.open()
        self.assertEqual(self.stage(), first)
        self.assertEqual(self.factory.begin(change_token=self.token), {'generation': 2})
        self.assertNotIn(self.token.encode(), Path(self.temp.name, 'recovery.sqlite3').read_bytes())
        self.assertEqual(self.complete()['revision'], first['revision'])
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)

    def test_mapping_commits_before_candidate_and_retry_reuses_incarnation(self):
        real = self.profiles.prepare
        def prepare(body):
            if json.loads(body)['revision'] != 'b' * 64:
                raise RuntimeError('Synthetic disk failure')
            return real(body)
        with mock.patch.object(self.profiles, 'prepare', side_effect=prepare):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.stage()
        row = self.store._db.execute('SELECT record FROM operator_incarnations').fetchone()
        self.assertIsNotNone(row)
        recorded = json.loads(row['record'])
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        retried = self.stage()
        self.assertEqual(retried['revision'], recorded['revision'])
        self.assertEqual(retried['identitySha256'], recorded['target'])

    def test_changed_source_baseline_or_realm_cannot_reuse_operation(self):
        first = self.stage()
        for body, changes in ((self.body('b', 'changed'), {}), (self.body('c'), {}), (None, {'expected_generation': 2}),
                              (None, {'expected_revision': None}), (self.body('b', origin='https://other.example'), {})):
            with self.subTest(changes=changes):
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.stage(body, **changes)
        self.assertEqual(self.stage(), first)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_existing_prepared_token_cannot_be_reserved_or_reserved_token_retargeted(self):
        receipt = self.stage()
        with self.assertRaises(sessions.RecoverySessionError):
            self.store.begin_prepared_operator_enrollment(expected_generation=1, expected_revision='a' * 64,
                identity_sha256=self.original.digest, origin=self.origin, change_token=self.token)
        self.factory.begin(change_token=self.token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage(self.body('c'))
        self.assertEqual(self.complete()['revision'], receipt['revision'])
        next_token = secrets.token_urlsafe(32)
        self.store.begin_prepared_operator_enrollment(expected_generation=3, expected_revision=receipt['revision'],
            identity_sha256=self.original.digest, origin=self.origin, change_token=next_token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage(expected_generation=3, expected_revision=receipt['revision'], change_token=next_token)

    def test_complete_requires_exact_fresh_source_and_refuses_legacy_bypass(self):
        receipt = self.stage()
        self.factory.begin(change_token=self.token)
        candidate = self.profiles.inspect_retained(receipt['identitySha256'])
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.complete(candidate, change_token=self.token, expected_generation=2)
        for body in (self.body('b', 'changed'), self.body('a'), Path(self.temp.name, 'profiles', candidate.digest, 'identity.json').read_bytes()):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.complete(body)
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        self.assertEqual(self.complete()['revision'], receipt['revision'])

    def test_changed_content_proof_or_changed_candidate_cannot_begin(self):
        receipt = self.stage()
        def changed(directory, digest):
            value = self.content(directory, digest)
            if digest == receipt['identitySha256']:
                value['contentSha256'] = 'f' * 64
            return value
        self.inspect.side_effect = changed
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.inspect.side_effect = self.content
        target = Path(self.temp.name, 'profiles', receipt['identitySha256'], 'identity.json')
        target.write_bytes(self.body('d'))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_racing_revoke_during_stage_or_complete_prevents_success(self):
        def revoke(directory, digest):
            self.inspect.side_effect = self.content
            self.store.revoke_operator(expected_generation=1, expected_revision='a' * 64)
            return self.content(directory, digest)
        self.inspect.side_effect = revoke
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage()
        self.assertEqual(self.store.operator_status()['generation'], 2)
        self.stage(expected_generation=2, expected_revision=None)
        self.factory.begin(change_token=self.token)
        def revoke_pending(directory, digest):
            self.inspect.side_effect = self.content
            self.store.revoke_operator(expected_generation=3, expected_revision=None)
            return self.content(directory, digest)
        self.inspect.side_effect = revoke_pending
        with self.assertRaises(profiles.RecoveryProfileError):
            self.complete(generation=3)
        self.assertEqual(self.store.operator_status()['state'], 'revoked')

    def test_concurrent_exact_stage_has_one_mapping_and_candidate(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.stage(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0], 1)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_capacity_refuses_before_revocation_and_exact_retry_does_not_allocate(self):
        first = self.stage()
        with mock.patch.object(incarnations, '_MAX', 1):
            self.assertEqual(self.stage(), first)
            with self.assertRaises(profiles.RecoveryProfileError):
                self.stage(change_token=secrets.token_urlsafe(32))
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_corrupt_mapping_and_inactive_revision_collision_refuse(self):
        self.stage()
        self.store._db.execute("UPDATE operator_incarnations SET record='{}'")
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        with mock.patch.object(incarnations, '_revision', return_value='a' * 64):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.stage(change_token=secrets.token_urlsafe(32))

    def test_root_control_accepts_only_exact_incarnation_fields_and_returns_no_private_material(self):
        import base64
        app = control.RecoveryControl(sessions=self.store, profiles=self.profiles, origin=self.origin, incarnations=self.factory)
        args = {'identityBase64': base64.b64encode(self.body('b')).decode(), 'expectedGeneration': 1,
                'expectedRevision': 'a' * 64, 'changeToken': self.token}
        def call(operation, arguments):
            return app.handle({'schema': control._SCHEMA, 'operation': operation, 'arguments': arguments})
        receipt = call('operator-stage-incarnation', args)
        self.assertTrue(receipt['ok'])
        self.assertNotIn(self.token, json.dumps(receipt))
        self.assertNotIn('synthetic-private-value', json.dumps(receipt))
        self.assertFalse(call('operator-stage-incarnation', {**args, 'revision': 'f' * 64})['ok'])
        self.assertTrue(call('operator-begin-incarnation', {'changeToken': self.token})['ok'])
        self.assertTrue(call('operator-complete-incarnation', {key: value for key, value in {**args, 'expectedGeneration': 2}.items() if key != 'expectedRevision'})['ok'])
        self.assertFalse(call('operator-stage-incarnation', args)['ok'])

    def test_older_store_migration_adds_table_without_rotating_operator(self):
        self.profiles.close()
        self.store.close()
        with sqlite3.connect(Path(self.temp.name, 'recovery.sqlite3')) as old:
            old.execute('DROP TABLE operator_incarnations')
        old.close()
        self.open()
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.assertTrue(self.stage()['revision'])

    def test_sqlite_reservation_failure_leaves_no_mapping_or_revocation(self):
        self.store._db.execute("CREATE TRIGGER refuse_incarnation BEFORE INSERT ON operator_incarnations BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0], 0)
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': 'a' * 64, 'state': 'enrolled'})
        self.store._db.execute('DROP TRIGGER refuse_incarnation')
        self.assertTrue(self.stage()['revision'])

    def test_key_session_survives_staging_begin_completion_and_failed_source_proof(self):
        key = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=key['revision'], recovery_key=key['recoveryKey'], expected_revision=None)
        binding = secrets.token_urlsafe(32)
        challenge = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)
        session = self.store.complete_recovery_key(challenge=challenge['challenge'], origin=self.origin,
                                                  browser_binding=binding, recovery_key=key['recoveryKey'])
        self.stage()
        self.factory.begin(change_token=self.token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.complete(self.body('a'))
        self.assertEqual(self.store.session(token=session['token'], origin=self.origin, touch=False)['method'], 'recovery-key')
        self.complete()
        self.assertEqual(self.store.session(token=session['token'], origin=self.origin, touch=False)['method'], 'recovery-key')

    def test_failed_mutation_requires_retirement_then_fresh_incarnation_for_unchanged_source(self):
        self.stage()
        self.factory.begin(change_token=self.token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.complete(self.body('a'))
        self.store.revoke_operator(expected_generation=2, expected_revision=None)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage(self.body('a'), expected_generation=3, expected_revision=None)
        token = secrets.token_urlsafe(32)
        restored = self.stage(self.body('a'), expected_generation=3, expected_revision=None, change_token=token)
        self.factory.begin(change_token=token)
        self.assertEqual(self.factory.complete(self.body('a'), change_token=token, expected_generation=4)['revision'], restored['revision'])

    def test_worker_proof_schema_digest_and_description_are_all_bound(self):
        for field, value in (('schema', 'different'), ('identitySha256', 'f' * 64), ('contentSha256', None), ('description', {})):
            def changed(directory, digest):
                return {**self.content(directory, digest), field: value}
            self.inspect.side_effect = changed
            with self.assertRaises(profiles.RecoveryProfileError):
                self.stage()
            self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0], 0)

    def test_changed_secret_then_original_source_gets_distinct_issued_revisions(self):
        changed = self.body('b', 'synthetic-new-secret')
        first = self.stage(changed)
        self.factory.begin(change_token=self.token)
        self.assertEqual(self.complete(changed)['revision'], first['revision'])
        token = secrets.token_urlsafe(32)
        original = self.body('a')
        restored = self.stage(original, expected_generation=3, expected_revision=first['revision'], change_token=token)
        self.assertNotEqual(first['contentSha256'], restored['contentSha256'])
        self.assertNotIn(restored['revision'], ('a' * 64, first['revision']))
        self.factory.begin(change_token=token)
        self.assertEqual(self.factory.complete(original, change_token=token, expected_generation=4)['revision'], restored['revision'])

    def test_actual_sqlite_commit_failure_rolls_back_reservation(self):
        self.store._db.execute('PRAGMA foreign_keys=ON')
        self.store._db.executescript('''
          CREATE TABLE fixture_parent(id INTEGER PRIMARY KEY);
          CREATE TABLE fixture_child(parent INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED);
          CREATE TRIGGER fixture_commit_failure AFTER INSERT ON operator_incarnations
          BEGIN INSERT INTO fixture_child VALUES (1); END;
        ''')
        with self.assertRaises(profiles.RecoveryProfileError):
            self.stage()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0], 0)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM fixture_child').fetchone()[0], 0)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.store._db.execute('DROP TRIGGER fixture_commit_failure')
        self.assertTrue(self.stage()['revision'])


if __name__ == '__main__':
    unittest.main()
