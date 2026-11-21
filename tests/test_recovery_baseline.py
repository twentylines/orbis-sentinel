"""Baseline admission port tests; actual worker crypto belongs to native QA."""

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_incarnations as incarnations
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions


class BaselineFixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='baseline-')
        self.addCleanup(self.temp.cleanup)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.origin = 'https://recovery.example'
        self.credential = secrets.token_urlsafe(16)
        self.store = sessions.RecoverySessions(self.temp.name)
        self.addCleanup(self.store.close)
        self.profiles = profiles.RecoveryProfiles(self.store, inspect=self.description, verify=lambda *args: None)
        self.addCleanup(self.profiles.close)
        self.inspector = mock.Mock(side_effect=self.content)
        self.factory = incarnations.RecoveryIncarnations(self.store, self.profiles, inspect=self.inspector, origin=self.origin)
        self.original = self.profiles.prepare(self.body('a'))
        self.store.enroll(json.loads(self.original._metadata))

    def body(self, revision='b', *, private='synthetic-private-value', account=1, origin=None, counter=3):
        return json.dumps({'revision': revision * 64, 'privateValue': private, 'accountId': account,
                           'origin': origin or self.origin, 'counter': counter}).encode()

    def read(self, directory, digest):
        body = Path(directory, 'identity.json').read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
        return json.loads(body)

    def description(self, directory, digest):
        value = self.read(directory, digest)
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest,
                'revision': value['revision'], 'accountId': value['accountId'], 'origin': value['origin'],
                'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {self.credential: value['counter']}}

    def content(self, directory, digest):
        value = self.read(directory, digest)
        bound = {key: item for key, item in value.items() if key != 'revision'}
        return {'schema': incarnations._SCHEMA, 'identitySha256': digest,
                'contentSha256': hashlib.sha256(incarnations._encoded(bound).encode()).hexdigest(),
                'description': self.description(directory, digest)}

    def check(self, body=None, **changes):
        return self.factory.check_source(body or self.body(), **{
            'expected_generation': 1, 'expected_revision': 'a' * 64, **changes})


class RecoveryBaselineTests(BaselineFixture, unittest.TestCase):
    def test_matching_full_content_allows_different_source_revision_without_changing_authority(self):
        before = self.store.operator_status()
        result = self.check()
        self.assertEqual(set(result), {'sourceSha256', 'contentSha256', 'generation', 'revision'})
        self.assertEqual(result['sourceSha256'], hashlib.sha256(self.body()).hexdigest())
        self.assertEqual(result['revision'], 'a' * 64)
        self.assertEqual(result['generation'], 1)
        self.assertEqual(self.check(), result)
        self.assertEqual(self.store.operator_status(), before)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0], 0)
        self.assertNotIn('synthetic-private-value', json.dumps(result))

    def test_root_issued_active_revision_compares_to_the_original_main_revision(self):
        token = secrets.token_urlsafe(32)
        issued = self.factory.stage(self.body(), expected_generation=1, expected_revision='a' * 64, change_token=token)
        self.factory.begin(change_token=token)
        self.factory.complete(self.body(), change_token=token, expected_generation=2)
        result = self.check(expected_generation=3, expected_revision=issued['revision'])
        self.assertEqual(result['revision'], issued['revision'])
        self.assertEqual(result['sourceSha256'], issued['sourceSha256'])
        self.assertNotEqual(result['sourceSha256'], issued['identitySha256'])

    def test_private_content_difference_is_rejected_even_when_public_metadata_matches(self):
        before = self.store.operator_status()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check(self.body(private='different-synthetic-password-hash'))
        self.assertEqual(self.store.operator_status(), before)

    def test_changed_account_realm_or_counter_cannot_pass_the_baseline_check(self):
        for body in (self.body(account=2), self.body(origin='https://other.example'), self.body(counter=4)):
            with self.subTest(source=hashlib.sha256(body).hexdigest()):
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.check(body)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_invalid_generation_revision_and_stale_expected_values_refuse(self):
        for change in ({'expected_generation': True}, {'expected_generation': -1}, {'expected_generation': 2},
                       {'expected_revision': None}, {'expected_revision': 'A' * 64}, {'expected_revision': 'c' * 64}):
            with self.subTest(fields=change):
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.check(**change)
        self.assertFalse(self.inspector.called)

    def test_pending_and_revoked_authority_never_count_as_a_matching_baseline(self):
        token = secrets.token_urlsafe(32)
        self.factory.stage(self.body(), expected_generation=1, expected_revision='a' * 64, change_token=token)
        self.factory.begin(change_token=token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check(expected_generation=2)
        self.store.revoke_operator(expected_generation=2, expected_revision=None)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check(expected_generation=3)
        self.assertEqual(self.store.operator_status()['state'], 'revoked')

    def test_never_enrolled_store_requires_a_separate_bootstrap(self):
        with tempfile.TemporaryDirectory(prefix='baseline-new-') as directory:
            store = sessions.RecoverySessions(directory)
            custody = profiles.RecoveryProfiles(store, inspect=self.description, verify=lambda *args: None)
            try:
                factory = incarnations.RecoveryIncarnations(store, custody, inspect=self.content, origin=self.origin)
                with self.assertRaises(profiles.RecoveryProfileError):
                    factory.check_source(self.body(), expected_generation=0, expected_revision='a' * 64)
                self.assertEqual(store.operator_status()['state'], 'never-enrolled')
            finally:
                custody.close()
                store.close()

    def test_advanced_missing_or_malformed_root_counter_floor_holds_without_rewriting_it(self):
        for counter in (4, 2, b'invalid'):
            with self.subTest(counter_type=type(counter).__name__):
                self.store._db.execute('UPDATE counters SET counter=? WHERE credential=?', (counter, self.credential))
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.check()
                self.assertEqual(self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (self.credential,)).fetchone()[0], counter)
        self.store._db.execute('DELETE FROM counters WHERE credential=?', (self.credential,))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_revoke_during_worker_execution_prevents_successful_baseline_receipt(self):
        def revoke(directory, digest):
            self.inspector.side_effect = self.content
            self.store.revoke_operator(expected_generation=1, expected_revision='a' * 64)
            return self.content(directory, digest)
        self.inspector.side_effect = revoke
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.assertEqual(self.store.operator_status()['state'], 'revoked')

    def test_counter_advancing_during_worker_execution_is_detected_on_final_read(self):
        def advance(directory, digest):
            self.inspector.side_effect = self.content
            self.store._db.execute('UPDATE counters SET counter=4 WHERE credential=?', (self.credential,))
            return self.content(directory, digest)
        self.inspector.side_effect = advance
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.assertEqual(self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (self.credential,)).fetchone()[0], 4)

    def test_active_retained_material_and_stored_enrollment_must_describe_the_same_profile(self):
        original = json.loads(self.original._metadata)
        changed = {**original, 'accountId': 2}
        self.store._db.execute('UPDATE identities SET profile=? WHERE active=1', (json.dumps(changed),))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.assertEqual(self.store._db.execute('SELECT profile FROM identities WHERE active=1').fetchone()[0], json.dumps(changed))

    def test_modified_active_file_or_invalid_worker_proof_is_never_admitted(self):
        real = self.content
        self.inspector.side_effect = lambda directory, digest: {**real(directory, digest), 'contentSha256': None}
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.inspector.side_effect = real
        Path(self.temp.name, 'profiles', self.original.digest, 'identity.json').write_bytes(self.body('c'))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.check()
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_root_control_is_exact_and_check_preserves_an_existing_key_session(self):
        key = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=key['revision'], recovery_key=key['recoveryKey'], expected_revision=None)
        binding = secrets.token_urlsafe(32)
        challenge = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)
        session = self.store.complete_recovery_key(challenge=challenge['challenge'], origin=self.origin,
                                                  browser_binding=binding, recovery_key=key['recoveryKey'])
        app = control.RecoveryControl(sessions=self.store, profiles=self.profiles, origin=self.origin, incarnations=self.factory)
        args = {'identityBase64': base64.b64encode(self.body()).decode(), 'expectedGeneration': 1, 'expectedRevision': 'a' * 64}
        def call(arguments):
            return app.handle({'schema': control._SCHEMA, 'operation': 'operator-check-source', 'arguments': arguments})
        self.assertTrue(call(args)['ok'])
        self.assertEqual(set(call(args)['result']), {'sourceSha256', 'contentSha256', 'generation', 'revision'})
        for invalid in ({**args, 'changeToken': secrets.token_urlsafe(32)}, {**args, 'expectedRevision': None},
                        {**args, 'expectedGeneration': False}, {**args, 'identityBase64': 'not base64'},
                        {key: value for key, value in args.items() if key != 'expectedGeneration'}):
            self.assertFalse(call(invalid)['ok'])
        disabled = control.RecoveryControl(sessions=self.store, profiles=self.profiles, origin=self.origin)
        self.assertFalse(disabled.handle({'schema': control._SCHEMA, 'operation': 'operator-check-source', 'arguments': args})['ok'])
        self.assertEqual(self.store.session(token=session['token'], origin=self.origin, touch=False)['method'], 'recovery-key')


if __name__ == '__main__':
    unittest.main()
