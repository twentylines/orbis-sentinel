"""Atomic managed-writer admission; worker callbacks are labeled port fixtures."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import unittest
from unittest import mock

import test_recovery_baseline as baseline_fixture
from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_incarnations as incarnations
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions


class RecoveryWriterPrepareTests(baseline_fixture.BaselineFixture, unittest.TestCase):
    def body(self, revision='b', *, private='synthetic-private-value', account=1, origin=None, counter=3, credentials=None):
        return json.dumps({'revision': revision * 64, 'privateValue': private, 'accountId': account,
                           'origin': origin or self.origin, 'counter': counter,
                           'credentials': credentials if credentials is not None else [{'id': self.credential, 'counter': counter}]}).encode()

    def description(self, directory, digest):
        value = self.read(directory, digest)
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest,
                'revision': value['revision'], 'accountId': value['accountId'], 'origin': value['origin'],
                'totpEnabled': False, 'requireTotpAfterPasskey': False,
                'credentials': {key['id']: key['counter'] for key in value['credentials']}}

    def setUp(self):
        super().setUp()
        self.token = secrets.token_urlsafe(32)
        self.before = self.body('b')
        self.planned = self.body('c', private='synthetic-new-password')

    def prepare(self, **changes):
        values = {'baseline_bytes': self.before, 'identity_bytes': self.planned,
                  'expected_generation': 1, 'expected_revision': 'a' * 64, 'change_token': self.token, **changes}
        return self.factory.prepare_writer(**values)

    def test_combined_prepare_reserves_before_revocation_and_returns_only_exact_receipt(self):
        result = self.prepare()
        self.assertEqual(set(result), {'baselineSha256', 'sourceSha256', 'identitySha256', 'revision', 'contentSha256', 'generation'})
        self.assertEqual(result['baselineSha256'], hashlib.sha256(self.before).hexdigest())
        self.assertEqual(result['sourceSha256'], hashlib.sha256(self.planned).hexdigest())
        self.assertEqual(result['generation'], 2)
        self.assertNotEqual(result['identitySha256'], result['sourceSha256'])
        self.assertEqual(self.store.operator_status(), {'generation': 2, 'revision': None, 'state': 'pending'})
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0], 1)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 1)
        self.assertNotIn(self.token, json.dumps(result))
        self.assertNotIn(self.token.encode(), Path(self.temp.name, 'recovery.sqlite3').read_bytes())
        self.assertNotIn('synthetic-new-password', json.dumps(result))
        completed = self.factory.complete(self.planned, change_token=self.token, expected_generation=2)
        self.assertEqual(completed['revision'], result['revision'])

    def test_lost_response_retry_reinspects_and_preserves_the_exact_pending_generation(self):
        first = self.prepare()
        self.inspector.reset_mock()
        second = self.prepare()
        self.assertEqual(second, first)
        self.assertGreaterEqual(self.inspector.call_count, 3)
        self.assertEqual(self.store.operator_status()['generation'], 2)
        self.profiles.close()
        self.store.close()
        self.store = sessions.RecoverySessions(self.temp.name)
        self.addCleanup(self.store.close)
        self.profiles = profiles.RecoveryProfiles(self.store, inspect=self.description, verify=lambda *args: None)
        self.addCleanup(self.profiles.close)
        self.factory = incarnations.RecoveryIncarnations(self.store, self.profiles, inspect=self.inspector, origin=self.origin)
        self.assertEqual(self.prepare(), first)

    def test_counter_advance_immediately_before_begin_is_checked_inside_revoke_transaction(self):
        begin = self.profiles.begin
        def advance(*args, **kwargs):
            self.store._db.execute('UPDATE counters SET counter=4 WHERE credential=?', (self.credential,))
            return begin(*args, **kwargs)
        with mock.patch.object(self.profiles, 'begin', side_effect=advance):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.prepare()
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': 'a' * 64, 'state': 'enrolled'})
        self.assertEqual(self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (self.credential,)).fetchone()[0], 4)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0], 0)

    def test_changed_baseline_planned_account_or_surviving_counter_is_rejected_before_revoke(self):
        for changes in ({'baseline_bytes': self.body('b', private='stale-main')},
                        {'identity_bytes': self.body('c', account=2)},
                        {'identity_bytes': self.body('c', counter=4)},
                        {'identity_bytes': self.body('c', counter=2)}):
            with self.subTest(fields=list(changes)):
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.prepare(**changes)
                self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0], 0)

    def test_key_removal_and_new_key_admission_do_not_rewrite_surviving_counters(self):
        new_key = {'id': 'bmV3LWNyZWRlbnRpYWw', 'counter': 1}
        planned = self.body('c', credentials=[{'id': self.credential, 'counter': 3}, new_key])
        result = self.prepare(identity_bytes=planned)
        self.assertEqual(result['generation'], 2)
        self.factory.complete(planned, change_token=self.token, expected_generation=2)
        next_token = secrets.token_urlsafe(32)
        removal = self.body('d', credentials=[new_key])
        prepared = self.factory.prepare_writer(planned, removal, expected_generation=3,
            expected_revision=result['revision'], change_token=next_token)
        self.assertEqual(prepared['generation'], 4)
        self.assertEqual(self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (self.credential,)).fetchone()[0], 3)

    def test_request_binding_cannot_change_on_retry(self):
        first = self.prepare()
        for changes in ({'baseline_bytes': self.body('d')}, {'identity_bytes': self.body('e')},
                        {'expected_generation': 2}, {'expected_revision': 'f' * 64},
                        {'change_token': secrets.token_urlsafe(32)}):
            with self.subTest(fields=list(changes)):
                with self.assertRaises(profiles.RecoveryProfileError):
                    self.prepare(**changes)
                self.assertEqual(self.store.operator_status()['generation'], 2)
        self.assertEqual(self.prepare(), first)

    def test_writer_reservation_is_durable_before_stage_and_cannot_be_adopted_by_legacy_begin(self):
        stage = self.factory.stage
        with mock.patch.object(self.factory, 'stage', side_effect=RuntimeError('synthetic stage unavailable')):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.prepare()
        token = sessions._token(self.token)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests WHERE token=?', (token,)).fetchone()[0], 1)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        # Stage is allowed to finish, but its old begin API cannot supply the
        # process-local baseline and inspected request witnesses.
        receipt = stage(self.planned, expected_generation=1, expected_revision='a' * 64, change_token=self.token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)
        raw = self.profiles.inspect_retained(receipt['sourceSha256'])
        issued = self.profiles.inspect_retained(receipt['identitySha256'])
        for target in (raw, issued):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.profiles.begin(target, expected_generation=1, expected_revision='a' * 64)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.assertEqual(self.prepare()['generation'], 2)

    def test_old_begin_cannot_ack_even_an_exact_writer_pending_without_reinspection_witness(self):
        receipt = self.prepare()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=self.token)
        with self.assertRaises(sessions.RecoverySessionError):
            self.store.begin_prepared_operator_enrollment(expected_generation=1, expected_revision='a' * 64,
                identity_sha256=receipt['identitySha256'], origin=self.origin, change_token=self.token)
        self.assertEqual(self.prepare(), receipt)

    def test_reserved_incarnation_target_cannot_be_aliased_through_a_different_legacy_token(self):
        staged = self.factory.stage(self.planned, expected_generation=1, expected_revision='a' * 64, change_token=self.token)
        target = self.profiles.inspect_retained(staged['identitySha256'])
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.begin(target, expected_generation=1, expected_revision='a' * 64)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        alias = secrets.token_urlsafe(32)
        # Simulate a pending alias saved by an older implementation; even then
        # completion must not skip the owning incarnation's source proof.
        self.store._db.execute('UPDATE identities SET active=0')
        self.store._db.execute('UPDATE operator_enrollment SET generation=2,nonce=?,target=?,origin=? WHERE id=1',
                               (sessions._token(alias), target.digest, self.origin))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.profiles.complete(target, expected_generation=2, change_token=alias)
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def test_completed_and_revoked_writer_requests_never_reopen(self):
        first = self.prepare()
        self.factory.complete(self.planned, change_token=self.token, expected_generation=2)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.prepare()
        self.store.revoke_operator(expected_generation=3, expected_revision=first['revision'])
        with self.assertRaises(profiles.RecoveryProfileError):
            self.prepare()
        self.assertEqual(self.store.operator_status()['state'], 'revoked')

    def test_existing_nonwriter_incarnation_cannot_be_reclassified_as_a_writer_request(self):
        self.factory.stage(self.planned, expected_generation=1, expected_revision='a' * 64, change_token=self.token)
        with self.assertRaises(profiles.RecoveryProfileError):
            self.prepare()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0], 0)

    def test_historical_writer_source_can_recur_only_through_a_new_combined_baseline(self):
        first = self.prepare()
        self.factory.complete(self.planned, change_token=self.token, expected_generation=2)
        revert_token = secrets.token_urlsafe(32)
        reverted = self.factory.prepare_writer(self.planned, self.before, expected_generation=3,
            expected_revision=first['revision'], change_token=revert_token)
        self.assertEqual(reverted['generation'], 4)
        self.factory.complete(self.before, change_token=revert_token, expected_generation=4)
        # Reuse the first operation's exact planned bytes with a new current
        # baseline and token; historical source ownership must not forbid this.
        repeated_token = secrets.token_urlsafe(32)
        repeated = self.factory.prepare_writer(self.before, self.planned, expected_generation=5,
            expected_revision=reverted['revision'], change_token=repeated_token)
        self.assertEqual(repeated['sourceSha256'], first['sourceSha256'])
        self.assertNotEqual(repeated['revision'], first['revision'])
        self.factory.complete(self.planned, change_token=repeated_token, expected_generation=6)
        self.assertEqual(self.store.operator_status()['generation'], 7)

    def test_writer_reserved_source_refuses_legacy_remint_and_preexisting_legacy_alias(self):
        legacy_token = secrets.token_urlsafe(32)
        legacy = self.factory.stage(self.planned, expected_generation=1, expected_revision='a' * 64, change_token=legacy_token)
        with mock.patch.object(self.factory, 'stage', side_effect=RuntimeError('synthetic stage unavailable')):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.prepare()
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.stage(self.planned, expected_generation=1, expected_revision='a' * 64,
                               change_token=secrets.token_urlsafe(32))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.begin(change_token=legacy_token)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
        self.store._db.execute('UPDATE identities SET active=0')
        self.store._db.execute('UPDATE operator_enrollment SET generation=2,nonce=?,target=?,origin=? WHERE id=1',
            (sessions._token(legacy_token), legacy['identitySha256'], self.origin))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.factory.complete(self.planned, expected_generation=2, change_token=legacy_token)
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def test_capacity_holds_before_revoke_and_existing_reservation_can_retry_at_capacity(self):
        with mock.patch.object(self.factory, 'stage', side_effect=RuntimeError('synthetic stage unavailable')):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.prepare()
        with mock.patch.object(incarnations, '_MAX', 1):
            with self.assertRaises(profiles.RecoveryProfileError):
                self.prepare(change_token=secrets.token_urlsafe(32))
            self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)
            self.assertEqual(self.prepare()['generation'], 2)

    def test_writer_reservation_insert_failure_rolls_back_without_revoking(self):
        self.store._db.execute("CREATE TRIGGER refuse_writer BEFORE INSERT ON operator_writer_requests BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(profiles.RecoveryProfileError):
            self.prepare()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0], 0)
        self.assertEqual(self.store.operator_status()['revision'], 'a' * 64)

    def test_concurrent_exact_requests_share_one_pending_operation(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: self.prepare(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0], 1)
        self.assertEqual(self.store.operator_status()['generation'], 2)

    def test_changed_retained_baseline_refuses_an_exact_pending_retry(self):
        receipt = self.prepare()
        Path(self.temp.name, 'profiles', receipt['baselineSha256'], 'identity.json').write_bytes(self.body('e'))
        with self.assertRaises(profiles.RecoveryProfileError):
            self.prepare()
        self.assertEqual(self.store.operator_status()['generation'], 2)

    def test_control_combined_operation_requires_exact_fields_and_two_bounded_identities(self):
        app = control.RecoveryControl(sessions=self.store, profiles=self.profiles, origin=self.origin, incarnations=self.factory)
        args = {'baselineIdentityBase64': base64.b64encode(self.before).decode(), 'identityBase64': base64.b64encode(self.planned).decode(),
                'expectedGeneration': 1, 'expectedRevision': 'a' * 64, 'changeToken': self.token}
        def call(arguments):
            return app.handle({'schema': control._SCHEMA, 'operation': 'operator-prepare-writer', 'arguments': arguments})
        for invalid in ({**args, 'extra': True}, {**args, 'expectedRevision': None}, {**args, 'expectedGeneration': False},
                        {key: value for key, value in args.items() if key != 'baselineIdentityBase64'}):
            self.assertFalse(call(invalid)['ok'])
        receipt = call(args)
        self.assertTrue(receipt['ok'])
        self.assertEqual(call(args), receipt)
        self.assertNotIn(self.token, json.dumps(receipt))
        self.assertEqual(control._MAX_REQUEST, 196608)
        with self.assertRaises(ValueError):
            control.RecoveryControl._identity(base64.b64encode(b'x' * 65537).decode())


if __name__ == '__main__':
    unittest.main()
