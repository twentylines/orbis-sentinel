"""Actual private artifacts/nonce/SQLite protocol; crypto callbacks are scoped seams.

No PostgreSQL/installed collector/runtime floor is claimed. All generated key
values are synthetic patched fixtures; the public activation gates stay closed.
"""
from dataclasses import replace
from contextlib import contextmanager
from contextlib import redirect_stderr
import base64
import hashlib
import io
import json
import os
import secrets
from pathlib import Path
import socket
import tempfile
import threading
import time
import sqlite3
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel.recovery_profiles import RecoveryProfiles, RecoveryProfileError
from orbis_sentinel.recovery_incarnations import RecoveryIncarnations
from orbis_sentinel.recovery_bootstrap import RecoveryBootstrap, _BootstrapActivationProof
from orbis_sentinel.bootstrap_source import encoded, digest, RootFileSourceWitness
from orbis_sentinel.bootstrap_control import RootBootstrapControl, RootBootstrapControlClient, RootBootstrapControlServer, _SCHEMA
from orbis_sentinel import bootstrap_control, recovery_control
from orbis_sentinel import bootstrap_source, collector_execution as execution, recovery_bootstrap
from orbis_sentinel import writer_control
from test_collector_execution import lease_fixture


class BootstrapFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bs-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.base.chmod(0o700)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start(); self.addCleanup(patch.stop)
        self.now = 1_800_000_000_000
        self.origin = 'https://recovery.example'
        self.op, self.installation = '1' * 64, '2' * 64
        self.credential = secrets.token_urlsafe(16)
        self.root = self.base / getattr(self, 'root_leaf', 'recovery'); self.root.mkdir(mode=0o700)
        self.namespace = self.base / 'namespace'; self.namespace.mkdir(mode=0o700)
        self.captures = self.namespace / 'bootstrap-sources'; self.captures.mkdir(mode=0o700)
        self.operation = self.root / 'bootstrap' / self.op
        self.operation.mkdir(mode=0o700, parents=True); self.operation.parent.chmod(0o700)
        self.raw = encoded({'schema': 'synthetic-fixture-only', 'revision': 'a' * 64, 'accountId': 1,
            'origin': self.origin, 'operator': True, 'passwordHash': 'synthetic-private-hash', 'counter': 3})
        self.plan = {'schema': 'orbis.sentinel-bootstrap-plan.v1', 'operationId': self.op, 'installationId': self.installation,
            'origin': self.origin, 'sourceSha256': digest(self.raw), 'captureRoot': str(self.captures),
            'collector': {'protocol': 'orbis.stopped-main-source.v1', 'programSha256': '3' * 64, 'imageId': 'sha256:' + '4' * 64},
            'hostHistorySha256': None}
        self.plan_sha = digest(encoded(self.plan)); self.write(self.operation / 'plan.json', encoded(self.plan))
        self.approval = {'schema': 'orbis.sentinel-bootstrap-approval.v1', 'operationId': self.op, 'planSha256': self.plan_sha,
                         'installationId': self.installation, 'approvalId': '5' * 64}
        self.write(self.operation / 'approval.json', encoded(self.approval))
        self.calls = []
        self.open()
        self.token_patch = mock.patch('orbis_sentinel.recovery_bootstrap.secrets.token_urlsafe', return_value='A' * 43)
        self.token_patch.start(); self.addCleanup(self.token_patch.stop)
        self.hex_patch = mock.patch('orbis_sentinel.recovery_bootstrap.secrets.token_hex', return_value='6' * 64)
        self.hex_patch.start(); self.addCleanup(self.hex_patch.stop)

    def write(self, path, body):
        path.write_bytes(body); path.chmod(0o600)

    def description(self, directory, expected):
        body = Path(directory, 'identity.json').read_bytes()
        self.assertEqual(digest(body), expected)
        value = json.loads(body)
        if value.get('operator') is not True:
            raise ValueError('Synthetic worker refuses nonoperators')
        self.calls.append(('describe', expected))
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': expected,
                'revision': value['revision'], 'accountId': value['accountId'], 'origin': value['origin'],
                'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {self.credential: value['counter']}}

    def content(self, directory, expected):
        value = json.loads(Path(directory, 'identity.json').read_bytes())
        self.calls.append(('content', expected))
        return {'schema': 'orbis.sentinel-identity-content.v1', 'identitySha256': expected,
                'contentSha256': digest(encoded({k: v for k, v in value.items() if k != 'revision'})),
                'description': self.description(directory, expected)}

    def open(self):
        self.store = sessions.RecoverySessions(self.root, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.profiles = RecoveryProfiles(self.store, inspect=self.description, verify=lambda *args: None)
        self.addCleanup(self.profiles.close)
        self.incarnations = RecoveryIncarnations(self.store, self.profiles, inspect=self.content, origin=self.origin)
        self.engine = RecoveryBootstrap(self.store, self.profiles, self.incarnations, origin=self.origin)

    def challenge(self, phase='proposal', request=None):
        request = request or ('7' if phase == 'proposal' else '8') * 64
        return request, self.engine.source_challenge(operation_id=self.op, plan_sha256=self.plan_sha, phase=phase, request_id=request)

    def capture(self, phase, challenge, *, raw=None, change=None):
        nonce = challenge['collectionNonce']
        directory = self.captures / self.op / (phase + '-' + digest(nonce.encode()))
        directory.mkdir(mode=0o700, parents=True, exist_ok=True); directory.parent.chmod(0o700)
        source = raw or self.raw
        descriptor = {'installationId': self.installation, 'origin': self.origin,
            'collector': {'protocol': 'orbis.stopped-main-source.v1', 'pid': 1, 'startTicks': 1, 'programSha256': '3' * 64},
            'exporter': {'cid': '9' * 64, 'imageId': 'sha256:' + '4' * 64, 'phase': 'awaiting-root-ack'}}
        witness = {'schema': 'orbis.bootstrap-source-witness.v1', 'operationId': self.op, 'planSha256': self.plan_sha,
                   'phase': phase, 'collectionNonce': nonce, 'sourceSha256': digest(source),
                   'descriptorSha256': digest(encoded(descriptor)), 'descriptor': descriptor, 'capturedAtMs': self.now}
        if change: change(witness)
        self.write(directory / 'source.json', source); self.write(directory / 'witness.json', encoded(witness))
        return directory, witness

    def stage(self):
        request, challenge = self.challenge(); self.capture('proposal', challenge)
        return self.engine.stage(operation_id=self.op, plan_sha256=self.plan_sha, request_id=request, collection_nonce=challenge['collectionNonce'])

    def prepare(self):
        self.stage()
        return self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha)

    def delivery(self):
        return json.loads((self.operation / 'delivery.json').read_bytes())

    def ack(self):
        self.prepare(); value = self.delivery()
        result = self.engine.acknowledge(operation_id=self.op, plan_sha256=self.plan_sha,
            delivery_epoch=value['epoch'], recovery_key=value['recoveryKey'])
        return result

    def activation(self):
        ack = self.ack(); request, challenge = self.challenge('activation'); self.capture('activation', challenge)
        return {'operation_id': self.op, 'plan_sha256': self.plan_sha, 'request_id': request,
                'collection_nonce': challenge['collectionNonce'], 'ack_receipt_id': ack['ackReceiptId']}

    def internal_proof(self, args):
        # Exercise the compound SQLite helper only. This does NOT qualify the
        # unavailable public live-context/writer-floor gates.
        with self.assertRaises(RecoveryProfileError): self.engine.activate(**args)
        def floor():
            record = self.engine._load(self.op)
            record['writerFloor'], record['managedIntent'] = 'b' * 64, 'c' * 64
            self.engine._save(record)
            return record
        record = self.store._transaction(floor)
        return _BootstrapActivationProof(self.store, self.op, self.plan_sha, record['sourceSha256'], record['candidate']['target'],
            record['candidate']['content'], record['challenges'][args['request_id']]['descriptor'], record['pendingGeneration'],
            record['key']['revision'], record['key']['ack'], args['request_id'], sessions._recovery_key_digest(self.delivery()['recoveryKey']),
            record['writerFloor'], record['managedIntent'])

    def test_nonce_consumption_precedes_independent_worker_and_staging_grants_no_authority(self):
        original = self.description
        def inspect(*args):
            record = self.store._transaction(lambda: self.engine._load(self.op))
            self.assertTrue(record['challenges']['7' * 64]['consumed'])
            return original(*args)
        self.profiles._inspect = inspect
        result = self.stage()
        self.assertEqual(result['phase'], 'staged'); self.assertNotEqual(result['revision'], 'a' * 64)
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': None, 'state': 'pending'})
        for table in ('identities', 'recovery_keys', 'sessions', 'counters'):
            self.assertEqual(self.store._db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)

    def test_root_challenge_exact_reply_and_stage_retry_survive_restart(self):
        request, issued = self.challenge(); self.assertEqual(self.challenge()[1], issued)
        self.capture('proposal', issued)
        first = self.engine.stage(operation_id=self.op, plan_sha256=self.plan_sha, request_id=request, collection_nonce=issued['collectionNonce'])
        self.profiles.close(); self.store.close(); self.open()
        self.assertEqual(self.engine.stage(operation_id=self.op, plan_sha256=self.plan_sha, request_id=request,
                                          collection_nonce=issued['collectionNonce']), first)

    def test_changed_approval_or_plan_refuses_without_root_operation(self):
        self.approval['installationId'] = 'd' * 64; self.write(self.operation / 'approval.json', encoded(self.approval))
        with self.assertRaises(ValueError): self.challenge()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM bootstrap_operations').fetchone()[0], 0)

    def test_unowned_profile_existing_key_revoked_and_managed_history_never_become_virgin(self):
        self.profiles.prepare(self.raw)
        with self.assertRaises(ValueError): self.challenge()
        self.assertEqual(self.store.operator_status()['state'], 'never-enrolled')

    def test_existing_key_and_revoked_operator_refuse_initial_preparation(self):
        self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        with self.assertRaises(ValueError): self.challenge()
        self.store._db.execute('DELETE FROM recovery_keys')
        self.store.revoke()
        with self.assertRaises(ValueError): self.challenge()

    def test_unowned_generic_stage_and_legacy_pending_state_at_zero_history_refuse(self):
        self.incarnations.stage(self.raw, expected_generation=0, expected_revision=None, change_token='A' * 43)
        self.assertEqual(self.store.operator_status()['generation'], 0)
        with self.assertRaises(ValueError): self.challenge()

    def test_preexisting_orphan_bootstrap_operation_is_not_adopted(self):
        self.challenge()
        record=self.store._transaction(lambda:self.engine._load(self.op))
        other='d'*64;record['operationId']=other
        self.store._db.execute('INSERT INTO bootstrap_operations VALUES (?,?)',(other,encoded(record).decode()))
        with self.assertRaises(ValueError): self.challenge(request='e'*64)

    def test_worker_rejects_bound_nonoperator_source_before_any_reservation(self):
        self.raw=self.raw.replace(b'"operator":true',b'"operator":false')
        self.plan['sourceSha256']=digest(self.raw);self.plan_sha=digest(encoded(self.plan))
        self.approval['planSha256']=self.plan_sha
        self.write(self.operation/'plan.json',encoded(self.plan));self.write(self.operation/'approval.json',encoded(self.approval))
        request,challenge=self.challenge();self.capture('proposal',challenge)
        with self.assertRaises(RecoveryProfileError):self.engine.stage(operation_id=self.op,plan_sha256=self.plan_sha,
            request_id=request,collection_nonce=challenge['collectionNonce'])
        self.assertEqual(self.store.operator_status()['generation'],0)

    def test_actual_managed_history_or_missing_expected_history_blocks(self):
        self.write(self.namespace / 'recovery-admission-history.json', encoded({'schema': 'orbis.recovery-admission-history.v1',
            'managedEver': True, 'mode': 'managed', 'installationId': self.installation}))
        with self.assertRaises(ValueError): self.challenge()
        self.plan['hostHistorySha256']=digest((self.namespace/'recovery-admission-history.json').read_bytes())
        self.plan_sha=digest(encoded(self.plan));self.approval['planSha256']=self.plan_sha
        self.write(self.operation/'plan.json',encoded(self.plan));self.write(self.operation/'approval.json',encoded(self.approval))
        with self.assertRaises(ValueError):self.challenge()

    def test_bad_source_witness_consumes_nonce_without_staging(self):
        request, challenge = self.challenge(); self.capture('proposal', challenge, change=lambda value: value.update(descriptorSha256='d' * 64))
        with self.assertRaises(RecoveryProfileError): self.engine.stage(operation_id=self.op, plan_sha256=self.plan_sha,
            request_id=request, collection_nonce=challenge['collectionNonce'])
        self.assertEqual(self.store.operator_status()['generation'], 0)
        self.assertTrue(self.store._transaction(lambda: self.engine._load(self.op))['challenges'][request]['consumed'])

    def test_future_capture_timestamp_is_not_fresh_source_evidence(self):
        request,challenge=self.challenge()
        self.capture('proposal',challenge,change=lambda value:value.update(capturedAtMs=self.now+1))
        with self.assertRaises(RecoveryProfileError):self.engine.stage(operation_id=self.op,plan_sha256=self.plan_sha,
            request_id=request,collection_nonce=challenge['collectionNonce'])
        self.assertEqual(self.calls,[]);self.assertEqual(self.store.operator_status()['generation'],0)

    def test_changed_raw_source_wrong_role_or_counter_cannot_match_plan(self):
        request, challenge = self.challenge(); self.capture('proposal', challenge, raw=self.raw.replace(b'"counter":3', b'"counter":9'))
        with self.assertRaises(RecoveryProfileError): self.engine.stage(operation_id=self.op, plan_sha256=self.plan_sha,
            request_id=request, collection_nonce=challenge['collectionNonce'])
        self.assertEqual(self.store.operator_status()['generation'], 0)

    def test_secret_delivery_is_private_and_never_in_replies_or_sqlite(self):
        result = self.prepare(); value = self.delivery()
        self.assertEqual(result['phase'], 'key-prepared'); self.assertNotIn(value['recoveryKey'], json.dumps(result))
        self.assertNotIn(value['recoveryKey'].encode(), (self.root / 'recovery.sqlite3').read_bytes())
        self.assertEqual((self.operation / 'delivery.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)

    def test_readiness_observes_setup_without_releasing_or_acknowledging_a_key(self):
        control = RootBootstrapControl(self.engine)
        request = {'schema': 'orbis.sentinel-root-bootstrap-control.v1',
                   'operation': 'bootstrap-enrollment-state', 'arguments': {}}

        def stage(expected):
            self.assertEqual(control.handle(request), {'schema': request['schema'], 'ok': True,
                                                       'result': {'origin': self.origin, 'stage': expected}})

        stage('not-started')
        self.stage()
        stage('operator-staged')
        self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha)
        stage('key-prepared')
        value = self.delivery()
        self.assertIsNone(self.engine.status(operation_id=self.op)['ackReceiptId'])
        self.assertFalse(control.handle({**request, 'arguments': {'operationId': self.op}})['ok'])
        self.engine.acknowledge(operation_id=self.op, plan_sha256=self.plan_sha,
                                delivery_epoch=value['epoch'], recovery_key=value['recoveryKey'])
        stage('key-acknowledged')
        self.now += 600001
        stage('key-expired')
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_key_prepare_lost_reply_reuses_exact_private_delivery_across_restart(self):
        first = self.prepare(); before = (self.operation / 'delivery.json').read_bytes()
        self.profiles.close(); self.store.close(); self.open()
        self.assertEqual(self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha), first)
        self.assertEqual((self.operation / 'delivery.json').read_bytes(), before)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 1)

    def test_delivery_file_precedes_pending_hash_commit_and_recovers_same_file(self):
        self.stage(); original = self.store._transaction; interrupted = False
        def commit(work):
            nonlocal interrupted
            if (self.operation / 'delivery.json').exists() and not interrupted:
                interrupted = True; raise OSError('Synthetic before pending-key transaction')
            return original(work)
        with mock.patch.object(self.store, '_transaction', side_effect=commit), self.assertRaises(OSError):
            self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha)
        before = (self.operation / 'delivery.json').read_bytes()
        self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha)
        self.assertEqual((self.operation / 'delivery.json').read_bytes(), before)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 1)

    def test_malformed_or_replaced_delivery_is_retained_and_never_overwritten(self):
        self.stage(); self.write(self.operation / 'delivery.json', b'partial')
        with self.assertRaises(ValueError): self.engine.prepare_key(operation_id=self.op, plan_sha256=self.plan_sha)
        self.assertEqual((self.operation / 'delivery.json').read_bytes(), b'partial')

    def test_possession_acknowledgement_is_exact_and_idempotent_without_session(self):
        self.prepare(); value = self.delivery()
        for changes in ({'delivery_epoch': 'd' * 64}, {'recovery_key': 'orbis-recovery-' + 'B' * 42 + 'A'}):
            with self.assertRaises(ValueError): self.engine.acknowledge(**{'operation_id': self.op, 'plan_sha256': self.plan_sha,
                'delivery_epoch': value['epoch'], 'recovery_key': value['recoveryKey'], **changes})
        ack = self.engine.acknowledge(operation_id=self.op, plan_sha256=self.plan_sha, delivery_epoch=value['epoch'], recovery_key=value['recoveryKey'])
        self.assertEqual(self.engine.acknowledge(operation_id=self.op, plan_sha256=self.plan_sha,
            delivery_epoch=value['epoch'], recovery_key=value['recoveryKey']), ack)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)

    def test_expired_delivery_never_activates_or_rotates_itself(self):
        self.prepare(); value = self.delivery(); self.now += 600001
        with self.assertRaises(ValueError): self.engine.acknowledge(operation_id=self.op, plan_sha256=self.plan_sha,
            delivery_epoch=value['epoch'], recovery_key=value['recoveryKey'])
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 1)
        self.assertEqual((self.operation / 'delivery.json').exists(), True)

    def test_arbitrary_private_json_does_not_satisfy_live_context_or_writer_floor(self):
        args = self.activation()
        with self.assertRaises(RecoveryProfileError): self.engine.activate(**args)
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)
        with self.assertRaises(ValueError): self.engine.sources.require_live_context(True)
        with self.assertRaises(ValueError): self.engine.sources.require_writer_floor({'qualified': True})

    def test_compound_internal_transaction_activates_both_or_neither_without_session(self):
        proof = self.internal_proof(self.activation())
        before = self.store._db.total_changes
        with self.assertRaises(sessions.RecoverySessionError): self.store._activate_initial_bootstrap(replace(proof, key_digest='d' * 64))
        self.assertEqual(self.store.operator_status()['state'], 'pending')
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)
        result = self.store._activate_initial_bootstrap(proof)
        self.assertEqual(result['phase'], 'active'); self.assertEqual(result['generation'], 2)
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], 1)
        self.assertEqual(self.store._db.execute('SELECT counter FROM counters').fetchone()[0], 3)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)
        self.assertGreater(self.store._db.total_changes, before)
        self.assertEqual(self.engine.enrollment_state(), {'origin': self.origin, 'stage': 'activated'})

    def test_activation_exact_receipt_survives_restart_but_never_reactivates_retired_identity(self):
        args = self.activation(); proof = self.internal_proof(args); result = self.store._activate_initial_bootstrap(proof)
        self.profiles.close(); self.store.close(); self.open()
        self.assertEqual(self.engine.activate(**args), result)
        self.store.revoke_operator(expected_generation=2, expected_revision=result['revision'])
        with self.assertRaises(RecoveryProfileError): self.engine.activate(**args)
        self.assertEqual(self.store.operator_status()['state'], 'revoked')
        self.assertTrue(self.store.authentication_options()['recoveryKey'])

    def test_pending_bootstrap_blocks_legacy_operator_and_key_mutators(self):
        self.prepare(); value = self.delivery()
        for action in (lambda: self.store.revoke(), lambda: self.store.prepare_recovery_key(origin=self.origin, expected_revision=None),
                       lambda: self.store.activate_recovery_key(revision=value['revision'], recovery_key=value['recoveryKey'], expected_revision=None),
                       lambda: self.store.begin_operator_enrollment(expected_generation=1, expected_revision=None, identity_sha256='d' * 64, origin=self.origin)):
            with self.assertRaises(sessions.RecoverySessionError): action()
        self.assertEqual(self.store.operator_status()['state'], 'pending')

    def test_distinct_control_rejects_main_schema_unknown_fields_and_normal_client_privilege(self):
        app = RootBootstrapControl(self.engine)
        def call(op, args, schema=_SCHEMA): return app.handle({'schema': schema, 'operation': op, 'arguments': args})
        args = {'operationId': self.op, 'planSha256': self.plan_sha, 'phase': 'proposal', 'requestId': '7' * 64}
        self.assertFalse(call('bootstrap-source-challenge', args, 'orbis.sentinel-recovery-control.v1')['ok'])
        self.assertFalse(call('bootstrap-source-challenge', dict(args, verified=True))['ok'])
        self.assertTrue(call('bootstrap-source-challenge', args)['ok'])
        self.assertFalse(call('operator-begin', {})['ok'])
        self.assertNotIn('bootstrap-stage', writer_control._OPERATIONS)
        with self.assertRaises(ValueError): RootBootstrapControl(True)

    def test_compound_failure_after_identity_insert_rolls_back_both_authorities(self):
        proof=self.internal_proof(self.activation())
        self.store._db.execute("CREATE TRIGGER synthetic_key_failure BEFORE UPDATE OF active ON recovery_keys BEGIN SELECT RAISE(ABORT,'synthetic'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.store._activate_initial_bootstrap(proof)
        self.assertEqual(self.store.operator_status()['state'],'pending')
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM identities').fetchone()[0],0)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM counters').fetchone()[0],0)
        self.assertEqual(self.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0],-1)
        self.assertEqual(self.store._transaction(lambda:self.engine._load(self.op))['phase'],'acknowledged')

    def test_expired_or_crossed_source_nonce_refuses_before_crypto(self):
        request,challenge=self.challenge();self.capture('proposal',challenge)
        self.now+=120001
        with self.assertRaises(RecoveryProfileError):self.engine.stage(operation_id=self.op,plan_sha256=self.plan_sha,
            request_id=request,collection_nonce=challenge['collectionNonce'])
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError):self.challenge('activation')

    def test_actual_distinct_root_socket_and_client_never_return_raw_delivery(self):
        self.stage()
        # This macOS fixture exercises real framing/custody with explicit peer
        # seams; genuine SO_PEERCRED remains a separate Linux qualification.
        with mock.patch.object(bootstrap_control,'_OWNER_UID',os.getuid()), mock.patch.object(recovery_control,'_OWNER_UID',os.getuid()), \
                mock.patch.object(RootBootstrapControlClient,'_peer',return_value=True), \
                mock.patch.object(recovery_control.RecoveryControlServer,'_peer_uid',return_value=os.getuid()):
            server=RootBootstrapControlServer(str(self.root/'bootstrap.sock'),RootBootstrapControl(self.engine))
            thread=threading.Thread(target=server.serve_forever);thread.start()
            try:
                client=RootBootstrapControlClient(str(self.root/'bootstrap.sock'),timeout=3)
                result=client.call('bootstrap-key-prepare',{'operationId':self.op,'planSha256':self.plan_sha})
                value=self.delivery()
                self.assertEqual(result['phase'],'key-prepared');self.assertNotIn(value['recoveryKey'],json.dumps(result))
                with self.assertRaises(bootstrap_control.RootBootstrapControlError):client.call('operator-status',{})
                with self.assertRaises(writer_control.WriterControlError):writer_control.WriterControlClient(str(self.root/'bootstrap.sock')).call('bootstrap-key-prepare',{})
            finally:
                server.shutdown();thread.join(5);server.close()
                self.assertFalse(thread.is_alive())
        self.assertFalse((self.root/'bootstrap.sock').exists())

    def test_host_client_loads_from_exact_extra_source_without_server_import_fallback(self):
        package_name='_root_bootstrap_client_fixture'
        package=ModuleType(package_name);package.__path__=[]
        client_name=package_name+'.bootstrap_control'
        journal_name=package_name+'.writer_journal'
        package.__package__=package_name
        from orbis_sentinel import writer_journal
        sys.modules[package_name]=package;sys.modules[journal_name]=writer_journal
        module=ModuleType(client_name);module.__package__=package_name
        sys.modules[client_name]=module
        try:
            body=Path(bootstrap_control.__file__).read_bytes()
            exec(compile(body,'pinned-bootstrap-control.py','exec',dont_inherit=True),module.__dict__)
            self.assertNotIn(package_name+'.recovery_control',sys.modules)
            self.assertNotIn(package_name+'.recovery_bootstrap',sys.modules)
            client=module.RootBootstrapControlClient(str(self.root/'bootstrap.sock'))
            with self.assertRaises(module.RootBootstrapControlError):client.call('operator-status',{})
        finally:
            for name in (client_name,journal_name,package_name):sys.modules.pop(name,None)

    def test_hardlinked_symlink_and_changed_file_mode_refuse_private_plan(self):
        path = self.operation / 'plan.json'; os.link(path, self.operation / 'alias')
        with self.assertRaises(ValueError): self.challenge()
        (self.operation / 'alias').unlink(); path.chmod(0o644)
        with self.assertRaises(ValueError): self.challenge()
        path.chmod(0o600); path.rename(self.operation / 'original'); path.symlink_to(self.operation / 'original')
        with self.assertRaises((ValueError, OSError)): self.challenge()


class HeldStageTests(unittest.TestCase):
    def setUp(self):
        self.fixture = f = BootstrapFixture()
        f.root_leaf = 'r'
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.token_patch.stop()
        self.host = f.base / 'host-state'
        self.host.mkdir(mode=0o700)
        main_root = str(f.base / 'masked-main')
        namespace = self.host / 'installations' / digest(os.fsencode(main_root))
        namespace.mkdir(mode=0o700, parents=True)
        namespace.parent.chmod(0o700)
        f.captures = namespace / 'bootstrap-sources'
        f.captures.mkdir(mode=0o700)
        self.start(mock.patch.object(bootstrap_source, 'HOST_STATE', self.host))
        self.bodies = {name: b'# synthetic held module\n' for name in execution._REQUIRED}
        inventory = digest(encoded({name: digest(body) for name, body in self.bodies.items()}))
        prior = encoded({'origin': f.origin, 'mode': 'unmanaged'})
        f.write(self.host / 'credential-admission.json', prior)
        history = encoded({'schema': 'orbis.recovery-admission-history.v1', 'installationId': f.installation,
                           'mode': 'unmanaged', 'managedEver': False, 'generation': 7, 'configSha256': digest(prior)})
        f.write(namespace / 'recovery-admission-history.json', history)
        self.receiver = {'pid': 91, 'startTicks': 1, 'invocationId': '8' * 32, 'executableIdentity': [1, 1]}
        roles = dict(installation=main_root, namespace=str(namespace), journal=str(namespace / 'credential-journal'), recovery=str(f.root))
        self.review = {'schema': 'orbis.sentinel-bootstrap-review.v2', 'operationId': f.op, 'root': main_root,
            'context': 'local', 'installationId': f.installation, 'origin': f.origin, 'captureRoot': str(f.captures),
            'hostHistorySha256': digest(history), 'previousGeneration': 7, 'previousAdmissionSha256': digest(prior),
            'previousSentinelVersion': '1.0.0', 'previousWriterProtocol': 1, 'daemon': 'fixture-daemon',
            'layoutSha256': '3' * 64, 'main': {'id': '4' * 64, 'imageId': f.plan['collector']['imageId'],
                'publicationSha256': '5' * 64, 'definitionSha256': '6' * 64},
            'host': {'inventorySha256': inventory, 'unitSha256': 'b' * 64, 'environmentSha256': 'c' * 64},
            'collector': {**f.plan['collector'], 'inventorySha256': inventory},
            'publisher': {'operationId': '8' * 64, 'receiptSha256': '9' * 64},
            'runtime': {'version': '1.0.0', 'inventorySha256': 'a' * 64, 'runtimeDirectory': '/fixed/sentinel',
                'runtimeFiles': dict.fromkeys(('__init__.py', 'writer_broker.py', 'writer_control.py', 'writer_journal.py',
                                               'recovery_sessions.py', 'recovery_config.py'), 'd' * 64)},
            'recovery': {'process': self.receiver, 'configSha256': '4' * 64, 'environmentSha256': '5' * 64, 'unitSha256': '6' * 64},
            'storage': {key: {'path': path, 'filesystem': 'ext4', 'uuid': 'a' * 32,
                             'handle': f'{index:016x}', 'owner': [0, 0, 0o40700],
                             'filesystemPath': path, 'mountPoint': '/', 'mountRoot': '/'}
                        for index, (key, path) in enumerate(roles.items(), 1)}, 'journal': {}}
        self.review_sha = digest(encoded(self.review))
        f.write(f.operation / 'review-plan.json', encoded(self.review))
        f.write(f.operation / 'review-approval.json', encoded({'schema': 'orbis.sentinel-bootstrap-review-approval.v2',
            'operationId': f.op, 'reviewSha256': self.review_sha, 'installationId': f.installation, 'approvalId': 'b' * 64}))
        f.plan.update(schema=bootstrap_source.HELD_PLAN, reviewSha256=self.review_sha,
                      captureRoot=str(f.captures), hostHistorySha256=digest(history))
        f.plan_sha = digest(encoded(f.plan))
        f.approval.update(schema='orbis.sentinel-bootstrap-approval.v2', planSha256=f.plan_sha)
        f.write(f.operation / 'plan.json', encoded(f.plan))
        f.write(f.operation / 'approval.json', encoded(f.approval))
        self.start(mock.patch.object(recovery_bootstrap, '_receiver_invocation', return_value=self.receiver))
        # The local portability seams stand in for native Linux pidfds and seals.
        # The listener, passed descriptors, child dialogue, real file reads and
        # the sole Sessions SQLite transaction are all exercised below.
        self.start(mock.patch.object(execution, '_pidfd_pid', return_value=42))
        self.start(mock.patch.object(execution, '_peer_identity', return_value=(42, 0, 0)))
        self.start(mock.patch.object(execution, '_sealed_capsule', side_effect=self.sealed))
        self.start(mock.patch.object(recovery_control.RecoveryControlServer, '_peer_uid', return_value=os.getuid()))
        self.start(mock.patch.object(recovery_control, '_OWNER_UID', os.getuid()))
        path = f.root / 'bootstrap.sock'
        self.server = RootBootstrapControlServer(str(path), RootBootstrapControl(f.engine))
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close)
        self.path = path

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def close(self):
        self.server.shutdown()
        self.thread.join(5)
        self.server.close()
        self.assertFalse(self.thread.is_alive())

    @staticmethod
    def sealed(fd, expected=None):
        info = os.fstat(fd)
        result = digest(os.pread(fd, info.st_size, 0))
        if expected is not None and result != expected:
            raise execution.unavailable()
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size, result)

    def packet(self, *, activating=None):
        f = self.fixture
        phase = 'activation' if activating else 'proposal'
        if activating is None:
            request_id, challenge = f.challenge()
        else:
            request_id, challenge, _, _ = activating
        f.now = f.store._now()

        def bind(witness):
            descriptor = witness['descriptor']
            descriptor['collector']['pid'] = 42
            descriptor.update(main=self.review['main'], daemon=self.review['daemon'], layoutSha256=self.review['layoutSha256'])
            witness['descriptorSha256'] = digest(encoded(descriptor))

        _, witness = f.capture(phase, challenge, change=bind)
        request = {'operationId': f.op, 'planSha256': f.plan_sha, 'phase': phase,
                   'collectionNonce': challenge['collectionNonce'], 'origin': f.origin}
        scope = {'root': self.review['root'], 'context': 'local', 'request': request, 'holdBinding': self.review_sha}
        inventory = self.review['collector']['inventorySha256']
        payload = {'schema': execution.SCHEMA, 'directory': str(execution.HOST_SOURCE), 'scope': scope,
                   'inventorySha256': inventory, 'bodies': {key: base64.b64encode(body).decode() for key, body in self.bodies.items()}}
        program = execution._held_program(Path(execution.__file__).read_bytes(), 47, 48, payload)
        self.capsule = f.base / 'synthetic-capsule'
        f.write(self.capsule, program)
        extra = {'packetSha256': activating[2], 'intentSha256': activating[3]} if activating else {}
        return {'schema': execution.held_schema(phase), 'step': 'offer', 'operationId': f.op,
                'planSha256': f.plan_sha, 'requestId': request_id, 'reviewSha256': self.review_sha,
                'collectionNonce': request['collectionNonce'], 'holdBinding': self.review_sha,
                'capsuleSha256': digest(program), 'inventorySha256': inventory,
                'descriptorSha256': witness['descriptorSha256'], 'sourceSha256': digest(f.raw), **extra}, request

    def exercise(self, outcome, *, activating=None):
        f = self.fixture
        offer, request = self.packet(activating=activating)
        actual = dict(offer)
        if outcome == 'crossed':
            offer['capsuleSha256'] = '0' * 64
        if outcome == 'crossed-intent':
            offer['intentSha256'] = '0' * 64
        read_end, write_end = os.pipe()
        if outcome == 'dead':
            os.close(write_end)
            write_end = None
        terminal, transferred = socket.socketpair()
        try:
            with (terminal, transferred, self.capsule.open('rb') as capsule,
                  socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as control):
                control.connect(str(self.path))
                deadline = time.monotonic() + 3
                execution.send_frame(control, offer, deadline, rights=(read_end, capsule.fileno(), transferred.fileno()))
                transferred.close()
                if outcome in ('crossed', 'dead', 'crossed-intent'):
                    execution.require_eof(control, deadline)
                    self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'activation-pending' if activating else 'collecting')
                    return
                seen = set()
                for check_index in range(2):
                    frame, _ = execution.receive_frame(terminal, deadline)
                    self.assertNotIn(frame['challenge'], seen)
                    seen.add(frame['challenge'])
                    if check_index == 1 and outcome == 'intent-changed-before-commit':
                        current = f.captures.parent / 'credential-bootstrap-intent.json'
                        f.write(current, current.read_bytes() + b' ')
                    execution.send_frame(terminal, {**frame, 'step': 'checked',
                        'capsuleIdentity': list(self.sealed(capsule.fileno())[:2]),
                        **{key: offer[key] for key in ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256')}},
                        deadline)
                if outcome == 'intent-changed-before-commit':
                    execution.require_eof(control, deadline)
                    return
                pending, _ = execution.receive_frame(control, deadline)
                self.assertEqual(pending['step'], 'finish-required')
                self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'activation-committed' if activating else 'held-stage-pending')
                if outcome == 'lost':
                    control.shutdown(socket.SHUT_WR)
                    execution.require_eof(control, deadline)
                    return
                terminal.close()
                os.close(write_end)
                write_end = None
                receipt = {'schema': execution.SCHEMA, 'phase': 'complete', 'request': request,
                           'installationId': f.installation, 'executionSha256': 'a' * 64,
                           'process': {'pid': 42, 'startTicks': 1, 'executable': [1, 1]},
                           'root': self.review['root'], 'context': self.review['context'], 'exitCode': 0,
                           'authority': 'inventory-execution-custody-only',
                           **{key: offer[key] for key in ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256', 'holdBinding')}}
                schema = bootstrap_source.ACTIVATION_TERMINAL if activating else 'orbis.sentinel-bootstrap-held-terminal.v1'
                extra = {'commitSha256': pending['commitSha256']} if activating else {}
                data = encoded({'schema': schema, 'offerSha256': digest(encoded(actual)),
                                'terminalChallenge': pending['terminalChallenge'], 'receipt': receipt, **extra})
                name = 'held-activation-terminal.json' if activating else 'held-stage-terminal.json'
                f.write(f.operation / name, data)
                execution.send_frame(control, {**pending, 'step': 'finished', 'terminalReceiptSha256': digest(data)}, deadline)
                control.shutdown(socket.SHUT_WR)
                result, _ = execution.receive_frame(control, deadline)
                self.assertEqual(result['step'], 'activation-committed' if activating else 'stage-complete')
                execution.require_eof(control, deadline)
        finally:
            os.close(read_end)
            if write_end is not None:
                os.close(write_end)

    def test_real_ancillary_stage_persists_exact_terminal_in_sole_sessions_owner(self):
        self.exercise('complete')
        f = self.fixture
        self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'held-stage-complete')
        self.assertEqual(f.store.operator_status(), {'generation': 1, 'revision': None, 'state': 'pending'})
        self.assertFalse((f.operation / 'delivery.json').exists())
        with self.assertRaises(ValueError):
            f.engine.source_challenge(operation_id=f.op, plan_sha256=f.plan_sha, phase='activation', request_id='8' * 64)
        f.profiles.close(); f.store.close(); f.open()
        self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'held-stage-complete')

    def approved_activation(self, *, staged=False):
        from orbis_sentinel import credential_floor as floor
        f, review = self.fixture, self.review
        if not staged:
            self.exercise('complete')
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        f.engine.prepare_key(**parameters)
        key = f.delivery()
        f.engine.acknowledge(**parameters, delivery_epoch=key['epoch'], recovery_key=key['recoveryKey'])
        value = f.store._transaction(lambda: f.engine._load(f.op))
        request_id = '8' * 64
        core = f.engine._activation_core(value, request_id)
        projected = digest(encoded(core))
        prior = {'historySha256': review['hostHistorySha256'], 'configSha256': review['previousAdmissionSha256'],
                 'generation': review['previousGeneration']}
        config_epoch = digest(encoded({'operationId': f.op, 'reviewSha256': self.review_sha,
                                       'prior': prior, 'publication': review['publisher']}))

        def file(name, data):
            body = encoded(data)
            f.write(f.operation / name, body)
            return digest(body)

        config = {'schema': 'orbis.host.credential-admission.v1', 'mode': 'managed',
                  **{key: review[key] for key in ('installationId', 'root', 'context', 'origin')},
                  'writerProtocol': 1, 'recoveryEpoch': config_epoch, 'runtimeDirectory': review['runtime']['runtimeDirectory'],
                  'runtimeFiles': review['runtime']['runtimeFiles'], 'journalDirectory': str(f.captures.parent / 'credential-journal'),
                  'recoveryConfig': str(floor.RECOVERY_ROOT / 'config.json'), 'recoveryConfigSha256': review['recovery']['configSha256']}
        config_sha = file('activation-config.json', config)
        bridge = {'schema': bootstrap_source.ACTIVATION_BRIDGE,
                  **{key: review[key] for key in ('installationId', 'context', 'daemon')},
                  'parentFloorSha256': review['hostHistorySha256'], 'publicationOperation': review['publisher']['operationId'],
                  'publicationSha256': review['publisher']['receiptSha256'], 'recoveryUnitSha256': review['recovery']['unitSha256'],
                  'roles': review['storage']}
        bridge_sha = file('activation-bridge.json', bridge)
        history = {'schema': floor.SCHEMA, 'installationId': f.installation, 'generation': review['previousGeneration'] + 1,
                   'managedEver': True, 'mode': 'managed', 'configSha256': config_sha, 'planSha256': f.plan_sha,
                   'sentinelVersion': review['runtime']['version'], 'writerProtocol': 1, 'previousSha256': review['hostHistorySha256'],
                   'positiveNeverManaged': None,
                   'minimum': {name: {'family': family, 'version': version} for name, (family, version) in floor.CONTRACTS.items()},
                   'current': {
                       'main': {'imageId': review['main']['imageId'], 'creationSha256': review['main']['definitionSha256'],
                                'publicationSha256': review['main']['publicationSha256']},
                       'host': review['host'],
                       'sentinel': {'version': review['runtime']['version'], 'inventorySha256': review['runtime']['inventorySha256'],
                                    'runtimeSha256': '2' * 64, 'unitSha256': review['recovery']['unitSha256'],
                                    'environmentSha256': review['recovery']['environmentSha256']},
                       'authWorker': {'imageId': review['main']['imageId'], 'anchorSha256': '7' * 64, 'capabilitiesSha256': '8' * 64},
                       'sourceExporter': {key: review['collector'][key] for key in ('imageId', 'programSha256')},
                       'recoveryOrigin': f.origin,
                       'configuration': {'hostAdmissionSha256': config_sha, 'recoveryConfigSha256': config['recoveryConfigSha256'],
                                         'recoveryEnvironmentSha256': review['recovery']['environmentSha256']},
                       'storage': {'bridgeSha256': bridge_sha, 'parentFloorSha256': review['hostHistorySha256'],
                                   'journalSchema': 'orbis.sentinel-writer-journal.v1'},
                       'receipts': {'bootstrapSha256': value['heldStage']['terminalReceiptSha256'],
                                    'sourceSha256': value['sourceSha256'], 'activationSha256': projected}}}
        history['current']['sourceExporter']['capabilitiesSha256'] = '9' * 64
        history_sha = file('activation-history.json', history)
        packet = {'schema': bootstrap_source.ACTIVATION_PACKET, 'operationId': f.op, 'planSha256': f.plan_sha,
                  'reviewSha256': self.review_sha, **{key: review[key] for key in ('installationId', 'root', 'context', 'daemon', 'origin')},
                  'publication': review['publisher'], 'prior': prior,
                  'stage': {'terminalReceiptSha256': value['heldStage']['terminalReceiptSha256'], 'sourceSha256': value['sourceSha256'],
                            'identitySha256': core['identitySha256'], 'revision': core['revision'],
                            'contentSha256': value['candidate']['content'], 'pendingGeneration': value['pendingGeneration']},
                  'key': {'revision': core['keyRevision'], 'ackReceiptId': core['ackReceiptId']},
                  'activationRequestId': request_id, 'candidate': {'configSha256': config_sha, 'historySha256': history_sha,
                    'bridgeSha256': bridge_sha, 'projectedCommitSha256': projected}}
        packet_sha = file('activation-packet.json', packet)
        approval_sha = file('activation-approval.json', {'schema': 'orbis.sentinel-bootstrap-activation-approval.v1',
            'operationId': f.op, 'installationId': f.installation, 'packetSha256': packet_sha,
            'activationRequestId': request_id, 'approvalId': 'c' * 64})
        return packet, packet_sha, approval_sha

    def activation_input(self, approved):
        f = self.fixture
        packet, packet_sha, approval_sha = approved
        challenge = f.engine.held_activation_challenge(operation_id=f.op, plan_sha256=f.plan_sha,
            packet_sha256=packet_sha, request_id=packet['activationRequestId'])
        intent = {'schema': 'orbis.host.credential-bootstrap-intent.v1',
                  **{key: packet[key] for key in ('operationId', 'installationId', 'reviewSha256', 'planSha256', 'activationRequestId')},
                  'packetSha256': packet_sha, 'approvalSha256': approval_sha, 'nonceSha256': digest(challenge['collectionNonce'].encode()),
                  'issuedAtMs': challenge['issuedAtMs'], 'expiresAtMs': challenge['expiresAtMs']}
        fence = {'schema': 'orbis.host-credential-fence.v1', 'operationId': f.op, 'root': self.review['root'],
                 'context': self.review['context'], 'admissionBinding': self.review_sha}
        f.write(f.captures.parent / 'credential-fence.json', encoded(fence) + b'\n')
        f.write(f.captures.parent / 'credential-bootstrap-intent.json', encoded(intent))
        return packet['activationRequestId'], challenge, packet_sha, digest(encoded(intent))

    def test_held_activation_stores_private_inactive_identity_and_exact_terminal(self):
        f = self.fixture
        approved = self.approved_activation()
        active_input = self.activation_input(approved)
        self.assertEqual(self.activation_input(approved), active_input)
        self.exercise('complete', activating=active_input)
        params = {'operation_id': f.op, 'plan_sha256': f.plan_sha, 'packet_sha256': approved[1]}
        receipt = f.engine.held_activation_receipt(**params)
        terminal = f.operation / 'held-activation-terminal.json'
        self.assertEqual(receipt['terminalReceiptSha256'], digest(terminal.read_bytes()))
        self.assertEqual(receipt['commitSha256'], approved[0]['candidate']['projectedCommitSha256'])
        self.assertEqual(f.store._db.execute('SELECT active FROM identities').fetchone()[0], 0)
        self.assertEqual(f.store._db.execute('SELECT active FROM recovery_keys').fetchone()[0], -1)
        with self.assertRaises(sessions.RecoverySessionError):
            f.store.authentication_options()
        f.profiles.close(); f.store.close(); f.open()
        f.now += 100_000_000
        self.assertEqual(f.engine.held_activation_receipt(**params), receipt)
        self.assertEqual(f.store._db.execute('SELECT generation FROM operator_enrollment').fetchone()[0], 1)
        f.write(terminal, terminal.read_bytes() + b' ')
        with self.assertRaises(ValueError):
            f.engine.held_activation_receipt(**params)

    def test_held_activation_refuses_crossed_packet_approval_intent_and_unproven_terminal(self):
        f = self.fixture
        approved = self.approved_activation()
        approval = f.operation / 'activation-approval.json'
        raw = approval.read_bytes()
        f.write(approval, encoded({**json.loads(raw), 'packetSha256': 'f' * 64}))
        with self.assertRaises(RecoveryProfileError):
            self.activation_input(approved)
        f.write(approval, raw)
        active_input = self.activation_input(approved)
        self.exercise('crossed-intent', activating=active_input)
        self.assertEqual(self.activation_input(approved), active_input)
        self.exercise('lost', activating=active_input)
        receipt = f.engine.held_activation_receipt(operation_id=f.op, plan_sha256=f.plan_sha, packet_sha256=approved[1])
        self.assertIsNone(receipt['terminalReceiptSha256'])
        with self.assertRaises(RecoveryProfileError):
            self.activation_input(approved)
        with self.assertRaises(sessions.RecoverySessionError):
            f.store.operator_status()

    def test_intent_replacement_between_live_checks_retains_consumed_pending_hold(self):
        f = self.fixture
        approved = self.approved_activation()
        active_input = self.activation_input(approved)
        self.exercise('intent-changed-before-commit', activating=active_input)
        self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'activation-pending')
        self.assertTrue(f.store._transaction(lambda: f.engine._load(f.op))['challenges'][active_input[0]]['consumed'])
        self.assertIsNone(f.store._db.execute('SELECT revision FROM identities').fetchone())
        self.assertFalse((f.operation / 'held-activation-terminal.json').exists())
        with self.assertRaises(RecoveryProfileError):
            self.activation_input(approved)

    def test_publication_hold_checks_old_session_and_verifier_that_crosses_its_commit(self):
        from orbis_sentinel.recovery_gateway import API, RecoveryApplication
        from orbis_sentinel.recovery_main_passkeys import RecoveryMainPasskeys
        f = self.fixture
        approved = self.approved_activation()
        candidate = f.store._transaction(lambda: f.engine._load(f.op))['candidate']['profile']
        revision = candidate['revision']
        binding, token, csrf = 'A' * 43, 'E' * 43, 'I' * 43
        # Model a stale browser authority across the state boundary. Real initial
        # enrollment rejects an already enrolled source; these are control rows
        # only to establish the guards rather than an empty-table failure.
        f.store._db.execute('INSERT INTO identities VALUES (?,?,1)', (revision, encoded(candidate).decode('ascii')))
        f.store._db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?)', (
            sessions._token(token), sessions._token(csrf), revision, 'password', f.now, f.now))
        self.assertTrue(f.store.authentication_options()['password'])
        self.assertEqual(f.store.session(token=token, origin=f.origin)['revision'], revision)
        challenge = f.store.challenge(method='password', origin=f.origin, browser_binding=binding)['challenge']

        def old_proof(identity, nonce):
            self.assertEqual(identity, candidate['identitySha256'])
            self.assertEqual(nonce, challenge)
            f.store._db.execute('UPDATE identities SET active=0')
            self.activation_input(approved)
            f.store._db.execute('UPDATE identities SET active=1')
            return {'schema': 'orbis.sentinel-authentication.v1', 'verified': True, 'accountId': candidate['accountId'],
                    'revision': revision, 'identitySha256': identity, 'challenge': challenge, 'method': 'password',
                    'verifiedAtMs': f.now, 'totpStep': None, 'credential': None}

        with self.assertRaises(sessions.RecoverySessionError):
            f.store.complete(challenge=challenge, origin=f.origin, browser_binding=binding, verifier=old_proof)
        f.now += 1
        with self.assertRaises(sessions.RecoverySessionError):
            f.store.session(token=token, origin=f.origin, csrf=csrf)
        with self.assertRaises(sessions.RecoverySessionError):
            f.store.logout(token=token, origin=f.origin, csrf=csrf)
        self.assertEqual(f.store._db.execute('SELECT touched FROM sessions').fetchall()[0][0], f.now - 1)
        self.assertEqual(f.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 1)
        gateway = RecoveryApplication(origin=f.origin, sessions=f.store, verify=mock.Mock(), status=mock.Mock())
        headers = {'host': gateway.host, 'cookie': gateway.prefix + 'session=' + token}
        self.assertEqual(gateway.handle('GET', API + '/options', headers).status, 401)
        self.assertFalse(json.loads(gateway.handle('GET', API + '/session', headers).body)['authenticated'])
        self.assertEqual(gateway.handle('GET', API + '/status', headers).status, 401)
        gateway.status.assert_not_called()
        ordinary = recovery_control.RecoveryControl(sessions=f.store, profiles=f.profiles, origin=f.origin,
                                                    incarnations=f.incarnations, main_passkeys=RecoveryMainPasskeys(f.store, f.profiles, origin=f.origin))
        def call(operation, arguments):
            return ordinary.handle({'schema': recovery_control._SCHEMA, 'operation': operation, 'arguments': arguments})
        self.assertFalse(call('operator-status', {})['ok'])
        with mock.patch.object(f.profiles, 'prepare', wraps=f.profiles.prepare) as prepare:
            self.assertFalse(call('operator-stage', {'identityBase64': base64.b64encode(f.raw).decode()})['ok'])
            with self.assertRaises(RecoveryProfileError):
                f.incarnations.stage(f.raw, expected_generation=1, expected_revision=revision, change_token='M' * 43)
            prepare.assert_not_called()

    def test_lost_terminal_is_durable_and_old_stage_cannot_replay_it(self):
        self.exercise('lost')
        f = self.fixture
        f.profiles.close(); f.store.close(); f.open()
        self.assertEqual(f.engine.status(operation_id=f.op)['phase'], 'held-stage-pending')
        with self.assertRaises(RecoveryProfileError):
            f.engine.stage(operation_id=f.op, plan_sha256=f.plan_sha, request_id='7' * 64, collection_nonce='A' * 43)
        with self.assertRaises(ValueError):
            f.engine.prepare_key(operation_id=f.op, plan_sha256=f.plan_sha)

    def test_crossed_capsule_is_rejected_before_challenge_consumption(self):
        self.exercise('crossed')
        f = self.fixture
        self.assertEqual(f.store.operator_status()['generation'], 0)
        self.assertFalse(f.challenge()[1]['consumed'])

    def test_dead_pidfd_is_rejected_before_challenge_consumption(self):
        self.exercise('dead')
        f = self.fixture
        self.assertEqual(f.store.operator_status()['generation'], 0)
        self.assertFalse(f.challenge()[1]['consumed'])

    def test_c3_preserves_exact_key_across_restart_retry_and_possession(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        first = f.engine.prepare_key(**parameters)
        self.assertEqual(first['phase'], 'key-prepared')
        delivery = f.operation / 'delivery.json'
        original_sha = digest(delivery.read_bytes())
        saved = json.loads(delivery.read_bytes())
        self.assertEqual(first['deliverySha256'], original_sha)
        f.profiles.close(); f.store.close(); f.open()
        with mock.patch.object(f.engine, '_new_delivery', side_effect=AssertionError('existing key replaced')):
            self.assertEqual(f.engine.prepare_key(**parameters), first)
            with self.assertRaises(ValueError):
                f.engine.acknowledge(**parameters, delivery_epoch='9' * 64, recovery_key=saved['recoveryKey'])
            with self.assertRaises(ValueError):
                f.engine.acknowledge(**parameters, delivery_epoch=saved['epoch'], recovery_key='orbis-recovery-' + 'A' * 43)
            ack = f.engine.acknowledge(**parameters, delivery_epoch=saved['epoch'], recovery_key=saved['recoveryKey'])
            self.assertEqual(f.engine.acknowledge(**parameters, delivery_epoch=saved['epoch'], recovery_key=saved['recoveryKey']), ack)
        self.assertEqual(digest(delivery.read_bytes()), original_sha)
        row = f.store._db.execute('SELECT revision, active FROM recovery_keys').fetchone()
        self.assertEqual((row['revision'], row['active']), (first['keyRevision'], -1))
        self.assertEqual(f.store.operator_status()['state'], 'pending')
        self.assertEqual(f.store._db.execute('SELECT count(*) FROM identities').fetchone()[0], 0)
        with self.assertRaises(sessions.RecoverySessionError):
            f.store.authentication_options()
        with self.assertRaises(ValueError):
            f.engine.source_challenge(**parameters, phase='activation', request_id='8' * 64)

    def test_browser_handoff_requires_root_authorization_exact_delivery_and_saved_copy(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        prepared = f.engine.prepare_key(**parameters)
        binding = {**parameters, 'review_sha256': self.review_sha, 'key_revision': prepared['keyRevision'],
                   'delivery_epoch': prepared['deliveryEpoch']}
        key = f.delivery()['recoveryKey']
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('deliver', **binding, handoff='C' * 42 + 'A')
        with mock.patch.object(recovery_bootstrap.secrets, 'token_urlsafe', return_value='C' * 42 + 'A'):
            grant = f.engine.browser_key_handoff('authorize', **binding)['handoff']
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('confirm', **binding, handoff=grant, recovery_key=key)
        self.assertEqual(f.engine.browser_key_handoff('revoke', **binding), {'state': 'revoked'})
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('deliver', **binding, handoff=grant)
        with mock.patch.object(recovery_bootstrap.secrets, 'token_urlsafe', return_value='E' * 42 + 'A'):
            expired = f.engine.browser_key_handoff('authorize', **binding)['handoff']
        f.now += 300001
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('deliver', **binding, handoff=expired)
        with mock.patch.object(recovery_bootstrap.secrets, 'token_urlsafe', return_value='D' * 42 + 'A'):
            grant = f.engine.browser_key_handoff('authorize', **binding)['handoff']
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('deliver', **{**binding, 'delivery_epoch': '9' * 64}, handoff=grant)
        for _ in range(2):
            self.assertEqual(f.engine.browser_key_handoff('deliver', **binding, handoff=grant),
                             {'origin': f.origin, 'recoveryKey': key})
        self.assertIsNone(f.engine.status(operation_id=f.op)['ackReceiptId'])
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('confirm', **binding, handoff=grant, recovery_key='orbis-recovery-' + 'B' * 42 + 'A')
        for _ in range(2):
            self.assertEqual(f.engine.browser_key_handoff('confirm', **binding, handoff=grant, recovery_key=key),
                             {'origin': f.origin, 'state': 'acknowledged'})
        with self.assertRaises(ValueError):
            f.engine.browser_key_handoff('deliver', **binding, handoff=grant)
        self.assertEqual(f.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_reserved_delivery_crash_before_file_never_generates_another_key(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        with mock.patch.object(recovery_bootstrap, 'create_file', side_effect=OSError('fixture interrupted reservation')):
            with self.assertRaises(OSError):
                f.engine.prepare_key(**parameters)
        reservation = f.store._transaction(lambda: f.engine._load(f.op))['keyPreparation']
        self.assertEqual(len(reservation), 64)
        self.assertFalse((f.operation / 'delivery.json').exists())
        f.profiles.close(); f.store.close(); f.open()
        with mock.patch.object(f.engine, '_new_delivery', side_effect=AssertionError('missing key generated again')):
            with self.assertRaises(OSError):
                f.engine.prepare_key(**parameters)
        self.assertEqual(f.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 0)
        self.assertEqual(f.store._transaction(lambda: f.engine._load(f.op))['keyPreparation'], reservation)

    def test_crash_after_delivery_accepts_only_exact_reserved_bytes(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        save = f.engine._save
        def interrupt(record):
            if record['phase'] == 'key-prepared':
                raise OSError('fixture interrupted pending key commit')
            return save(record)
        with mock.patch.object(f.engine, '_save', side_effect=interrupt), self.assertRaises(OSError):
            f.engine.prepare_key(**parameters)
        path = f.operation / 'delivery.json'
        original = path.read_bytes()
        self.assertEqual(f.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 0)
        f.write(path, original + b'\n')
        with mock.patch.object(f.engine, '_new_delivery', side_effect=AssertionError('reserved key replaced')):
            with self.assertRaises(ValueError):
                f.engine.prepare_key(**parameters)
            f.write(path, original)
            self.assertEqual(f.engine.prepare_key(**parameters)['deliverySha256'], digest(original))

    def test_key_step_rechecks_original_c2_terminal_source_and_v1_before_issuing(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        record = f.store._transaction(lambda: f.engine._load(f.op))
        nonce = record['challenges'][record['heldStage']['requestId']]['nonce']
        captured = f.captures / f.op / ('proposal-' + digest(nonce.encode()))
        for path in (f.operation / 'held-stage-terminal.json', f.operation / 'review-plan.json',
                     self.host / 'credential-admission.json', f.captures.parent / 'recovery-admission-history.json',
                     captured / 'source.json', captured / 'witness.json'):
            with self.subTest(artifact=path.name):
                original = path.read_bytes()
                changed = encoded({**json.loads(original), 'descriptorSha256': 'f' * 64}) if path.name == 'witness.json' else original + b'\n'
                f.write(path, changed)
                try:
                    with self.assertRaises(ValueError):
                        f.engine.prepare_key(**parameters)
                finally:
                    f.write(path, original)
        self.assertFalse((f.operation / 'delivery.json').exists())

    def test_expired_or_missing_recorded_delivery_holds_same_key(self):
        self.exercise('complete')
        f = self.fixture
        parameters = {'operation_id': f.op, 'plan_sha256': f.plan_sha}
        first = f.engine.prepare_key(**parameters)
        path = f.operation / 'delivery.json'
        initial_sha = digest(path.read_bytes())
        moved = f.operation / 'fixture-preserved-delivery.json'
        path.rename(moved)
        with mock.patch.object(f.engine, '_new_delivery', side_effect=AssertionError('missing key regenerated')):
            with self.assertRaises(OSError):
                f.engine.prepare_key(**parameters)
            moved.rename(path)
            f.now = first['expiresAtMs'] + 1
            with self.assertRaises(ValueError):
                f.engine.prepare_key(**parameters)
            with self.assertRaises(ValueError):
                f.engine.held_key_status(**parameters)
        self.assertEqual(digest(path.read_bytes()), initial_sha)
        self.assertEqual(f.engine.status(operation_id=f.op)['keyRevision'], first['keyRevision'])

    def start_sole_runtime(self):
        from orbis_sentinel import recovery_runtime as runtime
        f = self.fixture
        self.close()
        f.profiles.close()
        f.store.close()
        self.start(mock.patch.object(runtime, '_require_root'))
        workers = []
        def open_worker(store, **_):
            workers.append(store)
            return SimpleNamespace(inspect=f.description, inspect_content=f.content,
                                   inspect_effective_content=f.content, verify=mock.Mock(), verify_counter=mock.Mock(),
                                   close=mock.Mock(), capability=mock.Mock())
        self.start(mock.patch.object(runtime, 'RecoveryWorker', side_effect=open_worker))
        active = []
        def observe(engine, **options):
            active.append(engine)
            return RootBootstrapControl(engine, **options)
        self.start(mock.patch.object(runtime, 'RootBootstrapControl', side_effect=observe))
        ready, stop = threading.Event(), threading.Event()
        errors = []
        def run():
            try:
                runtime.run_recovery(directory=str(f.root), image_id=self.review['collector']['imageId'], origin=f.origin,
                    address=('127.0.0.1', 0), status=lambda: {}, stop=stop, ready=lambda _: ready.set(), control=True)
            except Exception as error:
                errors.append(error)
                ready.set()
        thread = threading.Thread(target=run)
        thread.start()
        def drain():
            stop.set()
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
        self.addCleanup(drain)
        self.assertTrue(ready.wait(3))
        self.assertEqual(errors, [])
        self.assertEqual(len(active), 1)
        self.assertEqual(workers, [active[0].store])
        f.engine = active[0]
        f.store = active[0].store
        self.path = f.root / 'bootstrap-control.sock'

    def test_outer_lease_client_through_run_recovery_uses_sole_store_and_reads_terminal(self):
        from orbis_sentinel import credential_floor
        from orbis_sentinel.bootstrap_supervisor import PublishedBootstrapSupervisor
        self.start_sole_runtime()
        f = self.fixture
        self.start(mock.patch.object(bootstrap_control, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(RootBootstrapControlClient, '_peer', return_value=True))
        client = RootBootstrapControlClient(str(self.path), timeout=3)
        preflight = client.call('bootstrap-held-review', {'operationId': f.op, 'reviewSha256': self.review_sha})
        self.assertEqual(preflight['phase'], 'review-capture-ready')
        host_source = f.base / 'held-host-source'
        host_source.mkdir(mode=0o700)
        for name, body in self.bodies.items():
            f.write(host_source / name, body)
        self.start(mock.patch.object(execution, 'HOST_SOURCE', host_source))
        offer, request = self.packet()
        inventory = execution.CollectorExecutionInventory.open_installed({n: digest(b) for n, b in self.bodies.items()})
        self.addCleanup(inventory.close)
        scope = {'root': self.review['root'], 'context': self.review['context'], 'request': request,
                 'holdBinding': self.review_sha}
        lease = lease_fixture(self, inventory, scope, {'installationId': f.installation, 'sourceSha256': offer['sourceSha256'],
            'descriptorSha256': offer['descriptorSha256']}, capsule_body=self.capsule.read_bytes(), reported_pid=42)
        self.start(mock.patch.object(execution, '_pidfd_exited', side_effect=lambda _: lease._process.poll() is not None))
        read_end, write_end = os.pipe()
        terminal, transferred = socket.socketpair()
        errors = []
        def child():
            try:
                with terminal:
                    for _ in range(2):
                        frame, _ = execution.receive_frame(terminal, time.monotonic() + 3)
                        execution.send_frame(terminal, {**frame, 'step': 'checked',
                            'capsuleIdentity': list(lease._capsule_identity[:2]),
                            **{key: offer[key] for key in ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256')}},
                            time.monotonic() + 3)
            except Exception as error:
                errors.append(error)
        child_thread = threading.Thread(target=child)
        child_thread.start()
        def transfer(request_id):
            self.assertEqual(request_id, offer['requestId'])
            return os.dup(read_end), os.dup(lease._capsule_fd), os.dup(transferred.fileno())

        @contextmanager
        def installed(operation, review_sha256):
            self.assertEqual((operation, review_sha256), (f.op, self.review_sha))
            with bootstrap_source.PrivateDirectory(f.operation) as directory:
                yield self.review, directory, inventory, inventory.verify

        parameters = {'operation_id': f.op, 'review_sha256': self.review_sha,
                      'plan_sha256': f.plan_sha, 'request_id': offer['requestId']}
        try:
            with mock.patch.object(credential_floor, 'RECOVERY_ROOT', f.root):
                supervisor = PublishedBootstrapSupervisor()
            supervisor.client = client
            with (mock.patch.object(lease, 'open_held_proof', side_effect=transfer),
                  mock.patch.object(supervisor, '_published', side_effect=installed),
                  mock.patch.object(inventory, 'capture', return_value=lease) as capture):
                result = supervisor.stage(**parameters)
                self.assertEqual(supervisor.stage(**parameters), result)
                capture.assert_called_once_with(root=self.review['root'], context='local', request=request,
                                                hold_binding=self.review_sha, held_stage=True)
            status = client.call('bootstrap-status', {'operationId': f.op})
            self.assertEqual(result, status)
            self.assertEqual(status['terminalReceiptSha256'], digest((f.operation / 'held-stage-terminal.json').read_bytes()))
            self.assertEqual((status['phase'], status['generation'], status['keyRevision']), ('held-stage-complete', 1, None))
            self.assertEqual(lease._process.returncode, 0)
            key_parameters = {key: value for key, value in parameters.items() if key != 'request_id'}
            with (mock.patch.object(supervisor, '_published', side_effect=installed),
                  tempfile.TemporaryDirectory(prefix='saved-key-c3-') as output):
                key = supervisor.prepare_key(**key_parameters)
                self.assertEqual(key['phase'], 'key-prepared')
                original = f.operation / 'delivery.json'
                destination = Path(output).resolve() / 'my-saved-key'
                os.chmod(destination.parent, 0o700)
                foreign = destination.with_name('existing')
                f.write(foreign, b'unrelated private data\n')
                with self.assertRaises(ValueError):
                    supervisor.save_key(**key_parameters, destination=str(foreign))
                self.assertEqual(foreign.read_bytes(), b'unrelated private data\n')
                alias = destination.with_name('alias')
                alias.symlink_to(foreign)
                with self.assertRaises((ValueError, OSError)):
                    supervisor.save_key(**key_parameters, destination=str(alias))
                result = supervisor.save_key(**key_parameters, destination=str(destination))
                self.assertEqual(supervisor.save_key(**key_parameters, destination=str(destination)), result)
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                from_saved_copy = destination.read_bytes().rstrip(b'\n').decode('ascii')
                self.assertTrue(from_saved_copy == json.loads(original.read_bytes())['recoveryKey'])
                with mock.patch('orbis_sentinel.bootstrap_supervisor._read_saved_key', return_value=from_saved_copy) as prompt:
                    ack = supervisor.acknowledge_key(**key_parameters)
                    self.assertEqual(supervisor.acknowledge_key(**key_parameters), ack)
                    self.assertEqual(prompt.call_count, 2)
                self.assertEqual((supervisor.status(**key_parameters)['phase'], f.store.operator_status()['state']),
                                 ('acknowledged', 'pending'))
                self.assertEqual(digest(original.read_bytes()), key['deliverySha256'])
                with self.assertRaises(sessions.RecoverySessionError):
                    f.store.authentication_options()
        finally:
            terminal.close()
            transferred.close()
            os.close(read_end)
            os.close(write_end)
            child_thread.join(5)
            self.assertFalse(child_thread.is_alive())
            self.assertEqual(errors, [])

    def test_retained_coordinator_joins_actual_c3b_listener_through_outer_lease(self):
        from orbis_sentinel import credential_floor
        from orbis_sentinel.bootstrap_supervisor import PublishedBootstrapSupervisor
        self.start_sole_runtime()
        f = self.fixture
        self.start(mock.patch.object(bootstrap_control, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(RootBootstrapControlClient, '_peer', return_value=True))
        host_source = f.base / 'held-host-source'
        host_source.mkdir(mode=0o700)
        for name, body in self.bodies.items():
            f.write(host_source / name, body)
        self.start(mock.patch.object(execution, 'HOST_SOURCE', host_source))
        approved = self.approved_activation()
        activation = self.activation_input(approved)
        offer, request = self.packet(activating=activation)
        inventory = execution.CollectorExecutionInventory.open_installed({name: digest(body) for name, body in self.bodies.items()})
        self.addCleanup(inventory.close)
        scope = {'root': self.review['root'], 'context': 'local', 'request': request, 'holdBinding': self.review_sha}
        lease = lease_fixture(self, inventory, scope, {'installationId': f.installation, 'sourceSha256': offer['sourceSha256'],
            'descriptorSha256': offer['descriptorSha256']}, capsule_body=self.capsule.read_bytes(), reported_pid=42)
        self.start(mock.patch.object(execution, '_pidfd_exited', side_effect=lambda _: lease._process.poll() is not None))
        read_end, write_end = os.pipe()
        peer, transferred = socket.socketpair()
        errors = []

        def collector():
            try:
                with peer:
                    for _ in range(2):
                        frame, _ = execution.receive_frame(peer, time.monotonic() + 3)
                        self.assertEqual(frame['schema'], execution.HELD_ACTIVATION)
                        execution.send_frame(peer, {**frame, 'step': 'checked',
                            'capsuleIdentity': list(lease._capsule_identity[:2]),
                            **{key: offer[key] for key in ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256')}},
                            time.monotonic() + 3)
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=collector)
        thread.start()

        def transfer(request_id):
            self.assertEqual(request_id, activation[0])
            return os.dup(read_end), os.dup(lease._capsule_fd), os.dup(transferred.fileno())

        @contextmanager
        def installed(operation, review_sha256):
            self.assertEqual((operation, review_sha256), (f.op, self.review_sha))
            with bootstrap_source.PrivateDirectory(f.operation) as directory:
                yield self.review, directory, inventory, inventory.verify

        try:
            with mock.patch.object(credential_floor, 'RECOVERY_ROOT', f.root):
                supervisor = PublishedBootstrapSupervisor()
            supervisor.client = RootBootstrapControlClient(str(self.path), timeout=3)
            scope = {'operation_id': f.op, 'review_sha256': self.review_sha, 'plan_sha256': f.plan_sha, 'packet_sha256': approved[1]}
            with (mock.patch.object(lease, 'open_held_proof', side_effect=transfer),
                  mock.patch.object(supervisor, '_published', side_effect=installed),
                  mock.patch.object(inventory, 'capture', return_value=lease) as capture):
                result = supervisor.activate_held(**scope)
                self.assertEqual(supervisor.activate_held(**scope), result)
                capture.assert_called_once_with(root=self.review['root'], context='local', request=request,
                                                hold_binding=self.review_sha, held_stage=True)
            self.assertEqual(result['terminalReceiptSha256'], digest((f.operation / 'held-activation-terminal.json').read_bytes()))
            self.assertEqual(result['commitSha256'], approved[0]['candidate']['projectedCommitSha256'])
            self.assertEqual(lease._process.returncode, 0)
            with self.assertRaises(sessions.RecoverySessionError):
                f.store.authentication_options()
        finally:
            peer.close()
            transferred.close()
            os.close(read_end)
            os.close(write_end)
            thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])


class BootstrapDispatcherTests(unittest.TestCase):
    def test_only_exact_selected_options_dispatch_and_key_argument_never_echoes(self):
        from orbis_sentinel import bootstrap_supervisor, runtime
        common = ['--bootstrap-operation', '1' * 64, '--review-sha256', '2' * 64]
        supplied_plan = ['--plan-sha256', '3' * 64]
        with mock.patch.object(bootstrap_supervisor, 'run_published_bootstrap', return_value=0) as dispatch:
            self.assertEqual(runtime.main(['--bootstrap', 'save-key', *common, *supplied_plan,
                                           '--save-key-to', '/protected/private/user-selected']), 0)
            dispatch.assert_called_once_with('save-key', '1' * 64, '2' * 64, '3' * 64,
                                             request=None, destination='/protected/private/user-selected')
            for other_args in (['--bootstrap', 'stage', *common, *supplied_plan],
                               ['--bootstrap', 'status', *common, *supplied_plan, '--observer-socket', '/unused'],
                               ['--bootstrap', 'acknowledge-key', *common, *supplied_plan, '--key', 'private-input-fixture'],
                               ['--systemd-socket', *common]):
                with self.subTest(mode=other_args[1]), redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                    runtime.main(other_args)
                self.assertNotIn('private-input-fixture', stderr.getvalue())
            self.assertEqual(dispatch.call_count, 1)

    def test_hidden_tty_refuses_fallback_before_key_entry(self):
        import getpass
        import warnings
        from orbis_sentinel.bootstrap_supervisor import _read_saved_key
        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        handle.isatty.return_value = True
        with (mock.patch('builtins.open', return_value=handle) as opened,
              mock.patch.object(getpass, 'getpass', side_effect=lambda *_args, **_kwargs: warnings.warn(
                  'fixture fallback', getpass.GetPassWarning)), self.assertRaises(getpass.GetPassWarning)):
            _read_saved_key()
        opened.assert_called_once_with('/dev/tty', 'r+', encoding='utf-8')


if __name__ == '__main__': unittest.main()
