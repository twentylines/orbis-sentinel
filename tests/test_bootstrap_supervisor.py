"""Actual Root engine/files/SQLite and actual ExecutionLease/private Popen pipe.

Host/PG/capture code and portable process/sealed-FD observations are explicit
code-owned fixtures. Crypto is the existing synthetic bootstrap worker seam.
No publisher, native/kernel/Host/PG, key or activation qualification is claimed.
"""
import copy
import json
import os
import secrets
from pathlib import Path
import unittest
from unittest import mock

from orbis_sentinel import collector_execution as execution, credential_floor
from orbis_sentinel.bootstrap_source import PrivateDirectory, CollectedSource, encoded, digest
from orbis_sentinel.bootstrap_supervisor import BootstrapSupervisor, BootstrapSupervisorError
from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel.recovery_profiles import RecoveryProfiles, RecoveryProfileError
from orbis_sentinel.recovery_incarnations import RecoveryIncarnations
from orbis_sentinel.recovery_bootstrap import RecoveryBootstrap
import test_collector_execution as execution_fixtures


class BootstrapSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = execution_fixtures.FixtureInventory('test_whole_inventory_is_held_and_never_becomes_publisher_authority')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)
        self.base = self.fixture.base
        self.inventory = self.fixture.open()
        self.root = self.directory(self.base / 'main')
        self.state = self.directory(self.base / 'state')
        patch = mock.patch.object(credential_floor, 'STATE_ROOT', self.state)
        patch.start(); self.addCleanup(patch.stop)
        self.namespace = self.state / 'installations' / digest(os.fsencode(str(self.root)))
        self.namespace.mkdir(mode=0o700, parents=True); self.namespace.parent.chmod(0o700)
        self.captures = self.directory(self.namespace / 'bootstrap-sources')
        self.recovery = self.directory(self.base / 'recovery')
        self.store = sessions.RecoverySessions(self.recovery)
        self.addCleanup(self.store.close)
        self.now = self.store._now()
        self.op, self.installation = '1' * 64, '2' * 64
        self.origin = 'https://recovery.example'
        self.credential = secrets.token_urlsafe(16)
        self.raw = encoded({'schema': 'synthetic-source-only', 'revision': 'a' * 64, 'accountId': 1,
            'origin': self.origin, 'operator': True, 'passwordHash': 'synthetic-private-fixture', 'counter': 3})
        self.worker_calls = []
        self.profiles = RecoveryProfiles(self.store, inspect=self.description, verify=lambda *_args: None)
        self.addCleanup(self.profiles.close)
        self.incarnations = RecoveryIncarnations(self.store, self.profiles, inspect=self.content, origin=self.origin)
        self.engine = RecoveryBootstrap(self.store, self.profiles, self.incarnations, origin=self.origin)
        self.operation = self.recovery / 'bootstrap' / self.op
        self.operation.mkdir(mode=0o700, parents=True); self.operation.parent.chmod(0o700)
        self.review_plan = {'schema': 'orbis.sentinel-bootstrap-review.v1', 'operationId': self.op,
            'root': str(self.root), 'context': 'fixture-local', 'installationId': self.installation, 'origin': self.origin,
            'captureRoot': str(self.captures), 'collector': {'protocol': 'orbis.stopped-main-source.v1',
                'programSha256': digest(self.inventory.bodies['orbis-host-recovery-source.py']),
                'imageId': 'sha256:' + '3' * 64, 'inventorySha256': self.inventory.inventory_sha256}, 'hostHistorySha256': None}
        self.review_sha = self.write(self.operation / 'review-plan.json', self.review_plan)
        self.write(self.operation / 'review-approval.json', {'schema': 'orbis.sentinel-bootstrap-review-approval.v1',
            'operationId': self.op, 'reviewSha256': self.review_sha, 'installationId': self.installation, 'approvalId': '4' * 64})
        self.supervisor = BootstrapSupervisor(self.engine, self.inventory)
        self.captures_seen, self.leases = [], []
        self.mode, self.capture_raw, self.mutate_witness, self.after_capture = 'normal', None, None, None
        patch = mock.patch.object(execution.CollectorExecutionInventory, 'capture', self.capture_fixture)
        patch.start(); self.addCleanup(patch.stop)

    def directory(self, path):
        path.mkdir(mode=0o700)
        return path

    def write(self, path, value):
        body = value if type(value) is bytes else encoded(value)
        path.write_bytes(body); path.chmod(0o600)
        return digest(body)

    def description(self, directory, expected):
        body = Path(directory, 'identity.json').read_bytes()
        self.assertEqual(digest(body), expected)
        value = json.loads(body)
        if value.get('operator') is not True:
            raise ValueError('Synthetic worker refuses nonoperators')
        self.worker_calls.append(('description', expected))
        return {'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': expected,
            'revision': value['revision'], 'accountId': value['accountId'], 'origin': value['origin'],
            'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {self.credential: value['counter']}}

    def content(self, directory, expected):
        value = json.loads(Path(directory, 'identity.json').read_bytes())
        self.worker_calls.append(('content', expected))
        return {'schema': 'orbis.sentinel-identity-content.v1', 'identitySha256': expected,
            'contentSha256': digest(encoded({k: v for k, v in value.items() if k != 'revision'})),
            'description': self.description(directory, expected)}

    def capture_fixture(self, *, root, context, request, hold_binding):
        """Temporary actual artifacts+Popen; production Host capture is NOT invoked."""
        self.assertEqual(root, str(self.root)); self.assertEqual(context, 'fixture-local')
        self.assertEqual(hold_binding, self.review_sha)
        self.captures_seen.append(copy.deepcopy(request))
        path = self.captures / request['operationId'] / (request['phase'] + '-' + digest(request['collectionNonce'].encode()))
        path.parent.mkdir(mode=0o700, exist_ok=True); path.mkdir(mode=0o700)
        source = self.capture_raw or self.raw
        descriptor = {'installationId': self.installation, 'origin': self.origin,
            'collector': {'protocol': 'orbis.stopped-main-source.v1', 'programSha256': self.review_plan['collector']['programSha256'],
                          'pid': os.getpid(), 'startTicks': 1},
            'exporter': {'cid': '5' * 64, 'imageId': self.review_plan['collector']['imageId'], 'phase': 'awaiting-root-ack'}}
        witness = {'schema': 'orbis.bootstrap-source-witness.v1', **request,
            'sourceSha256': digest(source), 'descriptorSha256': digest(encoded(descriptor)), 'descriptor': descriptor,
            'capturedAtMs': self.store._now()}
        del witness['origin']
        if self.mutate_witness:
            self.mutate_witness(witness)
        self.write(path / 'source.json', source); self.write(path / 'witness.json', witness)
        scope = execution._scope(root, context, request, hold_binding)
        lease = execution_fixtures.lease_fixture(self, self.inventory, scope, {'installationId': self.installation,
            'sourceSha256': digest(source), 'descriptorSha256': witness['descriptorSha256']}, mode=self.mode)
        self.leases.append(lease)
        if self.after_capture:
            self.after_capture()
        return lease

    def review(self):
        return self.supervisor.review(operation_id=self.op, review_sha256=self.review_sha)

    def approve_plan(self):
        plan = self.supervisor.prepare_plan(operation_id=self.op, review_sha256=self.review_sha)
        self.plan_sha = plan['planSha256']
        self.write(self.operation / 'approval.json', {'schema': 'orbis.sentinel-bootstrap-approval.v1',
            'operationId': self.op, 'planSha256': self.plan_sha, 'installationId': self.installation, 'approvalId': '6' * 64})
        return plan

    def stage(self, supervisor=None, request='7' * 64):
        return (supervisor or self.supervisor).stage(operation_id=self.op, review_sha256=self.review_sha,
                                                    plan_sha256=self.plan_sha, request_id=request)

    def journal(self):
        return json.loads((self.operation / 'supervisor.json').read_bytes())

    def assert_inactive(self):
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM identities').fetchone()[0], 0)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0], 0)
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_actual_review_fresh_stage_and_terminal_are_one_owned_inactive_flow(self):
        reviewed = self.review()
        self.assertEqual(reviewed['sourceSha256'], digest(self.raw))
        self.assertEqual(len(self.captures_seen), 1)
        plan = self.approve_plan(); result = self.stage()
        self.assertEqual(result['phase'], 'source-staged-no-admission')
        self.assertEqual(result['authority'], 'inventory-execution-custody-only')
        self.assertEqual(result['sourceSha256'], plan['sourceSha256'])
        self.assertEqual(len(self.captures_seen), 2)
        self.assertNotEqual(self.captures_seen[0]['collectionNonce'], self.captures_seen[1]['collectionNonce'])
        self.assertEqual(self.captures_seen[0]['planSha256'], self.review_sha)
        self.assertEqual(self.captures_seen[1]['planSha256'], self.plan_sha)
        self.assertEqual(self.journal()['holdBinding'], self.review_sha)
        self.assertEqual(self.journal()['phase'], 'stage-complete')
        self.assertEqual(self.engine.status(operation_id=self.op)['phase'], 'staged')
        self.assertEqual(self.store.operator_status(), {'generation': 1, 'revision': None, 'state': 'pending'})
        self.assert_inactive()

    def test_inventory_and_staged_context_never_open_production_gates(self):
        self.review(); self.approve_plan(); self.stage()
        for item in (self.inventory, self.leases[-1]):
            with self.assertRaises(execution.ExecutionUnavailable): item.require_managed_admission()
        captured = CollectedSource(self.engine.sources, self.op, self.plan_sha, 'activation', 'A' * 43,
                                   self.raw, 'a' * 64)
        for method in (self.engine.sources.require_live_context, self.engine.sources.require_writer_floor):
            with self.assertRaises(ValueError): method(captured)
        self.assertFalse(hasattr(self.supervisor, 'activate'))
        self.assertFalse(hasattr(self.supervisor, 'prepare_key'))
        self.assert_inactive()

    def test_complete_review_and_plan_retries_never_recapture_or_approve(self):
        first = self.review(); plan = self.supervisor.prepare_plan(operation_id=self.op, review_sha256=self.review_sha)
        self.assertEqual(self.review(), first)
        other = BootstrapSupervisor(self.engine, self.inventory)
        self.assertEqual(other.review(operation_id=self.op, review_sha256=self.review_sha), first)
        self.assertEqual(other.prepare_plan(operation_id=self.op, review_sha256=self.review_sha), plan)
        self.assertEqual(len(self.captures_seen), 1)
        self.assertFalse((self.operation / 'approval.json').exists())
        self.assert_inactive()

    def test_complete_stage_retry_reads_actual_root_ledger_without_second_crypto(self):
        self.review(); self.approve_plan(); first = self.stage()
        calls = list(self.worker_calls)
        other = BootstrapSupervisor(self.engine, self.inventory)
        self.assertEqual(self.stage(other), first)
        self.assertEqual(self.worker_calls, calls)
        self.assertEqual(len(self.captures_seen), 2)
        with self.assertRaises(ValueError): self.stage(other, request='8' * 64)
        self.assert_inactive()

    def test_missing_or_wrong_review_approval_refuses_before_capture(self):
        path = self.operation / 'review-approval.json'
        approval = json.loads(path.read_bytes()); approval['reviewSha256'] = 'f' * 64; self.write(path, approval)
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.captures_seen, [])
        self.assertFalse((self.operation / 'supervisor.json').exists())
        self.assert_inactive()

    def test_scope_inventory_or_program_drift_refuses(self):
        original = self.review_plan
        for key in ('inventorySha256', 'programSha256'):
            value = copy.deepcopy(original); value['collector'][key] = 'f' * 64
            sha = self.write(self.operation / 'review-plan.json', value)
            self.write(self.operation / 'review-approval.json', {'schema': 'orbis.sentinel-bootstrap-review-approval.v1',
                'operationId': self.op, 'reviewSha256': sha, 'installationId': self.installation, 'approvalId': '4' * 64})
            with self.assertRaises(ValueError): self.supervisor.review(operation_id=self.op, review_sha256=sha)
        self.assertEqual(self.captures_seen, [])

    def test_final_plan_requires_independent_exact_approval(self):
        self.review(); plan = self.supervisor.prepare_plan(operation_id=self.op, review_sha256=self.review_sha)
        self.plan_sha = plan['planSha256']
        with self.assertRaises((ValueError, FileNotFoundError)): self.stage()
        self.assertEqual(len(self.captures_seen), 1)
        self.assert_inactive()

    def test_changed_physical_source_after_review_holds_before_root_stage(self):
        self.review(); self.approve_plan()
        self.capture_raw = self.raw + b' '
        with self.assertRaises(ValueError): self.stage()
        self.assertEqual(self.journal()['phase'], 'held')
        self.assertEqual(self.store.operator_status()['state'], 'never-enrolled')
        self.assert_inactive()

    def test_wrong_witness_nonce_consumes_actual_root_attempt_without_staging(self):
        self.review(); self.approve_plan()
        self.mutate_witness = lambda witness: witness.update(collectionNonce='B' * 43)
        with self.assertRaises((ValueError, RecoveryProfileError)): self.stage()
        record = self.store._transaction(lambda: self.engine._load(self.op))
        self.assertIs(record['challenges']['7' * 64]['consumed'], True)
        self.assertEqual(record['phase'], 'collecting')
        self.assertEqual(self.journal()['phase'], 'held')
        self.assert_inactive()

    def test_lost_challenge_reply_uses_actual_owned_nonce_once(self):
        self.review(); self.approve_plan()
        actual = self.engine.source_challenge
        def lost(**arguments):
            actual(**arguments)
            raise ConnectionError('synthetic dropped reply')
        with mock.patch.object(self.engine, 'source_challenge', side_effect=lost) as calls:
            self.assertEqual(self.stage()['phase'], 'source-staged-no-admission')
        self.assertEqual(calls.call_count, 1)
        record = self.store._transaction(lambda: self.engine._load(self.op))
        self.assertEqual(len(record['challenges']), 1)
        self.assertEqual(record['challenges']['7' * 64]['nonce'], self.journal()['stageNonce'])
        self.assert_inactive()

    def test_wrong_challenge_reply_cannot_replace_actual_ledger_nonce(self):
        self.review(); self.approve_plan()
        actual = self.engine.source_challenge
        def wrong(**arguments):
            return {**actual(**arguments), 'collectionNonce': 'B' * 43}
        with mock.patch.object(self.engine, 'source_challenge', side_effect=wrong):
            with self.assertRaises(ValueError): self.stage()
        self.assertEqual(len(self.captures_seen), 1)
        self.assert_inactive()

    def test_lost_stage_reply_is_resolved_by_actual_sql_receipt_and_terminal(self):
        self.review(); self.approve_plan()
        actual = self.engine.stage
        def lost(**arguments):
            actual(**arguments)
            raise ConnectionError('synthetic dropped stage reply')
        with mock.patch.object(self.engine, 'stage', side_effect=lost) as calls:
            self.assertEqual(self.stage()['phase'], 'source-staged-no-admission')
        self.assertEqual(calls.call_count, 1)
        self.assertEqual(self.journal()['rootReceipt'], self.engine.status(operation_id=self.op))
        self.assert_inactive()

    def test_nonzero_terminal_after_root_stage_remains_held_across_new_owner(self):
        self.review(); self.approve_plan(); self.mode = 'nonzero-finish'
        with self.assertRaises(ValueError): self.stage()
        self.assertEqual(self.engine.status(operation_id=self.op)['phase'], 'staged')
        self.assertEqual(self.journal()['phase'], 'held')
        calls = list(self.worker_calls)
        with self.assertRaises(ValueError): self.stage(BootstrapSupervisor(self.engine, self.inventory))
        self.assertEqual(self.worker_calls, calls)
        self.assertEqual(len(self.captures_seen), 2)
        self.assert_inactive()

    def test_wrong_live_check_never_completes_review(self):
        self.mode = 'wrong-check'
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.journal()['phase'], 'held')
        self.assertFalse((self.operation / 'plan.json').exists())
        self.assert_inactive()

    def test_trailing_terminal_never_completes_review(self):
        self.mode = 'trailing-finish'
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.journal()['phase'], 'held')
        self.assertFalse((self.operation / 'plan.json').exists())
        self.assert_inactive()

    def test_existing_root_lineage_is_refused_before_any_executor_hold(self):
        self.store._db.execute('UPDATE operator_enrollment SET generation=1 WHERE id=1')
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.captures_seen, [])
        self.assertFalse((self.operation / 'supervisor.json').exists())

    def test_file_validation_error_after_stage_commit_is_not_a_lost_reply(self):
        self.review(); self.approve_plan()
        actual = self.engine.stage
        def invalid(**arguments):
            actual(**arguments)
            raise ValueError('synthetic postcommit file drift; not a transport reply')
        with mock.patch.object(self.engine, 'stage', side_effect=invalid):
            with self.assertRaises(ValueError): self.stage()
        self.assertEqual(self.engine.status(operation_id=self.op)['phase'], 'staged')
        self.assertEqual(self.journal()['phase'], 'held')
        self.assert_inactive()

    def test_unknown_pending_journal_is_not_adopted_or_deleted(self):
        path = self.operation / 'supervisor.pending.json'; self.write(path, b'unknown preserved evidence')
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(path.read_bytes(), b'unknown preserved evidence')
        self.assertEqual(self.captures_seen, [])

    def test_real_operation_lock_excludes_another_supervisor(self):
        other = BootstrapSupervisor(self.engine, self.inventory)
        with self.supervisor._operation(self.op, self.review_sha):
            with self.assertRaises((ValueError, BlockingIOError)):
                other.review(operation_id=self.op, review_sha256=self.review_sha)
        self.assertEqual(self.captures_seen, [])

    def test_source_only_review_cannot_cross_existing_managed_history(self):
        self.write(self.namespace / 'recovery-admission-history.json', {'schema': 'orbis.recovery-admission-history.v1',
            'mode': 'managed', 'managedEver': True, 'installationId': self.installation})
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.captures_seen, [])
        self.assert_inactive()

    def test_replaced_review_inode_during_capture_holds_without_plan(self):
        def replace():
            path = self.operation / 'review-plan.json'
            replacement = self.operation / 'same-bytes.json'; self.write(replacement, path.read_bytes()); replacement.replace(path)
        self.after_capture = replace
        with self.assertRaises(ValueError): self.review()
        self.assertEqual(self.journal()['phase'], 'held')
        self.assertFalse((self.operation / 'plan.json').exists())
        self.assert_inactive()

    def test_forged_complete_journal_without_root_receipt_cannot_stage(self):
        self.review(); self.approve_plan()
        value = self.journal()
        nonce = 'A' * 43
        value.update(phase='stage-complete', planSha256=self.plan_sha, requestId='7' * 64, stageNonce=nonce,
                     rootReceipt={'phase': 'staged', 'identitySha256': 'f' * 64})
        evidence = copy.deepcopy(value['reviewEvidence'])
        evidence['request'] = self.supervisor._request(self.review_plan, self.plan_sha, nonce)
        value['stageEvidence'] = evidence
        self.write(self.operation / 'supervisor.json', value)
        with self.assertRaises(ValueError): self.stage()
        self.assertEqual(self.store._db.execute('SELECT count(*) FROM bootstrap_operations').fetchone()[0], 0)
        self.assertEqual(len(self.captures_seen), 1)
        self.assert_inactive()

    def test_opaque_execution_constructor_and_wrong_inventory_never_qualify(self):
        with self.assertRaises(ValueError): BootstrapSupervisor(self.engine, object())
        with self.assertRaises(ValueError): BootstrapSupervisor(object(), self.inventory)
        self.review()
        with self.assertRaises(ValueError): self.leases[-1].require_inventory(object())
        self.assert_inactive()


if __name__ == '__main__':
    unittest.main()
