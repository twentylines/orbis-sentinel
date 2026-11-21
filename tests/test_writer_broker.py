import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import unittest
from contextlib import contextmanager, nullcontext
from unittest import mock

from orbis_sentinel import writer_broker as broker
from orbis_sentinel import writer_journal as journal


class LifecycleFixture:
    """Ordering fixture; real host lock/custody is qualified separately."""
    def __init__(self):
        self.marker, self.held, self.fail_begin, self.fail_finish = None, False, False, False
        self.events = []

    @contextmanager
    def operation(self):
        assert not self.held
        self.held = True
        try:
            yield self
        finally:
            self.held = False

    def read(self):
        assert self.held
        return copy.deepcopy(self.marker)

    def begin(self, operation, binding):
        assert self.held
        if self.fail_begin:
            raise OSError('Synthetic lifecycle marker failure')
        value = {'operationId': operation, 'admissionBinding': binding}
        assert self.marker in (None, value)
        self.marker = value
        self.events.append('begin')

    def finish(self, operation, binding, *, verify_completed):
        assert self.held and verify_completed() is True
        if self.fail_finish:
            raise OSError('Synthetic lifecycle release failure')
        assert self.marker in (None, {'operationId': operation, 'admissionBinding': binding})
        self.marker = None
        self.events.append('finish')


class ControlFixture:
    """Control-port state machine; native proof uses the genuine Root protocol."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.status = {'generation': 1, 'revision': 'a' * 64, 'state': 'enrolled'}
        self.calls, self.pending, self.request = [], None, None
        self.drop_prepare, self.drop_complete = False, False

    def call(self, operation, arguments):
        self.calls.append(operation)
        if operation == 'operator-status':
            return copy.deepcopy(self.status)
        if operation == 'operator-writer-eligibility':
            return {'schema': 'orbis.sentinel-operator-writer-eligibility.v1',
                    'generation': self.status['generation'], 'revision': self.status['revision'],
                    'eligible': self.status['state'] == 'enrolled'}
        state = json.loads((self.directory / 'state.json').read_text())
        record = state['operations'][state['active']]
        assert record['changeToken'] == arguments['changeToken']
        if operation == 'operator-prepare-writer':
            assert record['phase'] == 'begin-requested'
            baseline = hashlib.sha256(base64.b64decode(arguments['baselineIdentityBase64'])).hexdigest()
            planned = hashlib.sha256(base64.b64decode(arguments['identityBase64'])).hexdigest()
            request = copy.deepcopy(arguments)
            if self.pending is not None:
                assert self.request == request and self.status == {'generation': 2, 'revision': None, 'state': 'pending'}
            else:
                assert self.status == {'generation': 1, 'revision': 'a' * 64, 'state': 'enrolled'}
                self.request = request
                self.pending = {'baselineSha256': baseline, 'sourceSha256': planned, 'identitySha256': 'd' * 64,
                                'revision': 'e' * 64, 'contentSha256': 'f' * 64, 'generation': 2}
                self.status = {'generation': 2, 'revision': None, 'state': 'pending'}
            if self.drop_prepare:
                self.drop_prepare = False
                raise TimeoutError('Synthetic response lost after commit')
            return copy.deepcopy(self.pending)
        if operation == 'operator-complete-incarnation':
            assert record['phase'] == 'complete-requested' and record['observedSha256'] == record['plannedSha256']
            assert self.pending is not None and arguments['expectedGeneration'] == 2
            assert self.status == {'generation': 2, 'revision': None, 'state': 'pending'}
            assert hashlib.sha256(base64.b64decode(arguments['identityBase64'])).hexdigest() == self.pending['sourceSha256']
            self.status = {'generation': 3, 'revision': self.pending['revision'], 'state': 'enrolled'}
            if self.drop_complete:
                self.drop_complete = False
                raise TimeoutError('Synthetic completion response lost')
            return copy.deepcopy(self.status)
        raise AssertionError('Unexpected control operation')


class WriterBrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='writer-')
        self.addCleanup(self.temp.cleanup)
        patch = mock.patch.object(journal, '_OWNER_UID', os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.context = {'schema': 'orbis.sentinel-writer-admission.v1', 'mode': 'managed', 'installationId': '1' * 64,
                        'controllerId': '2' * 64, 'imageId': 'sha256:' + '3' * 64, 'controllerEpoch': '4' * 64,
                        'origin': 'https://recovery.example', 'recoveryEpoch': '5' * 64}
        self.control = ControlFixture(self.temp.name)
        self.baseline, self.planned = b'{"syntheticBaseline":true}', b'{"syntheticPlannedPrivateValue":true}'
        self.request = secrets.token_hex(32)
        self.instance = self.open(create=True)
        self.binding = self.instance.admission()['binding']

    def open(self, **kwargs):
        value = broker.WriterBroker(self.temp.name, control=self.control, admit=lambda: copy.deepcopy(self.context), **kwargs)
        self.addCleanup(value.close)
        return value

    def prepare(self, **changes):
        return self.instance.prepare(**{**dict(request_id=self.request, admission_binding=self.binding,
                                              baseline_identity=self.baseline, planned_identity=self.planned), **changes})

    def complete(self, receipt, body=None):
        return self.instance.complete(operation_id=receipt['operationId'], admission_binding=self.binding,
                                      current_identity=body if body is not None else self.planned)

    def use_lifecycle(self):
        self.instance.close()
        self.lifecycle = LifecycleFixture()
        self.instance = self.open(lifecycle=self.lifecycle)

    def test_lifecycle_marker_precedes_root_mutation_and_release_follows_completed_journal(self):
        self.use_lifecycle()
        original = self.control.call

        def call(operation, arguments):
            self.assertTrue(self.lifecycle.held)
            if operation not in ('operator-status', 'operator-writer-eligibility'):
                state = self.instance.journal.read()
                self.assertEqual(self.lifecycle.marker['operationId'], state['active'])
                self.assertEqual(self.lifecycle.marker['admissionBinding'], self.binding)
            return original(operation, arguments)

        self.control.call = call
        receipt = self.prepare()
        self.assertIsNotNone(self.lifecycle.marker)
        self.assertFalse(self.lifecycle.held)
        self.assertTrue(self.instance.blocks_lifecycle())
        self.complete(receipt)
        self.assertIsNone(self.lifecycle.marker)
        self.assertFalse(self.instance.blocks_lifecycle())
        self.assertEqual(self.lifecycle.events, ['begin', 'finish'])

    def test_lifecycle_begin_failure_has_no_intent_or_root_mutation(self):
        self.use_lifecycle()
        self.lifecycle.fail_begin = True
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.assertIsNone(self.instance.journal.read()['active'])
        self.assertNotIn('operator-prepare-writer', self.control.calls)

    def test_writer_eligibility_failures_precede_fence_and_source_retention(self):
        self.use_lifecycle()
        original = self.control.call
        valid = original('operator-writer-eligibility', {})
        invalid = [None, True, {}, {**valid, 'eligible': False}, {**valid, 'eligible': 1},
                   {**valid, 'generation': True}, {**valid, 'generation': 2},
                   {**valid, 'revision': 'b' * 64}, {**valid, 'extra': True}]
        for value in invalid:
            with self.subTest(value=value):
                self.control.call = lambda operation, args: value if operation == 'operator-writer-eligibility' else original(operation, args)
                with mock.patch.object(self.instance.journal, 'retain', wraps=self.instance.journal.retain) as retained:
                    with self.assertRaises(broker.WriterBrokerError):
                        self.prepare()
                    retained.assert_not_called()
                self.assertIsNone(self.lifecycle.marker)
                self.assertIsNone(self.instance.journal.read()['active'])
        self.assertNotIn('operator-prepare-writer', self.control.calls)

    def test_crash_after_marker_before_intent_remains_held_in_new_broker(self):
        self.use_lifecycle()
        with mock.patch.object(self.instance.journal, 'save', side_effect=OSError('Synthetic intent failure')):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare()
        self.assertIsNotNone(self.lifecycle.marker)
        self.assertNotIn('operator-prepare-writer', self.control.calls)
        self.instance.close()
        self.instance = self.open(lifecycle=self.lifecycle)
        with self.assertRaises(broker.WriterBrokerError):
            self.instance.admission()
        self.assertIsNotNone(self.lifecycle.marker)

    def test_lost_prepare_reply_preserves_same_lifecycle_marker(self):
        self.use_lifecycle()
        self.control.drop_prepare = True
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        marker = copy.deepcopy(self.lifecycle.marker)
        self.instance.close()
        self.instance = self.open(lifecycle=self.lifecycle)
        receipt = self.prepare()
        self.assertEqual(self.lifecycle.marker, marker)
        self.assertEqual(receipt['operationId'], marker['operationId'])
        self.complete(receipt)
        self.assertIsNone(self.lifecycle.marker)

    def test_release_failure_reconciles_only_exact_completed_source_without_repeating_root_completion(self):
        self.use_lifecycle()
        receipt = self.prepare()
        self.lifecycle.fail_finish = True
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt)
        state = self.instance.journal.read()
        self.assertIsNone(state['active'])
        self.assertEqual(state['operations'][receipt['operationId']]['phase'], 'completed')
        self.assertTrue(self.instance.blocks_lifecycle())
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare(request_id=secrets.token_hex(32))
        self.lifecycle.fail_finish = False
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt, body=self.baseline)
        self.assertIsNotNone(self.lifecycle.marker)
        self.complete(receipt)
        self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 1)
        self.assertIsNone(self.lifecycle.marker)
        self.complete(receipt)
        self.assertFalse(self.instance.blocks_lifecycle())

    def test_missing_or_crossed_lifecycle_marker_refuses_active_lease_without_root_replay(self):
        self.use_lifecycle()
        receipt = self.prepare()
        previous = list(self.control.calls)
        self.lifecycle.marker = None
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.lifecycle.marker = {'operationId': secrets.token_hex(32), 'admissionBinding': self.binding}
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt)
        self.assertEqual(self.control.calls, previous)

    def test_explicit_unmanaged_still_uses_durable_lifecycle_lease(self):
        self.context.update(mode='unmanaged', recoveryEpoch=None)
        self.use_lifecycle()
        self.binding = self.instance.admission()['binding']
        receipt = self.prepare()
        self.assertTrue(self.instance.blocks_lifecycle())
        self.complete(receipt)
        self.assertFalse(self.instance.blocks_lifecycle())
        self.assertEqual(self.control.calls, [])

    def test_supplied_lifecycle_cannot_silently_yield_an_unfenced_operation(self):
        self.use_lifecycle()
        with mock.patch.object(self.lifecycle, 'operation', side_effect=nullcontext):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare()
        self.assertEqual(self.control.calls, [])
        self.assertIsNone(self.instance.journal.read()['active'])

    def test_private_durable_intent_precedes_root_revocation_and_main_receipt_has_no_control_token(self):
        receipt = self.prepare()
        self.assertTrue(self.instance.blocks_lifecycle())
        state = self.instance.journal.read()
        record = state['operations'][receipt['operationId']]
        self.assertEqual(record['phase'], 'pending')
        self.assertNotIn(record['changeToken'], json.dumps(receipt))
        self.assertNotIn('syntheticPlannedPrivateValue', json.dumps(state))
        self.assertEqual(Path(self.temp.name, 'state.json').stat().st_mode & 0o777, 0o600)
        for file in Path(self.temp.name, 'sources').iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        result = self.complete(receipt)
        self.assertEqual(result['state'], 'completed')
        self.assertFalse(self.instance.blocks_lifecycle())

    def test_lost_prepare_response_retries_same_token_and_operation_after_owner_restart(self):
        self.control.drop_prepare = True
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        state = self.instance.journal.read()
        operation, token = state['active'], state['operations'][state['active']]['changeToken']
        self.instance.close()
        self.instance = self.open()
        receipt = self.prepare()
        self.assertEqual(receipt['operationId'], operation)
        self.assertEqual(self.instance.journal.read()['operations'][operation]['changeToken'], token)
        self.assertEqual(self.control.calls.count('operator-prepare-writer'), 2)
        self.assertEqual(self.complete(receipt)['state'], 'completed')

    def test_lost_completion_response_is_reconciled_from_fresh_source_and_exact_root_state(self):
        receipt = self.prepare()
        self.control.drop_complete = True
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt)
        self.instance.close()
        self.instance = self.open()
        self.assertTrue(self.instance.blocks_lifecycle())
        result = self.instance.reconcile(current_identity=self.planned)
        self.assertEqual(result['operationId'], receipt['operationId'])
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 1)
        self.assertFalse(self.instance.blocks_lifecycle())

    def test_root_completion_survives_local_receipt_write_failure_without_replaying_complete(self):
        receipt = self.prepare()
        save = self.instance.journal.save
        def fail_completed(value):
            if value['operations'][receipt['operationId']]['phase'] == 'completed':
                raise journal.WriterJournalError()
            return save(value)
        with mock.patch.object(self.instance.journal, 'save', side_effect=fail_completed):
            with self.assertRaises(broker.WriterBrokerError):
                self.complete(receipt)
        self.instance.close()
        self.instance = self.open()
        self.assertEqual(self.complete(receipt)['state'], 'completed')
        self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 1)

    def test_unknown_or_changed_admission_refuses_before_granting_or_releasing_a_lease(self):
        self.context['mode'] = 'unknown'
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.assertEqual(self.control.calls, [])
        self.context['mode'] = 'managed'
        receipt = self.prepare()
        for field in ('controllerEpoch', 'imageId', 'recoveryEpoch', 'origin'):
            old = self.context[field]
            self.context[field] = 'https://other.example' if field == 'origin' else 'sha256:' + '6' * 64 if field == 'imageId' else '6' * 64
            with self.assertRaises(broker.WriterBrokerError):
                self.complete(receipt)
            self.assertTrue(self.instance.blocks_lifecycle())
            self.context[field] = old

    def test_explicit_unmanaged_mode_still_requires_durable_lease_and_exact_source(self):
        self.context.update(mode='unmanaged', recoveryEpoch=None)
        self.binding = self.instance.admission()['binding']
        receipt = self.prepare()
        self.assertEqual(self.control.calls, [])
        self.assertTrue(self.instance.blocks_lifecycle())
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt, self.baseline)
        self.assertTrue(self.instance.blocks_lifecycle())
        self.assertEqual(self.complete(receipt)['state'], 'completed')
        self.assertFalse(self.instance.blocks_lifecycle())

    def test_managed_history_cannot_be_reclassified_as_unmanaged(self):
        receipt = self.prepare()
        self.complete(receipt)
        self.context.update(mode='unmanaged', recoveryEpoch=None)
        with self.assertRaises(broker.WriterBrokerError):
            self.instance.admission()

    def test_duplicate_changed_and_crossed_requests_never_create_second_authority_or_accept_old_ack(self):
        receipt = self.prepare()
        self.assertEqual(self.prepare(), receipt)
        for changes in ({'request_id': secrets.token_hex(32)}, {'planned_identity': self.baseline}, {'baseline_identity': self.planned}):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare(**changes)
        self.control.status = {'generation': 3, 'revision': None, 'state': 'revoked'}
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.assertTrue(self.instance.blocks_lifecycle())

    def test_completed_operation_cannot_restart_and_repeated_complete_verifies_exact_root_target(self):
        receipt = self.prepare()
        result = self.complete(receipt)
        self.assertEqual(self.complete(receipt), result)
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.control.status = {'generation': 4, 'revision': '9' * 64, 'state': 'enrolled'}
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt)

    def test_wrong_fresh_source_and_baseline_reconciliation_remain_held_without_guessing_rollback(self):
        receipt = self.prepare()
        for value in (self.baseline, b'{"partialCommit":true}'):
            with self.assertRaises(broker.WriterBrokerError):
                self.instance.reconcile(current_identity=value)
        self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 0)
        self.assertTrue(self.instance.blocks_lifecycle())
        self.assertEqual(self.complete(receipt)['state'], 'completed')

    def test_wrong_pending_completion_bodies_preserve_source_budget_and_reconciliation_hold(self):
        receipt = self.prepare()
        sources = set(Path(self.temp.name, 'sources').iterdir())
        with mock.patch.object(journal, '_MAX_SOURCES', len(sources)):
            for value in (b'{"rejectedPrivateValue":1}', b'{"rejectedPrivateValue":2}'):
                with self.assertRaises(broker.WriterBrokerError):
                    self.complete(receipt, value)
                self.assertEqual(set(Path(self.temp.name, 'sources').iterdir()), sources)
                record = self.instance.journal.read()['operations'][receipt['operationId']]
                self.assertEqual((record['phase'], record['hold']), ('pending', 'source'))
                self.assertTrue(self.instance.blocks_lifecycle())
            self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 0)
            self.assertEqual(self.complete(receipt)['state'], 'completed')

    def test_wrong_completed_replays_cannot_exhaust_sources_or_block_the_next_operation(self):
        self.context.update(mode='unmanaged', recoveryEpoch=None)
        self.binding = self.instance.admission()['binding']
        receipt = self.prepare()
        self.complete(receipt)
        previous = self.instance.journal.read()
        sources = set(Path(self.temp.name, 'sources').iterdir())
        with mock.patch.object(journal, '_MAX_SOURCES', len(sources) + 1):
            for value in (b'{"rejectedPrivateValue":1}', b'{"rejectedPrivateValue":2}'):
                with self.assertRaises(broker.WriterBrokerError):
                    self.complete(receipt, value)
                self.assertEqual(set(Path(self.temp.name, 'sources').iterdir()), sources)
                self.assertEqual(self.instance.journal.read(), previous)
                self.assertFalse(self.instance.blocks_lifecycle())
            next_body = b'{"nextPlannedPrivateValue":true}'
            next_receipt = self.prepare(request_id=secrets.token_hex(32), baseline_identity=self.planned, planned_identity=next_body)
            self.assertEqual(self.complete(next_receipt, next_body)['state'], 'completed')
            self.assertEqual(len(list(Path(self.temp.name, 'sources').iterdir())), len(sources) + 1)
        self.assertEqual(self.control.calls, [])

    def test_corrupt_incomplete_and_replaced_journal_or_source_material_fail_closed(self):
        receipt = self.prepare()
        path = Path(self.temp.name, 'sources', receipt['plannedSha256'])
        path.write_bytes(b'changed')
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        with self.assertRaises(broker.WriterBrokerError):
            self.complete(receipt)
        self.assertTrue(self.instance.blocks_lifecycle())

    def test_single_owner_and_no_automatic_bootstrap_over_partial_journal(self):
        with self.assertRaises(broker.WriterBrokerError):
            self.open()
        self.instance.close()
        Path(self.temp.name, 'pending.json').write_text('{}')
        Path(self.temp.name, 'pending.json').chmod(0o600)
        with self.assertRaises(broker.WriterBrokerError):
            self.open(create=True)
        self.assertTrue(Path(self.temp.name, 'pending.json').exists())

    def test_fsync_failure_before_ipc_retains_uncertainty_and_never_returns_write_permission(self):
        with mock.patch.object(journal.os, 'fsync', side_effect=OSError('Synthetic durability failure')):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare()
        self.assertEqual(self.control.calls.count('operator-prepare-writer'), 0)

    def test_changed_control_receipt_is_held_before_any_main_ack(self):
        original = self.control.call
        def changed(operation, arguments):
            value = original(operation, arguments)
            if operation == 'operator-prepare-writer':
                value['baselineSha256'] = '9' * 64
            return value
        with mock.patch.object(self.control, 'call', side_effect=changed):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare()
        self.assertTrue(self.instance.blocks_lifecycle())
        self.assertEqual(self.control.calls.count('operator-complete-incarnation'), 0)

    def test_rejected_crossed_requests_cannot_fill_the_source_budget_with_orphan_credentials(self):
        self.prepare()
        sources = set(Path(self.temp.name, 'sources').iterdir())
        for changes in ({'request_id': secrets.token_hex(32), 'planned_identity': b'{"rejectedPrivateValue":1}'},
                        {'baseline_identity': b'{"rejectedPrivateValue":2}'}):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare(**changes)
            self.assertEqual(set(Path(self.temp.name, 'sources').iterdir()), sources)

    def test_unavailable_admission_and_unknown_source_entries_cannot_be_treated_as_an_empty_lease(self):
        with mock.patch.object(self.instance, 'admit', side_effect=FileNotFoundError('Synthetic missing installation record')):
            with self.assertRaises(broker.WriterBrokerError):
                self.instance.admission()
        self.assertEqual(self.control.calls, [])
        Path(self.temp.name, 'sources', 'unknown').write_text('private evidence')
        with self.assertRaises(journal.WriterJournalError):
            self.instance.blocks_lifecycle()
        self.assertEqual(Path(self.temp.name, 'sources', 'unknown').read_text(), 'private evidence')

    def test_capacity_refuses_a_new_intent_without_mutating_root_authority_or_erasing_history(self):
        receipt = self.prepare()
        self.complete(receipt)
        previous = self.instance.journal.read()
        with mock.patch.object(journal, '_MAX_RECORDS', 1):
            with self.assertRaises(broker.WriterBrokerError):
                self.prepare(request_id=secrets.token_hex(32))
        self.assertEqual(self.instance.journal.read(), previous)
        self.assertEqual(self.control.calls.count('operator-prepare-writer'), 1)
        self.assertEqual(self.control.status['state'], 'enrolled')

    def test_replaced_parent_and_permissive_state_refuse_without_control_or_evidence_deletion(self):
        self.prepare()
        state = Path(self.temp.name, 'state.json')
        state.chmod(0o644)
        with self.assertRaises(journal.WriterJournalError):
            self.instance.blocks_lifecycle()
        with self.assertRaises(broker.WriterBrokerError):
            self.prepare()
        self.assertTrue(state.exists())


if __name__ == '__main__':
    unittest.main()
