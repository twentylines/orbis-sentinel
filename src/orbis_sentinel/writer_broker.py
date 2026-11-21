"""Host-only credential leases and durable recovery-control reconciliation.

An installation supervisor must provide independently verified caller/controller,
storage, realm, runtime-floor and lifecycle admission. This library neither mounts
Main's control socket nor registers an HTTP route. Missing admission is UNKNOWN.
"""
import base64
import copy
import secrets
from contextlib import contextmanager, nullcontext
from urllib.parse import urlsplit

from .recovery_sessions import _integer, _token
from .writer_journal import WriterJournal, WriterJournalError, digest, encoded, hash_value

HOST_WRITER_PROTOCOL = 1


class WriterBrokerError(RuntimeError):
    def __init__(self):
        super().__init__('Credential synchronization is held for recovery; no rollback is implied.')


def fail():
    raise WriterBrokerError() from None


def admission_value(value):
    fields = {'schema', 'mode', 'installationId', 'controllerId', 'imageId', 'controllerEpoch', 'origin', 'recoveryEpoch'}
    if (type(value) is not dict or set(value) != fields or value['schema'] != 'orbis.sentinel-writer-admission.v1'
            or value['mode'] not in ('managed', 'unmanaged')
            or not all(hash_value(value[key]) for key in ('installationId', 'controllerId', 'controllerEpoch'))
            or type(value['imageId']) is not str or not value['imageId'].startswith('sha256:') or not hash_value(value['imageId'][7:])
            or (value['mode'] == 'managed' and not hash_value(value['recoveryEpoch']))
            or (value['mode'] == 'unmanaged' and value['recoveryEpoch'] is not None)
            or type(value['origin']) is not str or len(value['origin']) > 512):
        fail()
    try:
        origin = urlsplit(value['origin'])
        if (origin.scheme != 'https' or not origin.hostname or origin.path or origin.query or origin.fragment
                or origin.username is not None or origin.password is not None or origin.port == 0
                or any(ord(c) <= 32 or ord(c) == 127 for c in value['origin'])):
            fail()
    except ValueError:
        fail()
    return copy.deepcopy(value)


def status_value(value):
    if (type(value) is not dict or set(value) != {'generation', 'revision', 'state'}
            or not _integer(value['generation']) or value['state'] not in ('enrolled', 'pending', 'revoked', 'never-enrolled')
            or (value['state'] == 'enrolled' and not hash_value(value['revision']))
            or (value['state'] != 'enrolled' and value['revision'] is not None)):
        fail()
    return copy.deepcopy(value)


def staged_value(value, record):
    fields = {'baselineSha256', 'sourceSha256', 'identitySha256', 'revision', 'contentSha256', 'generation'}
    if (type(value) is not dict or set(value) != fields
            or not all(hash_value(value[key]) for key in fields - {'generation'})
            or value['baselineSha256'] != record['baselineSha256'] or value['sourceSha256'] != record['plannedSha256']
            or not _integer(value['generation']) or value['generation'] != record['rootBaseline']['generation'] + 1):
        fail()
    return copy.deepcopy(value)


def validate_record(operation, value):
    fields = {'requestId', 'admission', 'baselineSha256', 'plannedSha256', 'changeToken', 'phase', 'rootBaseline',
              'rootPending', 'observedSha256', 'hold'}
    if (type(value) is not dict or set(value) != fields or not hash_value(operation)
            or not all(hash_value(value[key]) for key in ('requestId', 'baselineSha256', 'plannedSha256'))
            or value['phase'] not in ('intent', 'begin-requested', 'pending', 'complete-requested', 'completed')
            or value['hold'] not in (None, 'control', 'source', 'admission')
            or (value['observedSha256'] is not None and not hash_value(value['observedSha256']))):
        fail()
    admission = admission_value(value['admission'])
    if admission['mode'] == 'managed':
        _token(value['changeToken'])
        baseline = status_value(value['rootBaseline'])
        if baseline['state'] != 'enrolled' or not _integer(baseline['generation'], 0, 9_007_199_254_740_988):
            fail()
        if value['rootPending'] is not None:
            staged_value(value['rootPending'], value)
        if value['phase'] in ('pending', 'complete-requested', 'completed') and value['rootPending'] is None:
            fail()
    elif value['changeToken'] is not None or value['rootBaseline'] is not None or value['rootPending'] is not None:
        fail()
    if value['phase'] in ('complete-requested', 'completed') and value['observedSha256'] != value['plannedSha256']:
        fail()
    if value['phase'] == 'completed' and value['hold'] is not None:
        fail()


class WriterBroker:
    def __init__(self, directory, *, control, admit, create=False, lifecycle=None):
        if (not callable(admit) or not callable(getattr(control, 'call', None))
                or lifecycle is not None and not callable(getattr(lifecycle, 'operation', None))):
            fail()
        self.control, self.admit, self.lifecycle = control, admit, lifecycle
        try:
            self.journal = WriterJournal(directory, create=create, validate_record=validate_record)
        except Exception:
            fail()

    @contextmanager
    def _operation(self):
        # Installed supervisors supply the shared host lock and durable marker.
        # The journal is acquired second, in the same order for every request.
        with (self.lifecycle.operation() if self.lifecycle is not None else nullcontext()) as fence:
            if self.lifecycle is not None and any(not callable(getattr(fence, name, None)) for name in ('read', 'begin', 'finish')):
                fail()
            with self.journal.operation():
                marker = fence.read() if fence is not None else None
                if fence is not None:
                    state = self.journal.read()
                    if marker is None:
                        if state['active'] is not None:
                            fail()
                    else:
                        operation = marker['operationId']
                        record = state['operations'].get(operation)
                        if (record is None or marker['admissionBinding'] != digest(encoded(record['admission']))
                                or state['active'] not in (None, operation)
                                or state['active'] is None and record['phase'] != 'completed'):
                            fail()
                yield fence, marker

    def _finish_fence(self, fence, operation, binding):
        if fence is None:
            return

        def completed():
            self._admitted(binding)
            state = self.journal.read()
            record = state['operations'].get(operation)
            return (state['active'] is None and record is not None and record['phase'] == 'completed'
                    and digest(encoded(record['admission'])) == binding
                    and (record['admission']['mode'] == 'unmanaged' or self._root_completed(record)))

        fence.finish(operation, binding, verify_completed=completed)

    def _admitted(self, expected=None):
        value = admission_value(self.admit())
        binding = digest(encoded(value))
        if expected is not None and binding != expected:
            fail()
        state = self.journal.read()
        if value['mode'] == 'unmanaged' and any(row['admission']['mode'] == 'managed' for row in state['operations'].values()):
            fail()
        return value, binding

    def admission(self):
        try:
            with self._operation():
                value, binding = self._admitted()
                return {'mode': value['mode'], 'binding': binding}
        except Exception:
            fail()

    def blocks_lifecycle(self):
        """Host restart/update/restore/enable admission must consult this marker.

        Unavailable/corrupt journal raises rather than returning an empty lease.
        Installed supervisors also enforce the durable shared host marker.
        """
        with self._operation() as (_, marker):
            return self.journal.read()['active'] is not None or marker is not None

    def _save(self, state):
        state['generation'] += 1
        self.journal.save(state)

    def _hold(self, state, record, reason):
        record['hold'] = reason
        self._save(state)
        fail()

    @staticmethod
    def _pending(operation, record):
        return {'operationId': operation, 'state': 'pending', 'admissionBinding': digest(encoded(record['admission'])),
                'baselineSha256': record['baselineSha256'], 'plannedSha256': record['plannedSha256']}

    @staticmethod
    def _completed(operation, record):
        return {'operationId': operation, 'state': 'completed', 'admissionBinding': digest(encoded(record['admission'])),
                'plannedSha256': record['plannedSha256']}

    def prepare(self, *, request_id, admission_binding, baseline_identity, planned_identity):
        try:
            with self._operation() as (fence, marker):
                if not hash_value(request_id) or not hash_value(admission_binding):
                    fail()
                if any(type(body) is not bytes or not 1 <= len(body) <= 65536 for body in (baseline_identity, planned_identity)):
                    fail()
                admitted, _ = self._admitted(admission_binding)
                baseline, planned = digest(baseline_identity), digest(planned_identity)
                state = self.journal.read()
                known = [(key, row) for key, row in state['operations'].items() if row['requestId'] == request_id]
                if known:
                    operation, record = known[0]
                    if (record['admission'] != admitted or record['baselineSha256'] != baseline or record['plannedSha256'] != planned
                            or state['active'] != operation or record['phase'] == 'completed'):
                        fail()
                    self.journal.retain(baseline_identity)
                    self.journal.retain(planned_identity)
                else:
                    if marker is not None or state['active'] is not None or len(state['operations']) >= 1024:
                        fail()
                    root_baseline = None
                    if admitted['mode'] == 'managed':
                        root_baseline = status_value(self.control.call('operator-status', {}))
                        if root_baseline['state'] != 'enrolled' or not _integer(root_baseline['generation'], 0, 9_007_199_254_740_988):
                            fail()
                        eligibility = self.control.call('operator-writer-eligibility', {})
                        if (type(eligibility) is not dict or eligibility != {
                                'schema': 'orbis.sentinel-operator-writer-eligibility.v1',
                                'generation': root_baseline['generation'], 'revision': root_baseline['revision'],
                                'eligible': True} or type(eligibility['eligible']) is not bool
                                or type(eligibility['generation']) is not int):
                            fail()
                    self._admitted(admission_binding)
                    self.journal.retain(baseline_identity)
                    self.journal.retain(planned_identity)
                    operation = secrets.token_hex(32)
                    if operation in state['operations']:
                        fail()
                    record = {'requestId': request_id, 'admission': admitted, 'baselineSha256': baseline, 'plannedSha256': planned,
                              'changeToken': secrets.token_urlsafe(32) if admitted['mode'] == 'managed' else None,
                              'phase': 'intent', 'rootBaseline': root_baseline, 'rootPending': None, 'observedSha256': None, 'hold': None}
                    state['operations'][operation] = record
                    state['active'] = operation
                    # Token and exact producer/source binding are durable BEFORE IPC.
                    # A crash between marker and intent publication stays held.
                    if fence is not None:
                        fence.begin(operation, admission_binding)
                    self._save(state)
                if record['phase'] in ('intent', 'begin-requested', 'pending'):
                    record['phase'], record['hold'] = 'begin-requested', None
                    self._save(state)
                    if admitted['mode'] == 'managed':
                        try:
                            result = self.control.call('operator-prepare-writer', {
                                'baselineIdentityBase64': base64.b64encode(self.journal.source(baseline)).decode('ascii'),
                                'identityBase64': base64.b64encode(self.journal.source(planned)).decode('ascii'),
                                'expectedGeneration': record['rootBaseline']['generation'], 'expectedRevision': record['rootBaseline']['revision'],
                                'changeToken': record['changeToken']})
                            staged = staged_value(result, record)
                            if record['rootPending'] is not None and record['rootPending'] != staged:
                                fail()
                            record['rootPending'] = staged
                        except Exception:
                            self._hold(state, record, 'control')
                    try:
                        self._admitted(admission_binding)
                    except Exception:
                        self._hold(state, record, 'admission')
                    record['phase'], record['hold'] = 'pending', None
                    self._save(state)
                elif record['phase'] != 'pending':
                    fail()
                # A pending ACK is a write lease, not an assertion Main has committed.
                return self._pending(operation, record)
        except Exception:
            fail()

    def _root_completed(self, record):
        current = status_value(self.control.call('operator-status', {}))
        expected = {'generation': record['rootPending']['generation'] + 1, 'revision': record['rootPending']['revision'], 'state': 'enrolled'}
        if current == expected:
            return True
        if current != {'generation': record['rootPending']['generation'], 'revision': None, 'state': 'pending'}:
            fail()
        return False

    def complete(self, *, operation_id, admission_binding, current_identity):
        try:
            with self._operation() as (fence, _):
                if not hash_value(operation_id) or not hash_value(admission_binding):
                    fail()
                admitted, _ = self._admitted(admission_binding)
                state = self.journal.read()
                record = state['operations'].get(operation_id)
                if record is None or record['admission'] != admitted:
                    fail()
                if type(current_identity) is not bytes or not 1 <= len(current_identity) <= 65536:
                    fail()
                observed = digest(current_identity)
                if observed != record['plannedSha256']:
                    if record['phase'] != 'completed':
                        self._hold(state, record, 'source')
                    fail()
                # Rejected bodies must not consume the immutable source budget,
                # including replays of an already completed operation.
                self.journal.retain(current_identity)
                if record['phase'] == 'completed':
                    if admitted['mode'] == 'managed' and not self._root_completed(record):
                        fail()
                    self._finish_fence(fence, operation_id, admission_binding)
                    return self._completed(operation_id, record)
                if state['active'] != operation_id or record['phase'] not in ('pending', 'complete-requested'):
                    fail()
                record['phase'], record['observedSha256'], record['hold'] = 'complete-requested', observed, None
                self._save(state)
                if admitted['mode'] == 'managed':
                    try:
                        # Lost completion reply is resolved from exact fresh source,
                        # durable intent and the unique Root-issued revision/generation.
                        if not self._root_completed(record):
                            result = status_value(self.control.call('operator-complete-incarnation', {
                                'identityBase64': base64.b64encode(self.journal.source(observed)).decode('ascii'),
                                'expectedGeneration': record['rootPending']['generation'], 'changeToken': record['changeToken']}))
                            if result != {'generation': record['rootPending']['generation'] + 1, 'revision': record['rootPending']['revision'], 'state': 'enrolled'}:
                                fail()
                        if not self._root_completed(record):
                            fail()
                    except Exception:
                        self._hold(state, record, 'control')
                try:
                    self._admitted(admission_binding)
                except Exception:
                    self._hold(state, record, 'admission')
                record['phase'], record['hold'], state['active'] = 'completed', None, None
                self._save(state)
                self._finish_fence(fence, operation_id, admission_binding)
                return self._completed(operation_id, record)
        except Exception:
            fail()

    def reconcile(self, *, current_identity):
        """Root supervisor supplies a NEW writer-fenced committed source snapshot.

        Only an exact planned state can complete automatically. Baseline/partial
        states, producer epoch changes and missing proof remain held for explicit
        reconciliation; no old credential or new incarnation is guessed here.
        """
        with self._operation():
            _, binding = self._admitted()
            state = self.journal.read()
            if state['active'] is None:
                fail()
            operation = state['active']
        return self.complete(operation_id=operation, admission_binding=binding, current_identity=current_identity)

    def close(self):
        self.journal.close()
