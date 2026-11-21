"""Root-only initial operator/key preparation; no Main or recovery session grants."""
from dataclasses import dataclass
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
import stat
import secrets
import threading
from pathlib import Path

from . import recovery_sessions as sessions
from .bootstrap_source import (HELD_PLAN, RootFileSourceWitness, PrivateDirectory, PrivateFile, create_file, decode, digest,
                               encoded, fail, hash_value, held_review)

_SCHEMA = 'orbis.sentinel-bootstrap-operation.v1'
_MAX = 128
_CHALLENGES = 32
_SOURCE_TTL = 120000
_KEY_TTL = 600000


def _receiver_invocation():
    with open('/proc/self/stat', 'rb') as stream:
        body = stream.read(4097)
    fields = body.rsplit(b') ', 1)[-1].split()
    if len(body) > 4096 or len(fields) < 20 or not fields[19].isdigit():
        fail()
    executable = Path('/proc/self/exe').stat()
    return {'pid': os.getpid(), 'startTicks': int(fields[19]), 'invocationId': os.environ.get('INVOCATION_ID'),
            'executableIdentity': [executable.st_dev, executable.st_ino]}


_PUBLICATION_PHASES = ('publication-ready', 'paired-published')
_ACTIVATION_PHASES = ('activation-pending', 'activation-committed')
_PAIRED_PHASES = (*_ACTIVATION_PHASES, *_PUBLICATION_PHASES)


def _record(body):
    value = decode(body)
    fields = {'schema', 'operationId', 'planSha256', 'installationId', 'origin', 'sourceSha256', 'phase',
              'challenges', 'candidate', 'pendingGeneration', 'key', 'activation', 'writerFloor', 'managedIntent', 'stageBinding', 'activationBinding'}
    if 'heldStage' in value:
        fields.add('heldStage')
    if 'keyPreparation' in value:
        fields.add('keyPreparation')
    if 'heldActivation' in value:
        fields.add('heldActivation')
    if 'pairedPublication' in value:
        fields.add('pairedPublication')
    if (set(value) != fields or value['schema'] != _SCHEMA
            or not all(hash_value(value[k]) for k in ('operationId', 'planSha256', 'installationId', 'sourceSha256'))
            or value['phase'] not in ('collecting', 'staged', 'key-prepared', 'acknowledged', 'active', *_PAIRED_PHASES)
            or type(value['challenges']) is not dict or len(value['challenges']) > _CHALLENGES
            or not sessions._integer(value['pendingGeneration'])
            or any(value[k] is not None and not hash_value(value[k]) for k in ('writerFloor', 'managedIntent', 'stageBinding', 'activationBinding'))):
        fail()
    sessions._origin(value['origin'])
    for request, item in value['challenges'].items():
        if (not hash_value(request) or type(item) is not dict or set(item) != {'phase', 'nonce', 'created', 'expires', 'consumed', 'descriptor'}
                or item['phase'] not in ('proposal', 'activation') or type(item['consumed']) is not bool
                or not sessions._integer(item['created'], 1) or item['expires'] != item['created'] + _SOURCE_TTL
                or item['descriptor'] is not None and not hash_value(item['descriptor'])):
            fail()
        if item['descriptor'] is not None and item['consumed'] is not True:
            fail()
        sessions._token(item['nonce'])
    candidate = value['candidate']
    if candidate is not None:
        if (type(candidate) is not dict or set(candidate) != {'nonce', 'target', 'revision', 'content', 'profile'}
                or not all(hash_value(candidate[k]) for k in ('nonce', 'target', 'revision', 'content'))
                or candidate['profile'] is not None and (sessions._enrollment(candidate['profile'])['identitySha256'] != candidate['target']
                                                        or candidate['profile']['revision'] != candidate['revision'])):
            fail()
        expected_revision = hashlib.sha256(b'orbis.sentinel-bootstrap-incarnation.v1\0' + encoded([value['sourceSha256'], candidate['nonce']])).hexdigest()
        if candidate['revision'] != expected_revision:
            fail()
        if candidate['profile'] is not None and candidate['profile']['origin'] != value['origin']:
            fail()
    key = value['key']
    if key is not None:
        if (type(key) is not dict or set(key) != {'revision', 'deliverySha256', 'epoch', 'created', 'expires', 'ack'}
                or not all(hash_value(key[k]) for k in ('revision', 'deliverySha256', 'epoch'))
                or not sessions._integer(key['created'], 1) or key['expires'] != key['created'] + _KEY_TTL
                or key['ack'] is not None and not hash_value(key['ack'])):
            fail()
    if value['activation'] is not None and type(value['activation']) is not dict:
        fail()
    phase = value['phase']
    if 'heldStage' in value:
        held = value['heldStage']
        if phase not in ('collecting', 'staged', 'key-prepared', 'acknowledged', *_PAIRED_PHASES) or held is None and phase != 'collecting':
            fail()
        if held is not None:
            if (type(held) is not dict
                    or set(held) != {'offerSha256', 'requestId', 'terminalChallenge', 'terminalReceiptSha256'}
                    or any(not hash_value(held[key]) for key in ('offerSha256', 'requestId'))
                    or held['terminalReceiptSha256'] is not None
                    and (phase == 'collecting' or not hash_value(held['terminalReceiptSha256']))):
                fail()
            sessions._token(held['terminalChallenge'])
            item = value['challenges'].get(held['requestId'])
            if item is None or item['phase'] != 'proposal' or not item['consumed']:
                fail()
    if ('keyPreparation' in value and (not hash_value(value['keyPreparation']) or phase == 'collecting'
            or value.get('heldStage') is None or value['heldStage']['terminalReceiptSha256'] is None)
            or 'heldStage' in value and phase in ('key-prepared', 'acknowledged', *_PAIRED_PHASES)
            and (key is None or value.get('keyPreparation') != key['deliverySha256'])):
        fail()
    if phase == 'collecting':
        if value['pendingGeneration'] != 0 or key is not None or value['activation'] is not None or value['stageBinding'] is not None:
            fail()
    elif candidate is None or candidate['profile'] is None or value['pendingGeneration'] != 1 or value['stageBinding'] is None:
        fail()
    if phase == 'staged' and key is not None:
        fail()
    if phase in ('key-prepared', 'acknowledged', 'active', *_PAIRED_PHASES) and key is None:
        fail()
    if phase == 'key-prepared' and key['ack'] is not None or phase in ('acknowledged', 'active', *_PAIRED_PHASES) and key['ack'] is None:
        fail()
    if phase == 'active':
        if value['activation'] is None or value['writerFloor'] is None or value['managedIntent'] is None or value['activationBinding'] is None:
            fail()
    elif phase not in ('activation-committed', *_PUBLICATION_PHASES) and (value['activation'] is not None or value['activationBinding'] is not None):
        fail()
    if ('heldActivation' in value) != (phase in _PAIRED_PHASES):
        fail()
    if phase in _PAIRED_PHASES:
        _held_activation_record(value)
    if ('pairedPublication' in value) != (phase in _PUBLICATION_PHASES):
        fail()
    if phase in _PUBLICATION_PHASES:
        from .bootstrap_publication import validate_record
        validate_record(value)
    return value


def _held_activation_record(value):
    from .bootstrap_source import ACTIVATION_COMMIT
    held = value['heldActivation']
    binding = ('intentSha256', 'descriptorSha256', 'offerSha256')
    if (type(held) is not dict or set(held) != {'packetSha256', 'requestId', 'terminalChallenge', 'terminalReceiptSha256', *binding}
            or not all(hash_value(held[key]) for key in ('packetSha256', 'requestId'))
            or value.get('heldStage', {}).get('terminalReceiptSha256') is None
            or value['writerFloor'] is not None or value['managedIntent'] is not None or value['activationBinding'] is not None):
        fail()
    item = value['challenges'].get(held['requestId'])
    if item is None or item['phase'] != 'activation':
        fail()
    if item['consumed']:
        if not all(hash_value(held[key]) for key in binding) or item['descriptor'] != held['descriptorSha256']:
            fail()
        sessions._token(held['terminalChallenge'])
    elif any(held[key] is not None for key in (*binding, 'terminalChallenge')) or item['descriptor'] is not None:
        fail()
    if value['phase'] == 'activation-pending':
        if value['activation'] is not None or held['terminalReceiptSha256'] is not None:
            fail()
        return
    if (not item['consumed'] or value['activation'] != {'schema': ACTIVATION_COMMIT, 'operationId': value['operationId'],
            'installationId': value['installationId'], 'planSha256': value['planSha256'], 'requestId': held['requestId'],
            'identitySha256': value['candidate']['target'], 'revision': value['candidate']['revision'],
            'generation': value['pendingGeneration'] + 1, 'keyRevision': value['key']['revision'],
            'ackReceiptId': value['key']['ack'], 'sourceSha256': value['sourceSha256']}
            or held['terminalReceiptSha256'] is not None and not hash_value(held['terminalReceiptSha256'])):
        fail()


@dataclass(frozen=True)
class _BootstrapActivationProof:
    owner: object
    operation: str
    plan: str
    source: str
    target: str
    content: str
    descriptor: str
    pending_generation: int
    key_revision: str
    ack: str
    request: str
    key_digest: str
    writer_floor: str
    managed_intent: str


class RecoveryBootstrap:
    def __init__(self, store, profiles, incarnations, *, origin, require_held_setup=False):
        if profiles._store is not store or incarnations.store is not store or incarnations.profiles is not profiles:
            fail()
        self.store, self.profiles, self.incarnations = store, profiles, incarnations
        self.origin = sessions._origin(origin)
        self.sources = RootFileSourceWitness(store)
        self.require_held_setup = require_held_setup
        self._browser_lock = threading.Lock()
        self._browser_grant = None

    def _listener_setup_check(self, review):
        setup = self.store._setup
        if setup is not None or self.require_held_setup:
            from .recovery_listener_install import read_setup_receipt
            if setup is None:
                fail()
            setup.verify()
            if setup.backend is None:
                read_setup_receipt(self.store._directory,review,marker_sha=setup.sha256)
            else:
                read_setup_receipt(self.store._directory,review,marker_sha=setup.sha256,setup=setup)
            if review['recovery']['process'] != _receiver_invocation():
                fail()

    def listener_probe(self, *, action, operation_id, marker_sha256, nonce=None, binding_sha256=None):
        setup = self.store._setup
        if setup is None:
            fail()

        def witness():
            self._virgin()
            if action == 'arm':
                value = setup.arm(operation_id, marker_sha256)
            elif action == 'confirm':
                setup.confirm(operation_id, marker_sha256, nonce, binding_sha256)
                value = nonce
            else:
                fail()
            return {'operationId': operation_id, 'markerSha256': marker_sha256, 'nonce': value,
                    'process': _receiver_invocation(), **(
                        {'bindingSha256': binding_sha256} if action == 'confirm' else {})}

        return self.store._transaction(witness)

    def _listener_plan_check(self, operation, plan_sha256):
        if self.require_held_setup or self.store._setup is not None:
            with (self.sources.plan(operation, plan_sha256) as (plan, directory),
                  held_review(directory, operation, plan['reviewSha256']) as review):
                self._listener_setup_check(review)

    def _load(self, operation):
        if not hash_value(operation):
            fail()
        row = self.store._db.execute('SELECT record FROM bootstrap_operations WHERE operation=?', (operation,)).fetchone()
        if row is None:
            fail()
        value = _record(row['record'])
        if value['operationId'] != operation or value['origin'] != self.origin:
            fail()
        return value

    def _save(self, record):
        body = encoded(record).decode('ascii')
        if len(body) > 65536:
            fail()
        _record(body)
        self.store._db.execute('INSERT INTO bootstrap_operations VALUES (?,?) ON CONFLICT(operation) DO UPDATE SET record=excluded.record',
                               (record['operationId'], body))

    def _virgin(self, *, operation=None):
        status = self.store._operator_status()
        if status != {'generation': 0, 'revision': None, 'state': 'never-enrolled'}:
            fail()
        for table in ('identities', 'recovery_keys', 'counters', 'factors', 'operator_incarnations', 'operator_prepared_begins',
                      'operator_writer_requests', 'sessions', 'challenges'):
            if self.store._db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                fail()
        allowed = set()
        if operation is not None:
            record = self._load(operation)
            allowed.add(record['sourceSha256'])
            if record['candidate'] is not None:
                allowed.add(record['candidate']['target'])
        try:
            fd = os.open('profiles', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.store._directories[-1][1])
            try:
                info = os.fstat(fd)
                if info.st_uid != sessions._OWNER_UID or stat.S_IMODE(info.st_mode) != 0o700 or not set(os.listdir(fd)) <= allowed:
                    fail()
            finally:
                os.close(fd)
        except FileNotFoundError:
            pass
        rows = self.store._db.execute('SELECT operation FROM bootstrap_operations').fetchall()
        if any(row['operation'] != operation for row in rows):
            fail()

    def held_review_status(self, *, operation_id, review_sha256):
        """Observe eligibility in the active Root owner before an outside capture."""
        if not hash_value(review_sha256):
            fail()
        with PrivateDirectory(self.sources.operation_path(operation_id)) as directory:
            with held_review(directory, operation_id, review_sha256) as review:
                self._listener_setup_check(review)
                if review['origin'] != self.origin or review['recovery']['process'] != _receiver_invocation():
                    fail()
                self.store._transaction(self._virgin)
                return {'operationId': operation_id, 'reviewSha256': review_sha256, 'phase': 'review-capture-ready'}

    def source_challenge(self, *, operation_id, plan_sha256, phase, request_id):
        if not hash_value(request_id) or phase not in ('proposal', 'activation'):
            fail()
        with self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            held = plan['schema'] == HELD_PLAN
            if plan['origin'] != self.origin or held and phase != 'proposal' or self.store._setup is not None and not held:
                fail()
            if held and (self.require_held_setup or self.store._setup is not None):
                with held_review(directory, operation_id, plan['reviewSha256']) as review:
                    self._listener_setup_check(review)
            def write():
                row = self.store._db.execute('SELECT record FROM bootstrap_operations WHERE operation=?', (operation_id,)).fetchone()
                if row is None:
                    self._virgin()
                    if phase != 'proposal' or self.store._db.execute('SELECT count(*) FROM bootstrap_operations').fetchone()[0] >= _MAX:
                        fail()
                    value = {'schema': _SCHEMA, 'operationId': operation_id, 'planSha256': plan_sha256,
                             'installationId': plan['installationId'], 'origin': self.origin, 'sourceSha256': plan['sourceSha256'],
                             'phase': 'collecting', 'challenges': {}, 'candidate': None, 'pendingGeneration': 0, 'key': None, 'activation': None,
                             'writerFloor': None, 'managedIntent': None, 'stageBinding': None, 'activationBinding': None}
                    if held:
                        value['heldStage'] = None
                else:
                    value = self._load(operation_id)
                if (value['planSha256'] != plan_sha256 or value['installationId'] != plan['installationId']
                        or value['sourceSha256'] != plan['sourceSha256'] or value['phase'] == 'active'
                        or phase == 'proposal' and value['phase'] != 'collecting'
                        or phase == 'activation' and value['phase'] != 'acknowledged'):
                    fail()
                if phase == 'proposal' and row is not None:
                    self._virgin(operation=operation_id)
                elif phase == 'activation':
                    self._pending(value)
                known = value['challenges'].get(request_id)
                if known is not None:
                    if known['phase'] != phase:
                        fail()
                    return {'collectionNonce': known['nonce'], 'expiresAtMs': known['expires'], 'consumed': known['consumed']}
                if value.get('heldStage') is not None:
                    fail()
                if len(value['challenges']) >= _CHALLENGES:
                    fail()
                now = self.store._now()
                item = {'phase': phase, 'nonce': secrets.token_urlsafe(32), 'created': now, 'expires': now + _SOURCE_TTL,
                        'consumed': False, 'descriptor': None}
                value['challenges'][request_id] = item
                self._save(value)
                return {'collectionNonce': item['nonce'], 'expiresAtMs': item['expires'], 'consumed': False}
            return self.store._transaction(write)

    def _consume(self, operation, plan, request, nonce, phase, *, held=None):
        def write():
            record = self._load(operation)
            item = record['challenges'].get(request)
            if (record['planSha256'] != plan or item is None or item['nonce'] != nonce or item['phase'] != phase
                    or item['consumed'] or not item['created'] <= self.store._now() <= item['expires']
                    or ('heldStage' in record) != (held is not None)):
                fail()
            if phase == 'proposal':
                self._virgin(operation=operation)
                if record['phase'] != 'collecting':
                    fail()
            elif record['phase'] != 'acknowledged':
                fail()
            item['consumed'] = True
            if held is not None:
                if record['heldStage'] is not None:
                    fail()
                record['heldStage'] = held
            self._save(record)
            return record, item
        return self.store._transaction(write)

    def stage(self, *, operation_id, plan_sha256, request_id, collection_nonce):
        if self.store._setup is not None:
            fail()
        return self._stage(operation_id, plan_sha256, request_id, collection_nonce)

    def _stage(self, operation_id, plan_sha256, request_id, collection_nonce, *, proof=None, held=None):
        with self.profiles._operation():
            prior = self.store._transaction(lambda: self._load(operation_id))
            if ('heldStage' in prior) != (proof is not None):
                fail()
            if prior['phase'] != 'collecting':
                if (proof is not None or prior['planSha256'] != plan_sha256
                        or prior['stageBinding'] != digest(encoded([operation_id, plan_sha256, request_id, collection_nonce]))):
                    fail()
                return self.status(operation_id=operation_id)
            record, challenge = self._consume(operation_id, plan_sha256, request_id, collection_nonce, 'proposal', held=held)
            with self.sources.source(operation_id, plan_sha256, 'proposal', collection_nonce,
                                     issued_at=challenge['created'], expires_at=challenge['expires']) as captured:
                if proof is not None:
                    self._listener_plan_check(operation_id, plan_sha256)
                    proof.check(captured)
                source = self.profiles.prepare(captured.body)
                content = self.incarnations._content(source)
                if source.digest != record['sourceSha256'] or json.loads(source._metadata)['origin'] != self.origin:
                    fail()
                def reserve():
                    if proof is not None:
                        self._listener_plan_check(operation_id, plan_sha256)
                    value = self._load(operation_id)
                    self._virgin(operation=operation_id)
                    if value['candidate'] is None:
                        nonce = secrets.token_hex(32)
                        revision = hashlib.sha256(b'orbis.sentinel-bootstrap-incarnation.v1\0' + encoded([source.digest, nonce])).hexdigest()
                        body = self.incarnations._rewrite(captured.body, revision)
                        value['candidate'] = {'nonce': nonce, 'target': digest(body), 'revision': revision, 'content': content, 'profile': None}
                        self._save(value)
                    if value['candidate']['content'] != content:
                        fail()
                    return value
                record = self.store._transaction(reserve)
                candidate = record['candidate']
                target = self.profiles.prepare(self.incarnations._rewrite(captured.body, candidate['revision']))
                if target.digest != candidate['target'] or self.incarnations._content(target) != content:
                    fail()
                metadata = json.loads(target._metadata)
                def finish():
                    value = self._load(operation_id)
                    self._virgin(operation=operation_id)
                    if value['candidate'] != candidate or not challenge['created'] <= self.store._now() <= challenge['expires']:
                        fail()
                    if proof is not None:
                        self._listener_plan_check(operation_id, plan_sha256)
                        proof.check(captured)
                    value['candidate']['profile'] = metadata
                    value['challenges'][request_id]['descriptor'] = captured.descriptor_sha256
                    value['phase'], value['pendingGeneration'] = 'staged', 1
                    value['stageBinding'] = digest(encoded([operation_id, plan_sha256, request_id, collection_nonce]))
                    self.store._db.execute('UPDATE operator_enrollment SET generation=1,nonce=?,target=?,origin=? WHERE id=1',
                        (digest(operation_id.encode('ascii')), target.digest, self.origin))
                    self._save(value)
                self.store._transaction(finish)
            return self.status(operation_id=operation_id)

    def open_held_stage(self, offer, descriptors, deadline):
        from .collector_execution import HeldStageProof
        operation, plan_sha = offer['operationId'], offer['planSha256']
        with self.sources.plan(operation, plan_sha) as (plan, directory):
            if (plan['schema'] != HELD_PLAN or plan['reviewSha256'] != offer['reviewSha256']
                    or offer['holdBinding'] != offer['reviewSha256'] or plan['sourceSha256'] != offer['sourceSha256']
                    or plan['origin'] != self.origin):
                fail()
            with held_review(directory, operation, plan['reviewSha256']) as review:
                self._listener_setup_check(review)
                inventory = review['collector']['inventorySha256']
                if offer['inventorySha256'] != inventory or review['recovery']['process'] != _receiver_invocation():
                    fail()
                request = {'operationId': operation, 'planSha256': plan_sha, 'phase': 'proposal',
                           'collectionNonce': offer['collectionNonce'], 'origin': self.origin}
                scope = {'root': review['root'], 'context': review['context'], 'request': request,
                         'holdBinding': offer['holdBinding']}
                return HeldStageProof(offer, descriptors, deadline, scope=scope, inventory=inventory)

    def stage_held(self, proof):
        from .collector_execution import HeldStageProof
        if type(proof) is not HeldStageProof or proof.phase != 'proposal':
            fail()
        offer = proof.offer
        challenge = secrets.token_urlsafe(32)
        held = {'offerSha256': digest(encoded(offer)), 'requestId': offer['requestId'],
                'terminalChallenge': challenge, 'terminalReceiptSha256': None}
        self._stage(offer['operationId'], offer['planSha256'], offer['requestId'], offer['collectionNonce'],
                    proof=proof, held=held)
        return challenge

    def _held_terminal_event(self, proof, plan, event):
        from .collector_execution import SCHEMA
        offer = proof.offer
        operation, plan_sha = offer['operationId'], offer['planSha256']
        if (type(event) is not dict
            or set(event) != {'schema', 'phase', 'request', 'installationId', 'sourceSha256', 'descriptorSha256',
                              'inventorySha256', 'executionSha256', 'process', 'capsuleSha256', 'root', 'context',
                              'holdBinding', 'authority', 'exitCode'}
            or event['schema'] != SCHEMA or event['phase'] != 'complete' or type(event['exitCode']) is not int
            or event['exitCode'] != 0 or event['authority'] != 'inventory-execution-custody-only'
            or event['installationId'] != plan['installationId'] or not hash_value(event['executionSha256'])
            or type(event['process']) is not dict
            or set(event['process']) != {'pid', 'startTicks', 'executable'}
            or not all(sessions._integer(event['process'][key], 1) for key in ('pid', 'startTicks'))
            or event['process']['pid'] != proof.pid or event['process']['startTicks'] != proof.start_ticks
            or type(event['process']['executable']) is not list or len(event['process']['executable']) != 2
            or any(not sessions._integer(item) for item in event['process']['executable'])
            or event['root'] != proof.root or event['context'] != proof.context
            or event['request'] != {'operationId': operation, 'planSha256': plan_sha, 'phase': proof.phase,
                                    'collectionNonce': offer['collectionNonce'], 'origin': self.origin}
            or any(event[key] != offer[key] for key in
                   ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256', 'holdBinding'))):
            fail()

    def finish_held(self, proof, *, terminal_challenge, receipt_sha256):
        from .collector_execution import HeldStageProof
        if type(proof) is not HeldStageProof or proof.phase != 'proposal' or not hash_value(receipt_sha256):
            fail()
        offer = proof.offer
        operation, plan_sha = offer['operationId'], offer['planSha256']
        proof.terminal()
        with self.sources.plan(operation, plan_sha) as (plan, directory):
            with PrivateFile(directory, 'held-stage-terminal.json', 16384) as terminal:
                packet = decode(terminal.body)
                event = packet.get('receipt')
                if (digest(terminal.body) != receipt_sha256
                        or packet != {'schema': 'orbis.sentinel-bootstrap-held-terminal.v1', 'offerSha256': digest(encoded(offer)),
                                      'terminalChallenge': terminal_challenge, 'receipt': event}):
                    fail()
                self._held_terminal_event(proof, plan, event)
                def commit():
                    self._listener_plan_check(operation, plan_sha)
                    value = self._load(operation)
                    held = value.get('heldStage')
                    if (value['planSha256'] != plan_sha or value['phase'] != 'staged' or held is None
                            or held != {'offerSha256': digest(encoded(offer)), 'requestId': offer['requestId'],
                                        'terminalChallenge': terminal_challenge, 'terminalReceiptSha256': None}):
                        fail()
                    self._pending(value)
                    terminal.verify()
                    held['terminalReceiptSha256'] = receipt_sha256
                    self._save(value)
                    return value['stageBinding']
                return self.store._transaction(commit)

    def _pending(self, record):
        if any(row['operation'] != record['operationId'] for row in self.store._db.execute('SELECT operation FROM bootstrap_operations').fetchall()):
            fail()
        expected = {'generation': record['pendingGeneration'], 'revision': None, 'state': 'pending'}
        state = self.store._operator_enrollment()
        if (self.store._operator_status() != expected or state['nonce'] != digest(record['operationId'].encode('ascii'))
                or state['target'] != record['candidate']['target'] or state['origin'] != self.origin):
            fail()

    @staticmethod
    def _activation_core(record, request_id):
        from .bootstrap_source import ACTIVATION_COMMIT
        candidate, key = record['candidate'], record['key']
        return {'schema': ACTIVATION_COMMIT, 'operationId': record['operationId'],
                'installationId': record['installationId'], 'planSha256': record['planSha256'],
                'requestId': request_id, 'identitySha256': candidate['target'], 'revision': candidate['revision'],
                'generation': record['pendingGeneration'] + 1, 'keyRevision': key['revision'],
                'ackReceiptId': key['ack'], 'sourceSha256': record['sourceSha256']}

    @contextmanager
    def _activation_scope(self, operation, plan_sha, packet_sha):
        from .bootstrap_source import activation_packet
        with (self.sources.plan(operation, plan_sha) as (plan, directory),
              held_review(directory, operation, plan['reviewSha256']) as review,
              activation_packet(directory, plan, review, packet_sha) as (packet, approval, verify_packet)):
            record = self.store._transaction(lambda: self._load(operation))
            if record['phase'] not in ('acknowledged', *_ACTIVATION_PHASES):
                fail()
            held = record.get('heldActivation')
            if held is not None and (held['packetSha256'] != packet_sha or held['requestId'] != packet['activationRequestId']):
                fail()
            core = self._activation_core(record, packet['activationRequestId'])
            candidate = record['candidate']
            if (packet['stage'] != {'terminalReceiptSha256': record['heldStage']['terminalReceiptSha256'],
                    'sourceSha256': record['sourceSha256'], 'identitySha256': candidate['target'],
                    'revision': candidate['revision'], 'contentSha256': candidate['content'],
                    'pendingGeneration': record['pendingGeneration']}
                    or packet['key'] != {'revision': core['keyRevision'], 'ackReceiptId': core['ackReceiptId']}
                    or packet['candidate']['projectedCommitSha256'] != digest(encoded(core))):
                fail()
            with self._key_stage(plan, directory, record) as verify_stage:
                def verify():
                    verify_stage()
                    verify_packet()
                yield record, packet, approval, core, review, directory, verify

    def held_activation_challenge(self, *, operation_id, plan_sha256, packet_sha256, request_id):
        with (self.profiles._operation(),
              self._activation_scope(operation_id, plan_sha256, packet_sha256) as
              (record, packet, _, _, _, directory, verify),
              self._held_delivery(directory, record) as (delivery, material)):
            if packet['activationRequestId'] != request_id or record['phase'] == 'activation-committed':
                fail()

            def issue():
                current = self._load(operation_id)
                if current != record:
                    fail()
                verify()
                delivery.verify()
                self._pending_key(current, material)
                now = self.store._now()
                item = current['challenges'].get(request_id)
                if item is None:
                    if current['phase'] != 'acknowledged' or len(current['challenges']) >= _CHALLENGES:
                        fail()
                    item = {'phase': 'activation', 'nonce': secrets.token_urlsafe(32), 'created': now,
                            'expires': now + _SOURCE_TTL, 'consumed': False, 'descriptor': None}
                    current['challenges'][request_id] = item
                    current['phase'] = 'activation-pending'
                    current['heldActivation'] = {'packetSha256': packet_sha256, 'requestId': request_id,
                        'intentSha256': None, 'descriptorSha256': None, 'offerSha256': None,
                        'terminalChallenge': None, 'terminalReceiptSha256': None}
                    self._save(current)
                elif current['phase'] != 'activation-pending' or item['consumed'] or not item['created'] <= now <= item['expires']:
                    fail()
                return {'collectionNonce': item['nonce'], 'issuedAtMs': item['created'], 'expiresAtMs': item['expires']}

            return self.store._transaction(issue)

    def open_held_activation(self, offer, descriptors, deadline):
        from .bootstrap_source import activation_intent
        from .collector_execution import HeldStageProof
        keys = ('operationId', 'planSha256', 'packetSha256')
        with self._activation_scope(*(offer[key] for key in keys)) as (record, packet, approval, _, review, _, verify):
            item = record['challenges'].get(offer['requestId'])
            if (record['phase'] != 'activation-pending' or offer['requestId'] != packet['activationRequestId']
                    or item is None or item['consumed'] or item['nonce'] != offer['collectionNonce']
                    or not item['created'] <= self.store._now() <= item['expires']
                    or offer['holdBinding'] != packet['reviewSha256'] or offer['reviewSha256'] != packet['reviewSha256']
                    or offer['sourceSha256'] != record['sourceSha256']
                    or offer['inventorySha256'] != review['collector']['inventorySha256']
                    or review['recovery']['process'] != _receiver_invocation()):
                fail()
            with activation_intent(review, packet, offer['packetSha256'], approval, item) as (intent, recheck):
                if intent != offer['intentSha256']:
                    fail()
                verify()
                recheck()
                request = {key: offer[key] for key in ('operationId', 'planSha256', 'collectionNonce')}
                scope = {'root': review['root'], 'context': review['context'], 'holdBinding': offer['holdBinding'],
                         'request': {**request, 'phase': 'activation', 'origin': self.origin}}
                return HeldStageProof(offer, descriptors, deadline, scope=scope, inventory=offer['inventorySha256'])

    def activate_held(self, proof):
        from .bootstrap_source import activation_intent
        from .collector_execution import HeldStageProof
        if type(proof) is not HeldStageProof or proof.phase != 'activation':
            fail()
        offer = proof.offer
        operation, plan_sha, packet_sha, request = (offer[key] for key in ('operationId', 'planSha256', 'packetSha256', 'requestId'))
        with (self.profiles._operation(),
              self._activation_scope(operation, plan_sha, packet_sha) as (record, packet, approval, core, review, directory, verify),
              self._held_delivery(directory, record) as (delivery, material)):
            item = record['challenges'].get(request)
            if (record['phase'] != 'activation-pending' or item is None or item['consumed']
                    or request != packet['activationRequestId'] or item['nonce'] != offer['collectionNonce']):
                fail()
            with (activation_intent(review, packet, packet_sha, approval, item) as (intent, verify_intent),
                  self.sources.source(operation, plan_sha, 'activation', item['nonce'],
                                      issued_at=item['created'], expires_at=item['expires']) as captured):
                if intent != offer['intentSha256']:
                    fail()
                terminal_challenge = secrets.token_urlsafe(32)
                proof.check(captured)

                def check():
                    verify()
                    verify_intent()
                    delivery.verify()
                    self._delivery_value(delivery.body, record)
                    if not item['created'] <= self.store._now() <= item['expires']:
                        fail()

                def consume():
                    current = self._load(operation)
                    if current != record:
                        fail()
                    check()
                    self._pending_key(current, material)
                    current['challenges'][request].update(consumed=True, descriptor=captured.descriptor_sha256)
                    current['heldActivation'].update(intentSha256=intent, descriptorSha256=captured.descriptor_sha256,
                        offerSha256=digest(encoded(offer)), terminalChallenge=terminal_challenge)
                    self._save(current)
                    return current

                consumed = self.store._transaction(consume)
                candidate = consumed['candidate']
                source = self.profiles.inspect_retained(record['sourceSha256'])
                target = self.profiles.inspect_retained(candidate['target'])
                if (digest(captured.body) != source.digest or source.digest != record['sourceSha256']
                        or self.incarnations._content(source) != candidate['content']
                        or self.incarnations._content(target) != candidate['content']
                        or json.loads(target._metadata) != candidate['profile']):
                    fail()

                def before_commit():
                    check()
                    self._pending_key(consumed, material)
                    proof.check(captured)
                    check()

                self.store._commit_held_bootstrap(consumed, core, proof, before_commit)
                return terminal_challenge, digest(encoded(core))

    def finish_held_activation(self, proof, *, terminal_challenge, receipt_sha256, commit_sha256):
        from .bootstrap_source import ACTIVATION_TERMINAL, activation_intent
        from .collector_execution import HeldStageProof
        if (type(proof) is not HeldStageProof or proof.phase != 'activation'
                or not hash_value(receipt_sha256) or not hash_value(commit_sha256)):
            fail()
        proof.terminal()
        offer = proof.offer
        operation, plan, packet_sha = (offer[key] for key in ('operationId', 'planSha256', 'packetSha256'))
        with self._activation_scope(operation, plan, packet_sha) as (record, packet, approval, core, review, directory, verify):
            held = record['heldActivation']
            item = record['challenges'][held['requestId']]
            if (record['phase'] != 'activation-committed' or held['terminalReceiptSha256'] is not None
                    or held['offerSha256'] != digest(encoded(offer)) or held['terminalChallenge'] != terminal_challenge
                    or digest(encoded(core)) != commit_sha256):
                fail()
            with (PrivateFile(directory, 'held-activation-terminal.json', 16384) as terminal,
                  activation_intent(review, packet, packet_sha, approval, item) as (intent, verify_intent)):
                body = decode(terminal.body)
                event = body.get('receipt')
                if (digest(terminal.body) != receipt_sha256 or intent != held['intentSha256']
                        or body != {'schema': ACTIVATION_TERMINAL, 'offerSha256': held['offerSha256'],
                                    'terminalChallenge': terminal_challenge, 'commitSha256': commit_sha256, 'receipt': event}):
                    fail()
                self._held_terminal_event(proof, packet, event)

                def commit():
                    current = self._load(operation)
                    if current != record:
                        fail()
                    self.store._held_bootstrap_rows(current)
                    verify()
                    verify_intent()
                    terminal.verify()
                    current['heldActivation']['terminalReceiptSha256'] = receipt_sha256
                    self._save(current)

                self.store._transaction(commit)
                return self._activation_readback(record, terminal=receipt_sha256)

    @staticmethod
    def _activation_readback(record, *, terminal):
        held = record['heldActivation']
        return {'phase': 'activation-committed', 'operationId': record['operationId'],
                'planSha256': record['planSha256'], 'packetSha256': held['packetSha256'],
                'requestId': held['requestId'], 'commitSha256': digest(encoded(record['activation'])),
                'terminalReceiptSha256': terminal, 'generation': record['activation']['generation'],
                'revision': record['activation']['revision'], 'keyRevision': record['key']['revision']}

    def held_activation_receipt(self, *, operation_id, plan_sha256, packet_sha256):
        from .bootstrap_source import activation_intent
        with self._activation_scope(operation_id, plan_sha256, packet_sha256) as (record, packet, approval, _, review, directory, verify):
            if record['phase'] != 'activation-committed':
                fail()
            held = record['heldActivation']
            item = record['challenges'][held['requestId']]
            with ExitStack() as resources:
                intent, verify_intent = resources.enter_context(activation_intent(review, packet, packet_sha256, approval, item))
                terminal_sha = held['terminalReceiptSha256']
                terminal = None
                if terminal_sha is not None:
                    terminal = resources.enter_context(PrivateFile(directory, 'held-activation-terminal.json', 16384))
                    if digest(terminal.body) != terminal_sha:
                        fail()
                if intent != held['intentSha256']:
                    fail()

                def read():
                    current = self._load(operation_id)
                    if current != record:
                        fail()
                    self.store._held_bootstrap_rows(current)
                    verify()
                    verify_intent()
                    if terminal is not None:
                        terminal.verify()
                    return self._activation_readback(current, terminal=terminal_sha)

                return self.store._transaction(read)

    def held_activation_projection(self, *, operation_id, plan_sha256, request_id):
        if not hash_value(request_id):
            fail()
        with self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            record = self.store._transaction(lambda: self._load(operation_id))
            if plan['schema'] != HELD_PLAN or record['phase'] != 'acknowledged' or request_id in record['challenges']:
                fail()
            with (held_review(directory, operation_id, plan['reviewSha256']) as review,
                  self._held_stage_evidence(plan, directory, record, review) as (captured, verify),
                  self._held_delivery(directory, record) as (delivery, material)):
                core = self._activation_core(record, request_id)
                candidate = record['candidate']

                def read():
                    if self._load(operation_id) != record or not hash_value(captured.exporter_capability_sha256):
                        fail()
                    self._pending_key(record, material)
                    verify()
                    delivery.verify()
                    return {'stage': {'terminalReceiptSha256': record['heldStage']['terminalReceiptSha256'],
                        'sourceSha256': record['sourceSha256'], 'identitySha256': core['identitySha256'],
                        'revision': core['revision'], 'contentSha256': candidate['content'],
                        'pendingGeneration': record['pendingGeneration']},
                        'key': {'revision': core['keyRevision'], 'ackReceiptId': core['ackReceiptId']},
                        'projectedCommitSha256': digest(encoded(core)), 'exporterCapabilitySha256': captured.exporter_capability_sha256}

                return self.store._transaction(read)

    def _committed_packet_receipt(self, value, packet):
        held = value['heldActivation']
        receipt = self._activation_readback(value, terminal=held['terminalReceiptSha256'])
        stage, key = packet['stage'], packet['key']
        if (receipt['commitSha256'] != packet['candidate']['projectedCommitSha256']
                or stage != {'terminalReceiptSha256': value['heldStage']['terminalReceiptSha256'],
                      'sourceSha256': value['sourceSha256'], 'identitySha256': value['candidate']['target'],
                      'revision': value['candidate']['revision'], 'contentSha256': value['candidate']['content'],
                      'pendingGeneration': value['pendingGeneration']}
                or key != {'revision': value['key']['revision'], 'ackReceiptId': value['key']['ack']}):
            fail()
        return receipt

    def held_activation_reconcile(self, *, operation_id, plan_sha256, packet_sha256):
        from .bootstrap_source import (activation_completion, activation_intent, activation_packet, host_commit_view, review_documents)
        with (self.store._borrow(), PrivateDirectory(self.sources.operation_path(operation_id)) as directory,
              self.sources.plan_documents(directory, operation_id, plan_sha256) as (plan, check_plan),
              review_documents(directory, operation_id, plan['reviewSha256']) as (review, check_review),
              activation_packet(directory, plan, review, packet_sha256) as (packet, approval, check_packet)):
            self.sources.check_review_plan(plan, review)
            value = self.store._transaction(lambda: self._load(operation_id))
            held = value.get('heldActivation')
            if (value['phase'] != 'activation-committed' or held['packetSha256'] != packet_sha256
                    or held['requestId'] != packet['activationRequestId'] or not hash_value(held['terminalReceiptSha256'])
                    or review['recovery']['process'] != _receiver_invocation()):
                fail()
            receipt = self._committed_packet_receipt(value, packet)
            item = value['challenges'][held['requestId']]
            with (activation_intent(review, packet, packet_sha256, approval, item) as (intent, check_intent),
                  PrivateFile(directory, 'held-activation-terminal.json', 16384) as terminal,
                  PrivateFile(directory, 'activation-history.json', 65536) as history,
                  self._held_stage_evidence(plan, directory, value, review) as (staged, check_stage),
                  self.sources.collected_source(plan, review, plan_sha256, 'activation', item['nonce'],
                      issued_at=item['created'], expires_at=item['expires']) as fresh,
                  host_commit_view(review, packet, packet_sha256, approval,
                      activation_completion(packet, packet_sha256, held['intentSha256'], receipt)) as (_, check_progress)):
                expected_capability = decode(history.body)['current']['sourceExporter']['capabilitiesSha256']
                if (intent != held['intentSha256'] or digest(terminal.body) != held['terminalReceiptSha256']
                        or digest(history.body) != packet['candidate']['historySha256']
                        or not hash_value(expected_capability) or fresh.exporter_capability_sha256 != expected_capability
                        or staged.exporter_capability_sha256 != expected_capability
                        or fresh.descriptor_sha256 != held['descriptorSha256']):
                    fail()

                def read():
                    current = self._load(operation_id)
                    if current != value:
                        fail()
                    self.store._held_bootstrap_rows(current)
                    for check in (check_plan, check_review, check_packet, check_intent, terminal.verify,
                                  history.verify, check_stage, fresh.verify, check_progress):
                        check()
                    return receipt

                return self.store._transaction(read)

    def paired_publication_ready(self, *, operation_id, plan_sha256, packet_sha256):
        return self._paired_publication(operation_id, plan_sha256, packet_sha256, publish=False)

    def paired_publication_publish(self, *, operation_id, plan_sha256, packet_sha256):
        return self._paired_publication(operation_id, plan_sha256, packet_sha256, publish=True)

    def _paired_publication(self, operation, plan_sha, packet_sha, *, publish):
        from . import bootstrap_publication as publication
        from .bootstrap_source import ACTIVATION_TERMINAL, activation_completion, activation_packet, review_documents

        with (self.store._borrow(), PrivateDirectory(self.sources.operation_path(operation)) as directory,
              self.sources.plan_documents(directory, operation, plan_sha) as (plan, check_plan),
              review_documents(directory, operation, plan['reviewSha256']) as (review, check_review),
              activation_packet(directory, plan, review, packet_sha) as (packet, approval, check_packet)):
            self.sources.check_review_plan(plan, review)
            value = self.store._transaction(lambda: self._load(operation))
            held = value.get('heldActivation')
            phase = value['phase']
            if (phase not in (('publication-ready', 'paired-published') if publish else
                             ('activation-committed', 'publication-ready'))
                    or value['planSha256'] != plan_sha or held['packetSha256'] != packet_sha
                    or held['requestId'] != packet['activationRequestId'] or not hash_value(held['terminalReceiptSha256'])):
                fail()

            receipt = self._committed_packet_receipt(value, packet)
            if phase == 'paired-published' and os.path.lexists(directory.path / publication.PROOF_FILE):
                with PrivateFile(directory, 'activation-history.json', 65536) as history:
                    return self._replay_paired_publication(value, packet, review, history)
            completion = activation_completion(packet, packet_sha, held['intentSha256'], receipt)
            ready = value.get('pairedPublication', {}).get('ready')
            item = value['challenges'][held['requestId']]
            with (PrivateFile(directory, 'held-activation-terminal.json', 16384) as terminal,
                  PrivateFile(directory, 'activation-history.json', 65536) as history,
                  self._held_stage_artifacts(plan, directory, value, review) as (staged, check_stage),
                  self.sources.collected_source(plan, review, plan_sha, 'activation', item['nonce'],
                      issued_at=item['created'], expires_at=item['expires']) as fresh):
                body = decode(terminal.body)
                expected_capability = decode(history.body)['current']['sourceExporter']['capabilitiesSha256']
                if (digest(terminal.body) != held['terminalReceiptSha256']
                        or type(body.get('receipt')) is not dict
                        or body != {'schema': ACTIVATION_TERMINAL, 'offerSha256': held['offerSha256'],
                                    'terminalChallenge': held['terminalChallenge'], 'commitSha256': receipt['commitSha256'],
                                    'receipt': body.get('receipt')}
                        or digest(history.body) != packet['candidate']['historySha256']
                        or not hash_value(expected_capability) or fresh.exporter_capability_sha256 != expected_capability
                        or staged.exporter_capability_sha256 != expected_capability
                        or fresh.descriptor_sha256 != held['descriptorSha256']):
                    fail()

                with publication.host_publication(review, packet, approval, completion, self.store._setup,
                        recovery_directory=self.store._directory, ready=ready if publish else None) as host_proof:
                    def recheck():
                        for check in (check_plan, check_review, check_packet, terminal.verify, history.verify,
                                      check_stage, fresh.verify, host_proof.recheck):
                            check()

                    result = self.store._transaction(lambda: self._advance_paired_publication(value, host_proof, recheck))
                    if publish:
                        self.store._transaction(lambda: self._export_paired_publication(operation, result, directory, recheck))
                    return result

    def _replay_paired_publication(self, value, packet, review, history):
        from .bootstrap_publication import PROOF_FILE, proof_record, read_published
        with read_published(Path(review['captureRoot']).parent, recovery_directory=self.store._directory,
                            root=packet['root'], context=packet['context'], daemon=packet['daemon'],
                            history_body=history.body) as published:
            def read():
                current = self._load(value['operationId'])
                if current != value or (published.operation_id, published.plan_sha256, published.packet_sha256) != (
                        current['operationId'], current['planSha256'], current['heldActivation']['packetSha256']):
                    fail()
                self.store._publication_idle()
                result = current['pairedPublication']['published']
                if digest(encoded(result)) != published.receipt_sha256:
                    fail()
                # A prior rename may have succeeded before its directory sync
                # failed. Exact replay must finish durability, not just read it.
                with (PrivateDirectory(self.sources.operation_path(current['operationId'])) as directory,
                      PrivateFile(directory, PROOF_FILE, 16384) as proof):
                    if proof.body != encoded(proof_record(current)):
                        fail()
                    os.fsync(proof.fd)
                    os.fsync(directory.fd)
                    proof.verify()
                history.verify()
                published.recheck()
                return result

            return self.store._transaction(read)

    def _advance_paired_publication(self, value, host_proof, recheck):
        from .bootstrap_publication import PUBLISHED, READY, _HostPublication
        if type(host_proof) is not _HostPublication:
            fail()
        current = self._load(value['operationId'])
        if (current != value or not self.store._db.in_transaction
                or self.store._db.execute('SELECT 1 FROM bootstrap_operations WHERE operation<>? LIMIT 1',
                                          (current['operationId'],)).fetchone() is not None):
            fail()
        result = decode(host_proof.body)
        recheck()
        if result['schema'] == READY and current['phase'] in ('activation-committed', 'publication-ready'):
            self.store._held_bootstrap_rows(current)
            state = {'ready': result, 'published': None}
            if current.get('pairedPublication', state) != state:
                fail()
            current.update(phase='publication-ready', pairedPublication=state)
        elif result['schema'] == PUBLISHED and current['phase'] in ('publication-ready', 'paired-published'):
            state = current['pairedPublication']
            if current['phase'] == 'publication-ready':
                self.store._publish_paired_rows(current)
                current['phase'], state['published'] = 'paired-published', result
            elif state['published'] != result:
                fail()
            self.store._paired_published_rows(current)
        else:
            fail()
        self._save(current)
        recheck()
        return result

    def _export_paired_publication(self, operation, published, directory, recheck):
        from .bootstrap_publication import PROOF_FILE, proof_record
        from .recovery_listener_install import _new_file
        value = self._load(operation)
        if value['phase'] != 'paired-published' or value['pairedPublication']['published'] != published:
            fail()
        self.store._paired_published_rows(value)
        recheck()
        _new_file(directory.path / PROOF_FILE, encoded(proof_record(value)), 0o600)
        self.store._check_paired_publication(value)
        recheck()

    @contextmanager
    def _key_stage(self, plan, directory, record):
        held = plan['schema'] == HELD_PLAN
        if (('heldStage' in record) != held or held and record['planSha256'] != digest(encoded(plan))
                or record['operationId'] != plan['operationId'] or record['installationId'] != plan['installationId']
                or record['sourceSha256'] != plan['sourceSha256'] or record['origin'] != plan['origin']):
            fail()
        if not held:
            if self.store._setup is not None:
                fail()
            yield lambda: None
            return
        operation, plan_sha = record['operationId'], record['planSha256']
        with (held_review(directory, operation, plan['reviewSha256']) as review,
              self._held_stage_evidence(plan, directory, record, review) as (_, verify_stage)):
            def recheck():
                verify_stage()
                with self.sources.plan(operation, plan_sha) as (current, _):
                    if current != plan:
                        fail()

            recheck()
            yield recheck
            recheck()

    @contextmanager
    def _held_stage_evidence(self, plan, directory, record, review):
        with self._held_stage_artifacts(plan, directory, record, review) as (captured, check):
            def recheck():
                check()
                self._listener_setup_check(review)

            recheck()
            yield captured, recheck
            recheck()

    @contextmanager
    def _held_stage_artifacts(self, plan, directory, record, review):
        stage = record.get('heldStage')
        if stage is None or not hash_value(stage['terminalReceiptSha256']):
            fail()
        request = stage['requestId']
        item = record['challenges'][request]
        nonce = item['nonce']
        operation, plan_sha = record['operationId'], record['planSha256']
        if record['stageBinding'] != digest(encoded([operation, plan_sha, request, nonce])):
            fail()
        with (PrivateFile(directory, 'held-stage-terminal.json', 16384) as terminal,
              self.sources.collected_source(plan, review, plan_sha, 'proposal', nonce,
                  issued_at=item['created'], expires_at=item['expires']) as captured):
            packet = decode(terminal.body)
            event = packet.get('receipt')
            if (digest(terminal.body) != stage['terminalReceiptSha256'] or type(event) is not dict
                    or packet != {'schema': 'orbis.sentinel-bootstrap-held-terminal.v1', 'offerSha256': stage['offerSha256'],
                                  'terminalChallenge': stage['terminalChallenge'], 'receipt': event}
                    or event.get('phase') != 'complete' or event.get('exitCode') != 0
                    or event.get('installationId') != record['installationId']
                    or event.get('sourceSha256') != record['sourceSha256'] or digest(captured.body) != record['sourceSha256']
                    or event.get('descriptorSha256') != item['descriptor'] or captured.descriptor_sha256 != item['descriptor']
                    or event.get('process', {}).get('pid') != captured.collector_pid
                    or event.get('process', {}).get('startTicks') != captured.collector_start_ticks
                    or event.get('root') != review['root'] or event.get('context') != review['context']
                    or event.get('holdBinding') != plan['reviewSha256']
                    or event.get('inventorySha256') != review['collector']['inventorySha256']
                    or event.get('request') != {'operationId': operation, 'planSha256': plan_sha, 'phase': 'proposal',
                                                'collectionNonce': nonce, 'origin': self.origin}):
                fail()

            def recheck():
                terminal.verify()
                captured.verify()

            recheck()
            yield captured, recheck
            recheck()

    def _new_delivery(self, record):
        now = self.store._now()
        return encoded({'schema': 'orbis.sentinel-bootstrap-delivery.v1', 'operationId': record['operationId'],
                        'planSha256': record['planSha256'], 'revision': secrets.token_hex(32), 'epoch': secrets.token_hex(32),
                        'created': now, 'expires': now + _KEY_TTL,
                        'recoveryKey': 'orbis-recovery-' + secrets.token_urlsafe(32)})

    def _reserve_held_delivery(self, directory, record, recheck):
        def reserve():
            current = self._load(record['operationId'])
            self._pending(current)
            recheck()
            if current != record or self.store._db.execute('SELECT 1 FROM recovery_keys').fetchone():
                fail()
            if 'keyPreparation' in current:
                return current, None
            try:
                os.stat('delivery.json', dir_fd=directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                fail()
            body = self._new_delivery(current)
            current['keyPreparation'] = digest(body)
            self._save(current)
            return current, body
        return self.store._transaction(reserve)

    def _pending_key(self, record, delivery):
        self._pending(record)
        rows = self.store._db.execute('SELECT * FROM recovery_keys').fetchall()
        expected = sessions._recovery_key_digest(delivery['recoveryKey'])
        if (len(rows) != 1 or rows[0]['revision'] != record['key']['revision'] or rows[0]['active'] != -1
                or rows[0]['previous_revision'] is not None or rows[0]['origin'] != self.origin
                or rows[0]['created'] != record['key']['created'] or not secrets.compare_digest(rows[0]['digest'], expected)):
            fail()

    def prepare_key(self, *, operation_id, plan_sha256):
        with self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            record = self.store._transaction(lambda: self._load(operation_id))
            if record['planSha256'] != plan_sha256 or record['phase'] not in ('staged', 'key-prepared', 'acknowledged'):
                fail()
            with self._key_stage(plan, directory, record) as recheck:
                self.store._transaction(lambda: self._pending(record))
                if record['key'] is not None:
                    with self._held_delivery(directory, record) as (delivery, value):
                        self.store._transaction(lambda: self._pending_key(self._load(operation_id), value))
                    return self.status(operation_id=operation_id)
                if plan['schema'] == HELD_PLAN:
                    record, body = self._reserve_held_delivery(directory, record, recheck)
                    if body is not None:
                        create_file(directory, 'delivery.json', body)
                else:
                    try:
                        with PrivateFile(directory, 'delivery.json', 4096):
                            pass
                    except FileNotFoundError:
                        create_file(directory, 'delivery.json', self._new_delivery(record))
                with PrivateFile(directory, 'delivery.json', 4096) as delivery:
                    value = self._delivery_value(delivery.body, record)
                    if 'keyPreparation' in record and record['keyPreparation'] != digest(delivery.body):
                        fail()
                    def commit():
                        current = self._load(operation_id)
                        self._pending(current)
                        recheck()
                        delivery.verify()
                        self._delivery_value(delivery.body, current)
                        if current != record or current['phase'] != 'staged' or self.store._db.execute('SELECT 1 FROM recovery_keys').fetchone():
                            fail()
                        self.store._db.execute('INSERT INTO recovery_keys VALUES (?,?,?,-1,NULL,?)',
                            (value['revision'], sessions._recovery_key_digest(value['recoveryKey']), self.origin, value['created']))
                        current['key'] = {'revision': value['revision'], 'deliverySha256': digest(delivery.body), 'epoch': value['epoch'],
                                          'created': value['created'], 'expires': value['expires'], 'ack': None}
                        current['phase'] = 'key-prepared'
                        self._save(current)
                    self.store._transaction(commit)
                    delivery.verify()
                return self.status(operation_id=operation_id)

    def _delivery_value(self, body, record):
        value = decode(body)
        fields = {'schema', 'operationId', 'planSha256', 'revision', 'epoch', 'created', 'expires', 'recoveryKey'}
        if (set(value) != fields or value['schema'] != 'orbis.sentinel-bootstrap-delivery.v1'
                or value['operationId'] != record['operationId'] or value['planSha256'] != record['planSha256']
                or not hash_value(value['revision']) or not hash_value(value['epoch'])
                or not sessions._integer(value['created'], 1) or value['expires'] != value['created'] + _KEY_TTL
                or not value['created'] <= self.store._now() <= value['expires']):
            fail()
        sessions._recovery_key_digest(value['recoveryKey'])
        return value

    @contextmanager
    def _held_delivery(self, directory, record):
        with PrivateFile(directory, 'delivery.json', 4096) as delivery:
            value = self._delivery_value(delivery.body, record)
            key = record['key']
            if (key['deliverySha256'] != digest(delivery.body)
                    or (key['revision'], key['epoch'], key['created'], key['expires'])
                    != (value['revision'], value['epoch'], value['created'], value['expires'])):
                fail()
            yield delivery, value
            delivery.verify()

    def _delivery(self, directory, record):
        with self._held_delivery(directory, record) as (_, value):
            return value

    def held_key_status(self, *, operation_id, plan_sha256):
        with self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            record = self.store._transaction(lambda: self._load(operation_id))
            if plan['schema'] != HELD_PLAN or record['phase'] not in ('key-prepared', 'acknowledged'):
                fail()
            with self._key_stage(plan, directory, record), self._held_delivery(directory, record) as (_, value):
                self.store._transaction(lambda: self._pending_key(record, value))
                return self.status(operation_id=operation_id)

    def acknowledge(self, *, operation_id, plan_sha256, delivery_epoch, recovery_key):
        key_digest = sessions._recovery_key_digest(recovery_key)
        with self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            record = self.store._transaction(lambda: self._load(operation_id))
            if record['planSha256'] != plan_sha256 or record['phase'] not in ('key-prepared', 'acknowledged'):
                fail()
            with self._key_stage(plan, directory, record) as recheck, self._held_delivery(directory, record) as (delivery, value):
                if value['epoch'] != delivery_epoch or not secrets.compare_digest(key_digest, sessions._recovery_key_digest(value['recoveryKey'])):
                    fail()
                acknowledgement = digest(encoded([operation_id, plan_sha256, delivery_epoch, record['key']['revision'], key_digest]))
                def write():
                    current = self._load(operation_id)
                    recheck()
                    delivery.verify()
                    self._delivery_value(delivery.body, current)
                    self._pending_key(current, value)
                    if current['key'] != record['key'] or current['phase'] not in ('key-prepared', 'acknowledged'):
                        fail()
                    current['phase'], current['key']['ack'] = 'acknowledged', acknowledgement
                    self._save(current)
                self.store._transaction(write)
                return {'ackReceiptId': acknowledgement, 'keyRevision': record['key']['revision']}

    def activate(self, *, operation_id, plan_sha256, request_id, collection_nonce, ack_receipt_id):
        if self.store._setup is not None:
            fail()
        with self.profiles._operation():
            record = self.store._transaction(lambda: self._load(operation_id))
            if record['phase'] == 'active':
                binding = digest(encoded([operation_id, plan_sha256, request_id, collection_nonce, ack_receipt_id]))
                if record['activationBinding'] != binding:
                    fail()
                return self.store._transaction(lambda: self.store._bootstrap_activation_receipt(operation_id, plan_sha256, ack_receipt_id))
            record, challenge = self._consume(operation_id, plan_sha256, request_id, collection_nonce, 'activation')
            if record['key']['ack'] != ack_receipt_id:
                fail()
            with self.sources.source(operation_id, plan_sha256, 'activation', collection_nonce,
                                     issued_at=challenge['created'], expires_at=challenge['expires']) as captured:
                source = self.profiles.prepare(captured.body)
                candidate = record['candidate']
                target = self.profiles.inspect_retained(candidate['target'])
                if (source.digest != record['sourceSha256'] or self.incarnations._content(source) != candidate['content']
                        or self.incarnations._content(target) != candidate['content'] or json.loads(target._metadata) != candidate['profile']):
                    fail()
                # Actual files and crypto are necessary but do not prove a live
                # PostgreSQL/file/Host lease. This fixed gate currently refuses.
                def verified():
                    current = self._load(operation_id)
                    if current != record:
                        fail()
                    current['challenges'][request_id]['descriptor'] = captured.descriptor_sha256
                    self._save(current)
                self.store._transaction(verified)
                self.sources.require_live_context(captured)
                floor, managed_intent = self.sources.require_writer_floor(captured)
                if not hash_value(floor) or not hash_value(managed_intent):
                    fail()
                def record_floor():
                    current = self._load(operation_id)
                    self._pending(current)
                    current['writerFloor'], current['managedIntent'] = floor, managed_intent
                    self._save(current)
                self.store._transaction(record_floor)
                with self.sources.plan(operation_id, plan_sha256) as (_, directory):
                    key = self._delivery(directory, record)
                proof = _BootstrapActivationProof(self.store, operation_id, plan_sha256, source.digest, target.digest,
                    candidate['content'], captured.descriptor_sha256, record['pendingGeneration'], record['key']['revision'], ack_receipt_id,
                    request_id, sessions._recovery_key_digest(key['recoveryKey']), floor, managed_intent)
                return self.store._activate_initial_bootstrap(proof)

    def browser_key_handoff(self, action, *, operation_id, review_sha256, plan_sha256,
                            key_revision, delivery_epoch, handoff=None, recovery_key=None):
        """An explicit Root grant for one already prepared key, scoped to this owner process."""
        binding = (operation_id, review_sha256, plan_sha256, key_revision, delivery_epoch)
        if not all(hash_value(field) for field in binding):
            fail()
        with self._browser_lock, self.sources.plan(operation_id, plan_sha256) as (plan, directory):
            if plan['schema'] != HELD_PLAN or plan['reviewSha256'] != review_sha256:
                fail()
            record = self.store._transaction(lambda: self._load(operation_id))
            if (record['phase'] not in ('key-prepared', 'acknowledged') or record['key']['revision'] != key_revision
                    or record['key']['epoch'] != delivery_epoch):
                fail()
            if action == 'revoke':
                if self._browser_grant is not None and self._browser_grant[0] == binding:
                    self._browser_grant = None
                return {'state': 'revoked'}
            with self._key_stage(plan, directory, record) as check, self._held_delivery(directory, record) as (delivery, key):
                self.store._transaction(lambda: self._pending_key(self._load(operation_id), key))
                check()
                delivery.verify()
                now = self.store._now()
                if action == 'authorize':
                    if record['phase'] != 'key-prepared':
                        fail()
                    token = secrets.token_urlsafe(32)
                    until = min(now + 300000, key['expires'])
                    if now >= until:
                        fail()
                    self._browser_grant = (binding, sessions._token(token), until, False)
                    return {'state': 'authorized', 'handoff': token, 'expiresAtMs': until}
                grant = self._browser_grant
                if (grant is None or grant[0] != binding or now >= grant[2]
                        or not secrets.compare_digest(grant[1], sessions._token(handoff))):
                    fail()
                if action == 'deliver' and record['phase'] == 'key-prepared':
                    self._browser_grant = (*grant[:3], True)
                    return {'origin': self.origin, 'recoveryKey': key['recoveryKey']}
                if action == 'confirm' and grant[3]:
                    receipt = self.acknowledge(operation_id=operation_id, plan_sha256=plan_sha256,
                                               delivery_epoch=delivery_epoch, recovery_key=recovery_key)
                    if receipt['keyRevision'] != key_revision:
                        fail()
                    return {'origin': self.origin, 'state': 'acknowledged'}
                fail()

    def enrollment_state(self):
        """Project progress from the existing Root owner without returning any operation or key material."""
        def read():
            rows = self.store._db.execute('SELECT operation FROM bootstrap_operations LIMIT 2').fetchall()
            if len(rows) > 1:
                fail()
            record = self._load(rows[0]['operation']) if rows else None
            if record is not None and record['origin'] != self.origin:
                fail()
            if record is None or record['phase'] in ('active', 'paired-published'):
                operator = self.store._operator_status()
                has_key = self.store._db.execute('SELECT 1 FROM recovery_keys WHERE active=1 LIMIT 1').fetchone()
                if record is None and operator['state'] == 'never-enrolled' and not has_key:
                    return 'not-started'
                self.store._publication_idle()
                if (operator['state'] != 'enrolled' or self.store._identity('password')['origin'] != self.origin
                        or self.store._identity('recovery-key')['origin'] != self.origin):
                    fail()
                return 'activated'
            phase = record['phase']
            if phase == 'collecting' or (phase == 'staged' and record.get('heldStage') is not None
                                         and record['heldStage']['terminalReceiptSha256'] is None):
                return 'staging'
            if phase == 'staged':
                return 'operator-staged'
            if phase in _PAIRED_PHASES:
                return 'activation-pending'
            if record['key']['expires'] <= self.store._now():
                return 'key-expired'
            return 'key-prepared' if phase == 'key-prepared' else 'key-acknowledged'
        return {'origin': self.origin, 'stage': self.store._transaction(read)}

    def status(self, *, operation_id):
        def read():
            value = self._load(operation_id)
            if value['phase'] == 'active':
                return self.store._bootstrap_activation_receipt(operation_id, value['planSha256'], value['key']['ack'])
            if value['phase'] == 'paired-published':
                self.store._publication_idle()
                return value['pairedPublication']['published']
            candidate, key = value['candidate'], value['key']
            held = value.get('heldStage')
            phase = value['phase']
            if held is not None and phase in ('collecting', 'staged'):
                phase = 'held-stage-complete' if held['terminalReceiptSha256'] else 'held-stage-pending'
            result = {'operationId': operation_id, 'planSha256': value['planSha256'], 'phase': phase,
                    'sourceSha256': value['sourceSha256'], 'identitySha256': candidate['target'] if candidate else None,
                    'revision': candidate['revision'] if candidate else None, 'generation': value['pendingGeneration'],
                    'keyRevision': key['revision'] if key else None, 'deliveryEpoch': key['epoch'] if key else None,
                    'expiresAtMs': key['expires'] if key else None, 'ackReceiptId': key['ack'] if key else None}
            if held is not None:
                result.update(requestId=held['requestId'], terminalReceiptSha256=held['terminalReceiptSha256'],
                              deliverySha256=key['deliverySha256'] if key else None)
            return result
        return self.store._transaction(read)
