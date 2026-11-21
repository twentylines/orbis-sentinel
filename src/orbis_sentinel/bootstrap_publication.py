"""Protected evidence for the paired bootstrap's one-way publication boundary."""

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
import os
from pathlib import Path

from . import bootstrap_source as source
from .bootstrap_source import PrivateDirectory, PrivateFile, decode, digest, encoded, fail, hash_value, mount_id
from .bootstrap_source import (LISTENER_RECEIPT_FILE, BUILTIN_LISTENER_RECEIPT, PAIRED_TRANSPORT_SCHEMA,
                               PAIRED_TRANSPORT_FILE, listener_review_binding)
from .recovery_sessions import _LISTENER_SETUP_STORE

READY = 'orbis.sentinel-bootstrap-publication-ready.v1'
RELEASE = 'orbis.host.credential-bootstrap-release.v1'
PUBLISHED = 'orbis.sentinel-bootstrap-published.v1'
PROOF = 'orbis.sentinel-bootstrap-publication-proof.v1'
QUALIFICATION = 'orbis.host.credential-bootstrap-consumer-qualification.v1'
QUALIFICATION_FILE = 'credential-bootstrap-consumer-qualification.json'
QUALIFICATION_EVIDENCE = 'orbis.host.credential-bootstrap-consumer-evidence.v1'
QUALIFICATION_EVIDENCE_FILE = 'credential-bootstrap-consumer-evidence.json'
RELEASE_FILE = 'credential-bootstrap-release.json'
PROOF_FILE = 'paired-publication.json'
SETUP_RECEIPT_FILE = LISTENER_RECEIPT_FILE
FENCE = 'credential-fence.json'
INTENT = 'credential-bootstrap-intent.json'
RETIRED_FENCE = 'credential-bootstrap-fence-retired.json'
RETIRED_INTENT = 'credential-bootstrap-intent-retired.json'
_SCOPE = ('operationId', 'installationId', 'packetSha256', 'completionSha256')


def _scope(completion):
    return {**{key: completion[key] for key in _SCOPE[:-1]},
            'completionSha256': digest(encoded(completion))}


def _fence(packet):
    return encoded({'schema': 'orbis.host-credential-fence.v1', **{
        key: packet[key] for key in ('root', 'context', 'operationId')},
        'admissionBinding': packet['reviewSha256']}) + b'\n'


def _intent(packet, completion, approval, value):
    from .recovery_sessions import _integer
    expected = {'schema': 'orbis.host.credential-bootstrap-intent.v1', **{
        key: packet[key] for key in ('operationId', 'installationId', 'reviewSha256', 'planSha256', 'activationRequestId')},
        'packetSha256': completion['packetSha256'], 'approvalSha256': approval,
        **{key: value.get(key) for key in ('nonceSha256', 'issuedAtMs', 'expiresAtMs')}}
    if (value != expected or not hash_value(value['nonceSha256'])
            or not _integer(value['issuedAtMs'], 1) or not _integer(value['expiresAtMs'], value['issuedAtMs'] + 1)
            or digest(encoded(value)) != completion['intentSha256']):
        fail()


def _qualification(value, completion, review, setup_sha):
    expected = {'schema': QUALIFICATION, **_scope(completion), 'setupSha256': setup_sha,
                'pairSha256': value.get('pairSha256'),
                'hostEffectiveSha256': review['host']['effectiveSha256'],
                'listenerEffectiveSha256': review['recovery']['effectiveSha256'],
                'consumers': value.get('consumers')}
    roles = value.get('consumers')
    # Only a separately qualified retained Host producer may write this record.
    # Each role pins the installed consumer's exact qualification evidence.
    if (value != expected or not all(hash_value(value[key]) for key in (
            'pairSha256', 'hostEffectiveSha256', 'listenerEffectiveSha256')) or type(roles) is not dict
            or set(roles) != {'host', 'main', 'sentinel'} or not all(hash_value(item) for item in roles.values())):
        fail()


def qualification_evidence(review, packet, completion, setup_sha, pair_sha, receipt, history_body, config_body,
                           terminal_body, setup_receipts):
    """Project checked held observations; this value alone grants no authority."""
    expected = {'phase': 'activation-committed', 'operationId': packet['operationId'],
                'packetSha256': completion['packetSha256'], 'planSha256': packet['planSha256'],
                'requestId': packet['activationRequestId'], 'commitSha256': packet['candidate']['projectedCommitSha256'],
                'generation': packet['stage']['pendingGeneration'] + 1, 'revision': packet['stage']['revision'],
                'keyRevision': packet['key']['revision'], 'terminalReceiptSha256': completion['terminalSha256']}
    terminal, history = decode(terminal_body), decode(history_body)
    event = terminal.get('receipt')
    current = history.get('current')
    exporter = current.get('sourceExporter') if type(current) is dict else None
    if (type(receipt) is not dict or receipt != expected or type(receipt['generation']) is not int
            or digest(history_body) != packet['candidate']['historySha256']
            or digest(config_body) != packet['candidate']['configSha256']
            or digest(terminal_body) != completion['terminalSha256'] or terminal.get('schema') != source.ACTIVATION_TERMINAL
            or terminal.get('commitSha256') != receipt['commitSha256'] or type(event) is not dict
            or event.get('phase') != 'complete' or event.get('exitCode') != 0 or type(event.get('exitCode')) is not int
            or event.get('installationId') != packet['installationId'] or event.get('sourceSha256') != packet['stage']['sourceSha256']
            or not hash_value(event.get('descriptorSha256')) or event.get('root') != packet['root']
            or event.get('context') != packet['context'] or event.get('holdBinding') != packet['reviewSha256']
            or event.get('inventorySha256') != review['collector']['inventorySha256']
            or type(exporter) is not dict or exporter.get('imageId') != review['main']['imageId']
            or exporter.get('programSha256') != review['collector']['programSha256']
            or not hash_value(exporter.get('capabilitiesSha256')) or not hash_value(setup_sha) or not hash_value(pair_sha)
            or type(setup_receipts) is not dict
            or set(setup_receipts) != {'listenerReceiptSha256', 'pairedReceiptSha256', 'storeReservationSha256'}
            or not all(hash_value(item) for item in setup_receipts.values())):
        fail()
    scope = {**_scope(completion), 'planSha256': packet['planSha256']}
    roles = {
        'host': {'schema': 'orbis.host.bootstrap-held-host-observation.v1', **scope,
            'host': review['host'], 'layoutSha256': review['layoutSha256'],
            'storageSha256': digest(encoded(review['storage'])), 'journalSha256': digest(encoded(review['journal'])),
            'historySha256': digest(history_body), 'configSha256': digest(config_body),
            'bridgeSha256': packet['candidate']['bridgeSha256']},
        'main': {'schema': 'orbis.host.bootstrap-held-main-observation.v1', **scope,
            'main': review['main'], 'daemon': packet['daemon'], 'sourceSha256': event['sourceSha256'],
            'descriptorSha256': event['descriptorSha256'], 'terminalSha256': digest(terminal_body), 'sourceExporter': exporter},
        'sentinel': {'schema': 'orbis.host.bootstrap-held-sentinel-observation.v1', **scope,
            'recovery': review['recovery'], 'runtime': review['runtime'], 'setupSha256': setup_sha,
            'pairSha256': pair_sha, 'setupReceipts': dict(setup_receipts), 'receipt': receipt},
    }
    return {'schema': QUALIFICATION_EVIDENCE, **scope, 'roles': roles}


def qualification_record(evidence, completion, review, setup_sha, pair_sha):
    return {'schema': QUALIFICATION, **_scope(completion), 'setupSha256': setup_sha, 'pairSha256': pair_sha,
            'hostEffectiveSha256': review['host']['effectiveSha256'],
            'listenerEffectiveSha256': review['recovery']['effectiveSha256'],
            'consumers': {name: digest(encoded(value)) for name, value in evidence['roles'].items()}}


def _qualification_evidence(evidence, namespace, recovery, review, packet, completion, qualification):
    value = evidence.document(namespace, QUALIFICATION_EVIDENCE_FILE, 32768)
    try:
        receipt = value['roles']['sentinel']['receipt']
    except (KeyError, TypeError):
        fail()
    directory = evidence.stack.enter_context(PrivateDirectory(recovery.path / 'bootstrap' / packet['operationId']))
    if mount_id(directory.fd) != mount_id(recovery.fd):
        fail()
    expected = qualification_evidence(review, packet, completion, qualification['setupSha256'], qualification['pairSha256'],
        receipt, evidence.file(directory, 'activation-history.json', 65536),
        evidence.file(directory, 'activation-config.json', 16384),
        evidence.file(directory, 'held-activation-terminal.json', 16384),
        _setup_evidence(evidence, recovery, review, qualification))
    if (value != expected or qualification != qualification_record(
            expected, completion, review, qualification['setupSha256'], qualification['pairSha256'])):
        fail()
    evidence.absent(namespace, '.' + QUALIFICATION_EVIDENCE_FILE + '.pending')


def _ready(completion, setup_sha, qualification):
    return {'schema': READY, **_scope(completion), **{
        key: completion[key] for key in ('commitSha256', 'terminalSha256')},
        'setupSha256': setup_sha, 'pairSha256': qualification['pairSha256'],
        'consumerQualificationSha256': digest(encoded(qualification))}


def _release(ready, packet, completion):
    return {'schema': RELEASE, **{key: ready[key] for key in _SCOPE},
            'sentinelReadySha256': digest(encoded(ready)),
            'consumerQualificationSha256': ready['consumerQualificationSha256'],
            'fenceSha256': digest(_fence(packet)), 'intentSha256': completion['intentSha256']}


def _published(ready, release_sha, packet):
    return {'schema': PUBLISHED, **{key: ready[key] for key in _SCOPE},
            'releaseSha256': release_sha, 'commitSha256': ready['commitSha256'],
            'revision': packet['stage']['revision'], 'keyRevision': packet['key']['revision'],
            'generation': packet['stage']['pendingGeneration'] + 1}


def proof_record(record):
    state = record['pairedPublication']
    return {'schema': PROOF, 'planSha256': record['planSha256'],
            'ready': state['ready'], 'published': state['published']}


def validate_record(record):
    """Validate the closed paired subtype without changing the legacy active shape."""
    state = record['pairedPublication']
    if type(state) is not dict or set(state) != {'ready', 'published'}:
        fail()
    ready, published = state['ready'], state['published']
    if type(ready) is not dict or not all(hash_value(ready.get(key)) for key in (
            'completionSha256', 'setupSha256', 'pairSha256', 'consumerQualificationSha256')):
        fail()
    held, commit = record['heldActivation'], record['activation']
    if held['terminalReceiptSha256'] is None or ready != {
            'schema': READY, 'operationId': record['operationId'], 'installationId': record['installationId'],
            'packetSha256': held['packetSha256'], 'commitSha256': digest(encoded(commit)),
            'terminalSha256': held['terminalReceiptSha256'], **{key: ready[key] for key in (
                'completionSha256', 'setupSha256', 'pairSha256', 'consumerQualificationSha256')}}:
        fail()
    if record['phase'] == 'publication-ready':
        if published is not None:
            fail()
    elif (type(published) is not dict or not hash_value(published.get('releaseSha256'))
            or published != {'schema': PUBLISHED, **{key: ready[key] for key in _SCOPE},
                **{key: commit[key] for key in ('revision', 'keyRevision', 'generation')},
                'commitSha256': ready['commitSha256'], 'releaseSha256': published['releaseSha256']}
            or type(published['generation']) is not int):
        fail()


class _Evidence:
    def __init__(self, stack):
        self.stack = stack
        self.checks = []

    def file(self, directory, name, limit=16384):
        pinned = self.stack.enter_context(PrivateFile(directory, name, limit))
        if mount_id(pinned.fd) != mount_id(directory.fd):
            fail()
        self.checks.append(pinned.verify)
        return pinned.body

    def document(self, directory, name, limit=16384):
        body = self.file(directory, name, limit)
        value = decode(body)
        if encoded(value) != body:
            fail()
        return value

    def absent(self, directory, *names):
        def check():
            directory.verify()
            for name in names:
                try:
                    os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                fail()
        self.checks.append(check)
        check()

    def recheck(self):
        for check in self.checks:
            check()


def _setup_evidence(evidence, recovery, review, qualification):
    setup = evidence.document(recovery, LISTENER_RECEIPT_FILE, 32768)
    pair_body = evidence.file(recovery, PAIRED_TRANSPORT_FILE, 32768)
    pair = decode(pair_body)
    reservation = evidence.document(recovery, _LISTENER_SETUP_STORE, 2048)
    marker = qualification['setupSha256']
    operation = setup.get('operationId')
    binding = listener_review_binding(review)
    if (setup.get('schema') != BUILTIN_LISTENER_RECEIPT or not hash_value(operation)
            or any(setup.get(key) != value for key, value in binding.items())
            or setup.get('markerSha256') != marker or setup.get('pairedSha256') != digest(pair_body)
            or pair_body != encoded(pair) or pair.get('schema') != PAIRED_TRANSPORT_SCHEMA
            or pair.get('markerSha256') != marker or pair.get('operationId') != operation
            or pair.get('installationId') != review['installationId']
            or pair.get('pairSha256') != qualification['pairSha256']
            or reservation != {'operationId': operation, 'markerSha256': marker}):
        fail()
    evidence.absent(recovery, *('.' + name + '.pending' for name in (
        LISTENER_RECEIPT_FILE, PAIRED_TRANSPORT_FILE, _LISTENER_SETUP_STORE)))
    return {'listenerReceiptSha256': digest(encoded(setup)), 'pairedReceiptSha256': digest(pair_body),
            'storeReservationSha256': digest(encoded(reservation))}


def _retirement(evidence, namespace, packet, approval, completion, ready):
    release = _release(ready, packet, completion)
    if (evidence.document(namespace, RELEASE_FILE) != release
            or evidence.file(namespace, RETIRED_FENCE, 4096) != _fence(packet)):
        fail()
    _intent(packet, completion, approval, evidence.document(namespace, RETIRED_INTENT))
    return release


@dataclass(frozen=True)
class _HostPublication:
    body: bytes
    recheck: object = field(repr=False)


@contextmanager
def host_publication(review, packet, approval, completion, setup, *, recovery_directory, ready=None):
    """Pin the final config-last state and the exact held or retired selectors."""
    if (setup is None or setup.backend is None or setup.installation != packet['installationId']
            or setup.origin != packet['origin']):
        fail()
    setup.verify()
    with (ExitStack() as stack,
          source.host_commit_view(review, packet, completion['packetSha256'], approval, completion) as (view, check_commit)):
        if view.phase != 'complete':
            fail()
        namespace = stack.enter_context(PrivateDirectory(Path(review['captureRoot']).parent))
        evidence = _Evidence(stack)
        evidence.checks.extend((check_commit, setup.verify))
        evidence.absent(namespace, '.' + QUALIFICATION_FILE + '.pending', '.' + RELEASE_FILE + '.pending',
                        '.' + RETIRED_FENCE + '.pending', '.' + RETIRED_INTENT + '.pending', '.' + FENCE + '.pending')
        qualification = evidence.document(namespace, QUALIFICATION_FILE)
        _qualification(qualification, completion, review, setup.sha256)
        if qualification['pairSha256'] != setup.backend.pair_sha256:
            fail()
        recovery = stack.enter_context(PrivateDirectory(recovery_directory))
        _setup_evidence(evidence, recovery, review, qualification)
        _qualification_evidence(evidence, namespace, recovery, review, packet, completion, qualification)
        expected = _ready(completion, setup.sha256, qualification)
        if ready is None:
            evidence.absent(namespace, RELEASE_FILE, RETIRED_FENCE, RETIRED_INTENT)
            if evidence.file(namespace, FENCE, 4096) != _fence(packet):
                fail()
            _intent(packet, completion, approval, evidence.document(namespace, INTENT))
            result = expected
        else:
            if ready != expected:
                fail()
            evidence.absent(namespace, FENCE, INTENT)
            release = _retirement(evidence, namespace, packet, approval, completion, ready)
            result = _published(ready, digest(encoded(release)), packet)
        evidence.recheck()
        yield _HostPublication(encoded(result), evidence.recheck)
        evidence.recheck()


@dataclass(frozen=True)
class PublishedWitness:
    operation_id: str
    plan_sha256: str
    packet_sha256: str
    receipt_sha256: str
    host_generation: int
    sessions_generation: int
    _verify: object = field(repr=False)

    def recheck(self):
        self._verify()


@contextmanager
def read_published(namespace, *, recovery_directory, root, context, daemon, history_body):
    """Pin published evidence for the exact initial V3 child, even in a later lineage."""
    from . import credential_floor as floor
    from . import credential_storage as storage

    with ExitStack() as stack:
        evidence = _Evidence(stack)
        protected = stack.enter_context(PrivateDirectory(namespace))
        completion = evidence.document(protected, source.ACTIVATION_COMPLETE)
        operation, packet_sha = completion.get('operationId'), completion.get('packetSha256')
        if not hash_value(operation) or not hash_value(packet_sha):
            fail()
        recovery = stack.enter_context(PrivateDirectory(recovery_directory))
        directory = stack.enter_context(PrivateDirectory(recovery.path / 'bootstrap' / operation))
        if mount_id(directory.fd) != mount_id(recovery.fd):
            fail()
        proof = evidence.document(directory, PROOF_FILE)
        if set(proof) != {'schema', 'planSha256', 'ready', 'published'} or proof['schema'] != PROOF:
            fail()
        plan, check_plan = stack.enter_context(source.RootFileSourceWitness.plan_documents(directory, operation, proof['planSha256']))
        review, check_review = stack.enter_context(source.review_documents(directory, operation, plan['reviewSha256']))
        packet, approval, check_packet = stack.enter_context(source.activation_packet(directory, plan, review, packet_sha))
        source.RootFileSourceWitness.check_review_plan(plan, review)
        if ((packet['root'], packet['context'], packet['daemon']) != (str(root), context, daemon)
                or Path(review['captureRoot']).parent != protected.path
                or packet['candidate']['historySha256'] != digest(history_body)):
            fail()
        terminal_sha = completion.get('terminalSha256')
        intent_sha = completion.get('intentSha256')
        if (not hash_value(intent_sha) or not hash_value(terminal_sha)
                or completion != source.activation_completion(packet, packet_sha, intent_sha, {
                    'commitSha256': packet['candidate']['projectedCommitSha256'], 'terminalReceiptSha256': terminal_sha})
                or type(completion['generation']) is not int
                or evidence.file(protected, source.ACTIVATION_PROGRESS) != source.activation_progress(
                    'complete', packet_sha, approval, completion)):
            fail()

        def archive(folder, expected, limit):
            area = stack.enter_context(PrivateDirectory(protected.path / folder))
            if mount_id(area.fd) != mount_id(protected.fd):
                fail()
            name = expected + '.json'
            body = evidence.file(area, name, limit)
            if digest(body) != expected:
                fail()
            evidence.absent(area, '.' + name + '.pending')
            return body

        prior = packet['prior']
        minimum = source.v1_contract_minima(review, archive(floor.ARCHIVE, prior['historySha256'], 65536),
                                         archive(source.CONFIG_ARCHIVE, prior['configSha256'], 16384))
        if any(decode(history_body)['minimum'][name]['version'] < version for name, version in minimum.items()):
            fail()
        archive(storage.BRIDGE_DIRECTORY, packet['candidate']['bridgeSha256'], 32768)
        if any(digest(evidence.file(directory, name)) != expected for name, expected in (
                ('held-stage-terminal.json', packet['stage']['terminalReceiptSha256']),
                ('held-activation-terminal.json', terminal_sha))):
            fail()
        setup_receipt = evidence.document(recovery, SETUP_RECEIPT_FILE, 32768)
        setup_sha = setup_receipt.get('markerSha256')
        qualification = evidence.document(protected, QUALIFICATION_FILE)
        if not hash_value(setup_sha):
            fail()
        _qualification(qualification, completion, review, setup_sha)
        _setup_evidence(evidence, recovery, review, qualification)
        _qualification_evidence(evidence, protected, recovery, review, packet, completion, qualification)
        ready = _ready(completion, setup_sha, qualification)
        release = _retirement(evidence, protected, packet, approval, completion, ready)
        published = _published(ready, digest(encoded(release)), packet)
        if (encoded(proof['ready']) != encoded(ready) or encoded(proof['published']) != encoded(published)):
            fail()
        evidence.absent(directory, '.' + PROOF_FILE + '.pending')
        evidence.absent(protected, *('.' + name + '.pending' for name in (
            source.ACTIVATION_COMPLETE, source.ACTIVATION_PROGRESS, QUALIFICATION_FILE,
            RELEASE_FILE, RETIRED_FENCE, RETIRED_INTENT)))
        evidence.checks.extend((check_plan, check_review, check_packet, recovery.verify))
        result = PublishedWitness(operation, proof['planSha256'], packet_sha, digest(encoded(published)),
                                  completion['generation'], published['generation'], evidence.recheck)
        result.recheck()
        yield result
        result.recheck()
