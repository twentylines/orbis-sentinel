"""Root-owned source artifacts, distinct from a live SQL/file collector lease."""
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from . import recovery_sessions as sessions
from .recovery_config import _pairs
from .writer_journal import mount_id, directory_seal, seal

HOST_STATE = Path('/var/lib/orbis/state')
HELD_PLAN = 'orbis.sentinel-bootstrap-plan.v2'
ACTIVATION_PACKET = 'orbis.sentinel-bootstrap-activation-packet.v1'
ACTIVATION_COMMIT = 'orbis.sentinel-bootstrap-activation-commit.v1'
ACTIVATION_TERMINAL = 'orbis.sentinel-bootstrap-held-activation-terminal.v1'
ACTIVATION_BRIDGE = 'orbis.credential-storage-v1-predecessor-bridge.v1'
ACTIVATION_PROGRESS = 'credential-bootstrap-config-progress.json'
ACTIVATION_COMPLETE = 'credential-bootstrap-config-complete.json'
CONFIG_ARCHIVE = 'credential-floor-config-history'
LISTENER_RECEIPT_FILE = 'listener-setup-receipt.json'
BUILTIN_LISTENER_RECEIPT = 'orbis.sentinel-recovery-listener-receipt.v2'
PAIRED_TRANSPORT_SCHEMA = 'orbis.sentinel-recovery-paired-transport.v1'
PAIRED_TRANSPORT_FILE = 'paired-transport-receipt.json'
ACTIVATION_PHASES = ('terminal-verified', 'predecessor-archived', 'bridge-ready', 'history-ready', 'config-verified', 'complete')
_REVIEW_FIELDS = {'schema', 'operationId', 'root', 'context', 'installationId', 'origin', 'captureRoot',
                  'hostHistorySha256', 'previousGeneration', 'previousAdmissionSha256', 'previousSentinelVersion',
                  'previousWriterProtocol', 'daemon', 'layoutSha256', 'main', 'host', 'collector', 'publisher',
                  'runtime', 'recovery', 'storage', 'journal'}


def fail():
    raise ValueError('The protected bootstrap source requires reconciliation.') from None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def listener_review_binding(review):
    """The same reviewed setup scope for listener and minimal floor readers."""
    return {'scope': {name: review[name] for name in ('root', 'context', 'installationId', 'daemon', 'origin')},
            'publication': review['publisher'], 'main': review['main'], 'runtime': review['runtime'],
            'historySha256': review['hostHistorySha256'], 'admissionSha256': review['previousAdmissionSha256']}


def hash_value(value):
    return type(value) is str and sessions._HEX.fullmatch(value) is not None


def decode(body):
    value = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: fail())
    if type(value) is not dict:
        fail()
    return value


def _hash_fields(value, fields):
    if type(value) is not dict or set(value) != set(fields) or any(not hash_value(item) for item in value.values()):
        fail()


class PrivateDirectory:
    def __init__(self, path):
        self.path, self.pins = Path(path), []
        try:
            if not self.path.is_absolute() or str(self.path) != os.path.realpath(self.path):
                fail()
            for current in (*reversed(self.path.parents), self.path):
                fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                self.pins.append((current, fd, directory_seal(info), mount_id(fd)))
                if info.st_uid not in {0, sessions._OWNER_UID} or info.st_mode & 0o022:
                    fail()
            leaf = os.fstat(self.fd)
            if leaf.st_uid != sessions._OWNER_UID or stat.S_IMODE(leaf.st_mode) != 0o700:
                fail()
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.pins[-1][1]

    def verify(self):
        if not self.pins or str(self.path) != os.path.realpath(self.path):
            fail()
        for path, fd, identity, mounted in self.pins:
            fresh = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if (directory_seal(os.fstat(fd)) != identity or directory_seal(os.fstat(fresh)) != identity
                        or mount_id(fd) != mounted or mount_id(fresh) != mounted):
                    fail()
            finally:
                os.close(fresh)

    def close(self):
        for _, fd, _, _ in reversed(self.pins):
            os.close(fd)
        self.pins.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PrivateFile:
    def __init__(self, directory, name, maximum):
        self.directory, self.name, self.fd = directory, name, None
        try:
            if type(name) is not str or Path(name).name != name:
                fail()
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory.fd)
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
                fail()
            self.identity = seal(info)
            self.mounted = mount_id(self.fd)
            if self.mounted != mount_id(directory.fd):
                fail()
            self.body = os.read(self.fd, maximum + 1)
            if len(self.body) != info.st_size:
                fail()
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        self.directory.verify()
        if self.fd is None:
            fail()
        fresh = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=self.directory.fd)
        try:
            if (any(seal(os.fstat(fd)) != self.identity or mount_id(fd) != self.mounted
                    for fd in (self.fd, fresh)) or mount_id(self.directory.fd) != self.mounted):
                fail()
        finally:
            os.close(fresh)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def create_file(directory, name, body):
    if type(body) is not bytes or not 0 < len(body) <= 65536 or Path(name).name != name:
        fail()
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory.fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(fd)
        os.fsync(directory.fd)
        directory.verify()
    finally:
        os.close(fd)


@dataclass(frozen=True)
class CollectedSource:
    owner: object
    operation: str
    plan_sha256: str
    phase: str
    nonce: str
    body: bytes
    descriptor_sha256: str
    collector_pid: int | None = None
    collector_start_ticks: int | None = None
    _held_files: tuple = ()
    exporter_capability_sha256: str | None = None

    def verify(self):
        for source in self._held_files:
            source.verify()


@contextmanager
def review_documents(directory, operation, review_sha256):
    """Pin the closed review and its consent, leaving predecessor selection to the caller."""
    with (PrivateFile(directory, 'review-plan.json', 16384) as review,
          PrivateFile(directory, 'review-approval.json', 4096) as approval):
        value, consent = decode(review.body), decode(approval.body)
        if (set(value) != _REVIEW_FIELDS or value['schema'] != 'orbis.sentinel-bootstrap-review.v2'
                or digest(review.body) != review_sha256 or value['operationId'] != operation
                or not all(hash_value(value[key]) for key in
                           ('installationId', 'hostHistorySha256', 'previousAdmissionSha256', 'layoutSha256'))
                or not sessions._integer(value['previousGeneration'], 1)
                or not sessions._integer(value['previousWriterProtocol'], 1)
                or type(value['context']) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['context']) is None):
            fail()
        root = value['root']
        if (type(root) is not str or not 1 <= len(os.fsencode(root)) <= 4096 or not root.startswith('/')
                or root.startswith('//') or os.path.normpath(root) != root or any(ord(char) < 32 for char in root)):
            fail()
        namespace_path = HOST_STATE / 'installations' / digest(os.fsencode(root))
        if (value['captureRoot'] != str(namespace_path / 'bootstrap-sources')
                or namespace_path.is_relative_to(root) or Path(root).is_relative_to(namespace_path)):
            fail()
        if consent != {'schema': 'orbis.sentinel-bootstrap-review-approval.v2', 'operationId': operation,
                       'reviewSha256': review_sha256, 'installationId': value['installationId'],
                       'approvalId': consent.get('approvalId')} or not hash_value(consent.get('approvalId')):
            fail()
        sessions._origin(value['origin'])
        publisher, collector = value['publisher'], value['collector']
        if (type(publisher) is not dict or set(publisher) != {'operationId', 'receiptSha256'}
                or not all(hash_value(item) for item in publisher.values())
                or type(collector) is not dict
                or set(collector) != {'protocol', 'programSha256', 'imageId', 'inventorySha256'}
                or collector['protocol'] != 'orbis.stopped-main-source.v1'
                or not all(hash_value(collector[key]) for key in ('programSha256', 'inventorySha256'))
                or type(collector['imageId']) is not str
                or re.fullmatch(r'sha256:[a-f0-9]{64}', collector['imageId']) is None):
            fail()
        def verify():
            review.verify()
            approval.verify()

        yield value, verify
        verify()


def check_v1_predecessor(review, history, admission):
    predecessor = decode(history)
    if (digest(history) != review['hostHistorySha256'] or digest(admission) != review['previousAdmissionSha256']
            or predecessor.get('schema') != 'orbis.recovery-admission-history.v1'
            or predecessor.get('mode') != 'unmanaged' or predecessor.get('managedEver') is not False
            or predecessor.get('installationId') != review['installationId']
            or predecessor.get('generation') != review['previousGeneration']
            or predecessor.get('configSha256') != review['previousAdmissionSha256']):
        fail()
    return predecessor


@contextmanager
def held_review(directory, operation, review_sha256):
    """Pin approved C1 evidence and exact live V1 history/admission outside masked Main."""
    with (review_documents(directory, operation, review_sha256) as (value, verify),
          PrivateDirectory(Path(value['captureRoot']).parent) as namespace,
          PrivateDirectory(HOST_STATE) as host,
          PrivateFile(namespace, 'recovery-admission-history.json', 16384) as history,
          PrivateFile(host, 'credential-admission.json', 16384) as admission):
        check_v1_predecessor(value, history.body, admission.body)
        try:
            yield value
        finally:
            verify()
            history.verify()
            admission.verify()


@contextmanager
def activation_packet(directory, plan, review, packet_sha256):
    """Open the exact pre-publication packet and separately issued consent."""
    if plan.get('schema') != HELD_PLAN or not hash_value(packet_sha256):
        fail()
    with ExitStack() as resources:
        pins = []

        def read(name, maximum, expected=None):
            pinned = resources.enter_context(PrivateFile(directory, name, maximum))
            pins.append(pinned)
            if expected is not None and digest(pinned.body) != expected:
                fail()
            value = decode(pinned.body)
            if pinned.body != encoded(value):
                fail()
            return value, digest(pinned.body)

        packet, _ = read('activation-packet.json', 65536, packet_sha256)
        approval, approval_sha = read('activation-approval.json', 16384)
        scope = {key: review[key] for key in ('operationId', 'installationId', 'root', 'context', 'daemon', 'origin')}
        static = {'schema': ACTIVATION_PACKET, **scope, 'reviewSha256': plan['reviewSha256'],
                  'planSha256': digest(encoded(plan)), 'publication': review['publisher'],
                  'prior': {'historySha256': review['hostHistorySha256'],
                            'configSha256': review['previousAdmissionSha256'],
                            'generation': review['previousGeneration']}}
        fields = ('stage', 'key', 'activationRequestId', 'candidate')
        if (set(packet) != set(static).union(fields) or any(packet[key] != item for key, item in static.items())
                or not hash_value(packet['activationRequestId'])):
            fail()
        stage = packet['stage']
        stage_fields = ('terminalReceiptSha256', 'sourceSha256', 'identitySha256', 'revision', 'contentSha256')
        if (type(stage) is not dict or set(stage) != {*stage_fields, 'pendingGeneration'}
                or not sessions._integer(stage['pendingGeneration'], 1, 9_007_199_254_740_990)
                or stage['sourceSha256'] != plan['sourceSha256']):
            fail()
        _hash_fields({key: stage[key] for key in stage_fields}, stage_fields)
        _hash_fields(packet['key'], ('revision', 'ackReceiptId'))
        candidate = packet['candidate']
        _hash_fields(candidate, ('configSha256', 'historySha256', 'bridgeSha256', 'projectedCommitSha256'))
        if (approval != {'schema': 'orbis.sentinel-bootstrap-activation-approval.v1',
                         'operationId': packet['operationId'], 'installationId': packet['installationId'],
                         'packetSha256': packet_sha256, 'activationRequestId': packet['activationRequestId'],
                         'approvalId': approval.get('approvalId')} or not hash_value(approval.get('approvalId'))):
            fail()
        config, _ = read('activation-config.json', 16384, candidate['configSha256'])
        history, _ = read('activation-history.json', 65536, candidate['historySha256'])
        bridge, _ = read('activation-bridge.json', 32768, candidate['bridgeSha256'])
        _activation_candidate(packet, review, config, history, bridge)

        def verify():
            for pinned in pins:
                pinned.verify()

        verify()
        yield packet, approval_sha, verify
        verify()


def _activation_candidate(packet, review, config, history, bridge):
    from . import credential_floor as floor
    from . import credential_storage as storage
    candidate, prior = packet['candidate'], packet['prior']
    recovery, runtime = review['recovery'], review['runtime']
    installation = packet['installationId']
    floor.record(history, installation)
    storage.validate_bridge({**bridge, 'schema': storage.BRIDGE_SCHEMA},
        installation=installation, context=packet['context'], daemon=packet['daemon'], previous=prior['historySha256'])
    current = history['current']
    epoch = digest(encoded({'operationId': packet['operationId'], 'reviewSha256': packet['reviewSha256'],
                            'prior': prior, 'publication': packet['publication']}))
    if (config != {'schema': 'orbis.host.credential-admission.v1', 'mode': 'managed',
                   **{key: packet[key] for key in ('installationId', 'root', 'context', 'origin')},
                   'writerProtocol': history['writerProtocol'], 'recoveryEpoch': epoch,
                   'runtimeDirectory': runtime['runtimeDirectory'], 'runtimeFiles': runtime['runtimeFiles'],
                   'journalDirectory': str(Path(review['captureRoot']).parent / 'credential-journal'),
                   'recoveryConfig': str(floor.RECOVERY_ROOT / 'config.json'), 'recoveryConfigSha256': recovery['configSha256']}
            or history['schema'] != floor.SCHEMA or history['mode'] != 'managed'
            or history['previousSha256'] != prior['historySha256'] or history['generation'] != prior['generation'] + 1
            or history['configSha256'] != candidate['configSha256'] or history['sentinelVersion'] != runtime['version']
            or history['planSha256'] != packet['planSha256']
            or floor._version_order(history['sentinelVersion']) < floor._version_order(review['previousSentinelVersion'])
            or history['writerProtocol'] < review['previousWriterProtocol']
            or any(history['minimum'][name]['version'] != version for name, (_, version) in floor.CONTRACTS.items())
            or current['storage']['bridgeSha256'] != candidate['bridgeSha256']
            or current['storage']['parentFloorSha256'] != prior['historySha256']
            or current['main'] != {'imageId': review['main']['imageId'], 'creationSha256': review['main']['definitionSha256'],
                                   'publicationSha256': review['main']['publicationSha256']}
            or current['host'] != {key: review['host'][key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')}
            or current['sentinel']['inventorySha256'] != runtime['inventorySha256']
            or current['sentinel']['unitSha256'] != recovery['unitSha256']
            or current['sentinel']['environmentSha256'] != recovery['environmentSha256']
            or current['sourceExporter']['imageId'] != review['collector']['imageId']
            or current['sourceExporter']['programSha256'] != review['collector']['programSha256']
            or current['recoveryOrigin'] != packet['origin']
            or current['configuration']['recoveryConfigSha256'] != recovery['configSha256']
            or current['configuration']['recoveryEnvironmentSha256'] != recovery['environmentSha256']
            or current['receipts'] != {'bootstrapSha256': packet['stage']['terminalReceiptSha256'],
                                       'sourceSha256': packet['stage']['sourceSha256'],
                                       'activationSha256': candidate['projectedCommitSha256']}
            or bridge['schema'] != ACTIVATION_BRIDGE or bridge['roles'] != review['storage']
            or bridge['publicationOperation'] != packet['publication']['operationId']
            or bridge['publicationSha256'] != packet['publication']['receiptSha256']
            or bridge['recoveryUnitSha256'] != recovery['unitSha256']):
        fail()


@contextmanager
def activation_intent(review, packet, packet_sha256, approval_sha256, challenge):
    """Verify the still-held Host selector and exact issued request, with no writes."""
    with (PrivateDirectory(Path(review['captureRoot']).parent) as namespace,
          PrivateFile(namespace, 'credential-bootstrap-intent.json', 16384) as intent,
          PrivateFile(namespace, 'credential-fence.json', 4096) as fence):
        value = {'schema': 'orbis.host.credential-bootstrap-intent.v1',
                 **{key: packet[key] for key in ('operationId', 'installationId', 'reviewSha256', 'planSha256', 'activationRequestId')},
                 'packetSha256': packet_sha256, 'approvalSha256': approval_sha256,
                 'nonceSha256': digest(challenge['nonce'].encode('ascii')),
                 'issuedAtMs': challenge['created'], 'expiresAtMs': challenge['expires']}
        expected = {'schema': 'orbis.host-credential-fence.v1', 'operationId': packet['operationId'],
                    'root': review['root'], 'context': review['context'], 'admissionBinding': packet['reviewSha256']}
        if intent.body != encoded(value) or fence.body != encoded(expected) + b'\n':
            fail()

        def verify():
            intent.verify()
            fence.verify()

        verify()
        yield digest(intent.body), verify
        verify()


def v1_contract_minima(review, prior_history, prior_config):
    from . import credential_floor as floor
    prior = check_v1_predecessor(review, prior_history, prior_config)
    floor.exact(prior, ('schema', 'installationId', 'generation', 'managedEver', 'mode',
                        'configSha256', 'planSha256', 'sentinelVersion', 'writerProtocol'))
    if (not hash_value(prior['planSha256']) or not floor.integer(prior['generation'], 1)
            or prior['sentinelVersion'] != review['previousSentinelVersion']
            or prior['writerProtocol'] != review['previousWriterProtocol']
            or not floor.integer(prior['writerProtocol'], 1)):
        fail()
    floor._version_order(prior['sentinelVersion'])
    # V1 has one numeric advertised writer floor. Its other inherited protocol
    # families use the original v1 baseline, not today's preferred versions.
    minimum = dict(reader=1, mainWriter=1, hostBroker=prior['writerProtocol'],
                   hostGuard=1, source=1, counter=1, effectiveIdentity=1, bootstrap=1)
    if set(minimum) != set(floor.CONTRACTS) or any(
            minimum[name] > supported for name, (_, supported) in floor.CONTRACTS.items()):
        fail()
    return minimum


def activation_completion(packet, packet_sha256, intent_sha256, receipt):
    return {'schema': 'orbis.host.credential-bootstrap-completion.v1',
            **{key: packet[key] for key in ('operationId', 'installationId', 'reviewSha256')},
            'packetSha256': packet_sha256, 'intentSha256': intent_sha256,
            **{key: packet['candidate'][key] for key in ('historySha256', 'configSha256', 'bridgeSha256')},
            'commitSha256': receipt['commitSha256'], 'terminalSha256': receipt['terminalReceiptSha256'],
            'generation': packet['prior']['generation'] + 1}


def activation_progress(phase, packet_sha, approval_sha, completion):
    return encoded({'schema': 'orbis.host.credential-bootstrap-config-progress.v1', 'phase': phase,
                    'completionSha256': digest(encoded(completion)), 'approvalSha256': approval_sha, 'packetSha256': packet_sha})


@dataclass(frozen=True)
class HostCommitView:
    phase: str | None
    history: bytes
    config: bytes
    prior_history: bytes
    prior_config: bytes
    archive_history: bool
    archive_config: bool
    bridge_present: bool
    inherited_minima: tuple


@contextmanager
def host_commit_view(review, packet, packet_sha, approval_sha, completion):
    """Pin the exact durable prefix allowed for this one completed activation."""
    from . import credential_floor as floor
    from . import credential_storage as storage
    with ExitStack() as resources:
        namespace = resources.enter_context(PrivateDirectory(Path(review['captureRoot']).parent))
        host = resources.enter_context(PrivateDirectory(HOST_STATE))
        pins = []

        def read(parent, name, limit, *, optional=False):
            try:
                pinned = resources.enter_context(PrivateFile(parent, name, limit))
            except FileNotFoundError:
                if optional:
                    return None
                raise
            if mount_id(pinned.fd) != mount_id(parent.fd):
                fail()
            pins.append(pinned)
            return pinned.body

        def archive(folder, expected):
            if not os.path.lexists(namespace.path / folder):
                return None, None
            directory = resources.enter_context(PrivateDirectory(namespace.path / folder))
            if mount_id(directory.fd) != mount_id(namespace.fd):
                fail()
            name = expected + '.json'
            body = read(directory, name, 65536, optional=True)
            staged = read(directory, '.' + name + '.pending', 65536, optional=True)
            if any(part is not None and digest(part) != expected for part in (body, staged)):
                fail()
            return body, staged

        clean_names = (
                'recovery-admission-intent.json', 'credential-storage-migration.json',
                '.credential-storage-migration.json.pending', 'credential-storage-migration-complete.json',
                '.credential-bootstrap-intent.json.pending', '.recovery-admission-intent.json.pending')

        def clean():
            if any(os.path.lexists(namespace.path / name) for name in clean_names):
                fail()

        clean()
        progress = read(namespace, ACTIVATION_PROGRESS, 16384, optional=True)
        complete = read(namespace, ACTIVATION_COMPLETE, 16384, optional=True)
        phase = None
        if progress is not None:
            phase = decode(progress).get('phase')
            if phase not in ACTIVATION_PHASES or progress != activation_progress(phase, packet_sha, approval_sha, completion):
                fail()

        history = read(namespace, floor.HISTORY, 65536)
        config = read(host, 'credential-admission.json', 16384)
        prior = packet['prior']
        archived_history, staged_archive = archive(floor.ARCHIVE, prior['historySha256'])
        archived_config, staged_config_archive = archive(CONFIG_ARCHIVE, prior['configSha256'])
        bridge, staged_bridge = archive(storage.BRIDGE_DIRECTORY, packet['candidate']['bridgeSha256'])
        old_history = digest(history) == prior['historySha256']
        old_config = digest(config) == prior['configSha256']
        if not old_history and digest(history) != packet['candidate']['historySha256']:
            fail()
        if not old_config and digest(config) != packet['candidate']['configSha256']:
            fail()
        rank = -1 if phase is None else ACTIVATION_PHASES.index(phase)
        if (rank < 0 and (archived_history is not None or archived_config is not None)
                or archived_config is not None and archived_history is None
                or rank >= 1 and (archived_history is None or archived_config is None)
                or rank < 1 and bridge is not None or rank >= 2 and bridge is None
                or rank < 2 and not old_history or rank >= 3 and old_history
                or rank < 3 and not old_config or rank >= 4 and old_config
                or rank < 4 and complete is not None
                or rank >= 5 and complete is None
                or complete is not None and complete != encoded(completion)):
            fail()

        if (staged_archive is not None and (rank != 0 or archived_history is not None)
                or staged_config_archive is not None and (rank != 0 or archived_history is None or archived_config is not None)
                or staged_bridge is not None and (rank != 1 or bridge is not None)):
            fail()
        progress_ready = (rank == -1 or rank == 0 and archived_config is not None or rank == 1 and bridge is not None
                          or rank == 2 and not old_history or rank == 3 and not old_config or rank == 4 and complete is not None)
        next_progress = activation_progress(ACTIVATION_PHASES[rank + 1], packet_sha, approval_sha, completion) if progress_ready else None
        pending = (
            (namespace, ACTIVATION_PROGRESS, 16384, digest(next_progress) if next_progress is not None else None),
            (namespace, floor.HISTORY, 65536, packet['candidate']['historySha256'] if rank == 2 and old_history else None),
            (host, 'credential-admission.json', 16384, packet['candidate']['configSha256'] if rank == 3 and old_config else None),
            (namespace, ACTIVATION_COMPLETE, 16384, digest(encoded(completion)) if rank == 4 and complete is None else None),
        )
        for parent, name, limit, expected in pending:
            saved = read(parent, '.' + name + '.pending', limit, optional=True)
            if saved is not None and digest(saved) != expected:
                fail()

        prior_history = history if old_history else archived_history
        prior_config = config if old_config else archived_config
        if prior_history is None or prior_config is None:
            fail()
        minimum = v1_contract_minima(review, prior_history, prior_config)
        if not old_history:
            actual = decode(history)
            if any(actual['minimum'][name]['version'] < version for name, version in minimum.items()):
                fail()

        def verify():
            clean()
            for pinned in pins:
                pinned.verify()
            namespace.verify()
            host.verify()

        verify()
        yield HostCommitView(phase, history, config, prior_history, prior_config,
                            archived_history is not None, archived_config is not None, bridge is not None,
                            tuple(minimum.items())), verify
        verify()


class RootFileSourceWitness:
    """Actual protected files and Root nonce, never a Boolean SQL-lock claim.

    Artifact validation does not establish a live collector context. Production
    activation stays unavailable until a fixed independent live lease joins it.
    """
    def __init__(self, store):
        self.store = store

    def operation_path(self, operation):
        if not hash_value(operation):
            fail()
        return Path(self.store._directory) / 'bootstrap' / operation

    @staticmethod
    @contextmanager
    def plan_documents(directory, operation, expected_sha256):
        if not hash_value(expected_sha256):
            fail()
        with PrivateFile(directory, 'plan.json', 16384) as source, PrivateFile(directory, 'approval.json', 16384) as approval:
            value, consent = decode(source.body), decode(approval.body)
            fields = {'schema', 'operationId', 'installationId', 'origin', 'sourceSha256', 'captureRoot', 'collector', 'hostHistorySha256'}
            held = value.get('schema') == HELD_PLAN
            if (set(value) != fields | ({'reviewSha256'} if held else set())
                    or value['schema'] not in ('orbis.sentinel-bootstrap-plan.v1', HELD_PLAN)
                    or value['operationId'] != operation or digest(source.body) != expected_sha256
                    or not hash_value(value['installationId']) or not hash_value(value['sourceSha256'])
                    or value['hostHistorySha256'] is not None and not hash_value(value['hostHistorySha256'])):
                fail()
            sessions._origin(value['origin'])
            collector = value['collector']
            if (type(collector) is not dict or set(collector) != {'protocol', 'programSha256', 'imageId'}
                    or collector['protocol'] != 'orbis.stopped-main-source.v1' or not hash_value(collector['programSha256'])
                    or type(collector['imageId']) is not str or not collector['imageId'].startswith('sha256:')
                    or not hash_value(collector['imageId'][7:])):
                fail()
            expected_consent = 'orbis.sentinel-bootstrap-approval.v2' if held else 'orbis.sentinel-bootstrap-approval.v1'
            if (set(consent) != {'schema', 'operationId', 'planSha256', 'installationId', 'approvalId'}
                    or consent['schema'] != expected_consent or consent['operationId'] != operation
                    or consent['planSha256'] != expected_sha256 or consent['installationId'] != value['installationId']
                    or not hash_value(consent['approvalId'])):
                fail()
            root = Path(value['captureRoot']) if type(value['captureRoot']) is str else Path('.')
            if not root.is_absolute() or root.name != 'bootstrap-sources':
                fail()
            def verify():
                source.verify()
                approval.verify()

            yield value, verify
            verify()

    @contextmanager
    def plan(self, operation, expected_sha256):
        with (self.store._borrow(), PrivateDirectory(self.operation_path(operation)) as directory,
              self.plan_documents(directory, operation, expected_sha256) as (value, verify)):
            if value['schema'] == HELD_PLAN:
                with held_review(directory, operation, value['reviewSha256']) as review:
                    self.check_review_plan(value, review)
                    yield value, directory
                verify()
                return
            with PrivateDirectory(Path(value['captureRoot']).parent) as namespace:
                try:
                    with PrivateFile(namespace, 'recovery-admission-history.json', 16384) as history:
                        if digest(history.body) != value['hostHistorySha256']:
                            fail()
                        record = decode(history.body)
                        if (record.get('schema') != 'orbis.recovery-admission-history.v1' or record.get('managedEver') is not False
                                or record.get('mode') != 'unmanaged' or record.get('installationId') != value['installationId']):
                            fail()
                except FileNotFoundError:
                    if value['hostHistorySha256'] is not None:
                        fail()
                yield value, directory
                namespace.verify()
            verify()

    @staticmethod
    def check_review_plan(plan, review):
        if (plan['schema'] != HELD_PLAN
                or any(plan[key] != review[key] for key in ('installationId', 'origin', 'captureRoot', 'hostHistorySha256'))
                or plan['collector'] != {key: review['collector'][key] for key in plan['collector']}):
            fail()

    @contextmanager
    def source(self, operation, plan_sha256, phase, nonce, *, issued_at, expires_at):
        with self.plan(operation, plan_sha256) as (plan, directory):
            with ExitStack() as resources:
                review = None
                if plan['schema'] == HELD_PLAN:
                    review = resources.enter_context(held_review(directory, operation, plan['reviewSha256']))
                captured = resources.enter_context(self.collected_source(
                    plan, review, plan_sha256, phase, nonce, issued_at=issued_at, expires_at=expires_at))
                yield captured

    @contextmanager
    def collected_source(self, plan, review, plan_sha256, phase, nonce, *, issued_at, expires_at):
        sessions._token(nonce)
        if phase not in ('proposal', 'activation'):
            fail()
        operation = plan['operationId']
        path = Path(plan['captureRoot']) / operation / (phase + '-' + digest(nonce.encode('ascii')))
        with PrivateDirectory(path) as directory, PrivateFile(directory, 'source.json', 65536) as source, PrivateFile(directory, 'witness.json', 32768) as witness:
            value = decode(witness.body)
            fields = {'schema', 'operationId', 'planSha256', 'phase', 'collectionNonce', 'sourceSha256', 'descriptorSha256', 'descriptor', 'capturedAtMs'}
            if (set(value) != fields or value['schema'] != 'orbis.bootstrap-source-witness.v1'
                    or value['operationId'] != operation or value['planSha256'] != plan_sha256 or value['phase'] != phase
                    or value['collectionNonce'] != nonce or value['sourceSha256'] != digest(source.body)
                    or value['sourceSha256'] != plan['sourceSha256'] or type(value['descriptor']) is not dict
                    or not hash_value(value['descriptorSha256']) or value['descriptorSha256'] != digest(encoded(value['descriptor']))
                    or not sessions._integer(value['capturedAtMs'], issued_at, min(expires_at, self.store._now()))):
                fail()
            descriptor = value['descriptor']
            collector, exporter = descriptor.get('collector'), descriptor.get('exporter')
            if (descriptor.get('installationId') != plan['installationId'] or descriptor.get('origin') != plan['origin']
                    or type(collector) is not dict or collector.get('protocol') != plan['collector']['protocol']
                    or collector.get('programSha256') != plan['collector']['programSha256']
                    or not sessions._integer(collector.get('pid'), 1) or not sessions._integer(collector.get('startTicks'), 1)
                    or type(exporter) is not dict or exporter.get('imageId') != plan['collector']['imageId']
                    or exporter.get('phase') != 'awaiting-root-ack' or not hash_value(exporter.get('cid'))):
                fail()
            if review is not None:
                main = descriptor.get('main')
                if (type(main) is not dict
                        or any(main.get(key) != review['main'].get(key) for key in
                               ('id', 'imageId', 'publicationSha256', 'definitionSha256'))
                        or descriptor.get('daemon') != review['daemon']
                        or descriptor.get('layoutSha256') != review['layoutSha256']):
                    fail()
            result = CollectedSource(self, operation, plan_sha256, phase, nonce, source.body,
                                     value['descriptorSha256'], collector['pid'], collector['startTicks'],
                                     (source, witness), exporter.get('capabilitySha256'))
            yield result
            source.verify()
            witness.verify()

    def require_live_context(self, source):
        if type(source) is not CollectedSource or source.owner is not self or source.phase != 'activation':
            fail()
        raise ValueError('The live stopped-Main source context has not been qualified.')

    def require_writer_floor(self, source):
        if type(source) is not CollectedSource or source.owner is not self or source.phase != 'activation':
            fail()
        raise ValueError('The target writer floor and durable managed intent have not been qualified.')

