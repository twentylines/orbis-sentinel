"""Read-only Root credential history; record consistency is not admission.

No producer, CLI, startup permission, publisher verifier or recovery-route hook
is provided here. Trusted retained Root orchestration supplies the actual Host
state directory/context/local daemon; nothing in this module is a Main API.
Live journal, incarnation/counter, publisher and process checks remain separate.
"""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat

from .bootstrap_source import PrivateDirectory, PrivateFile, decode, digest, encoded, hash_value
from . import credential_storage as storage, recovery_sessions as sessions
from .recovery_config import RecoveryConfig
from .writer_journal import directory_seal, mount_id, seal


STATE_ROOT = Path('/var/lib/orbis/state')
RECOVERY_ROOT = Path('/var/lib/orbis-sentinel/recovery')
RECOVERY_ENV = Path('/etc/orbis-sentinel/recovery.env')
RECOVERY_UNIT = Path('/etc/systemd/system/orbis-sentinel-recovery.service')
HISTORY = 'recovery-admission-history.json'
ARCHIVE = 'credential-floor-history'
LEGACY_SCHEMA = 'orbis.recovery-admission-history.v2'
SCHEMA = 'orbis.recovery-admission-history.v3'
CONTRACTS = {
    'reader': ('orbis.credential-floor', 3),
    'mainWriter': ('orbis.credentials', 1),
    'hostBroker': ('orbis.credential-broker', 1),
    'hostGuard': ('orbis.credential-lifecycle-guard', 1),
    'source': ('orbis.stopped-main-source', 1),
    'counter': ('orbis.sentinel-passkey-counter', 1),
    'effectiveIdentity': ('orbis.sentinel-effective-identity-content', 1),
    'bootstrap': ('orbis.sentinel-root-bootstrap-control', 1),
}
_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z')
_MAX = 65536
_ISSUER = object()


class CredentialFloorError(ValueError):
    def __init__(self):
        super().__init__('The protected credential floor requires reconciliation.')


class _LegacyUpgrade(Exception):
    pass


class _StorageUpgradeRequired(Exception):
    pass


def fail():
    raise CredentialFloorError() from None


def integer(value, minimum=0):
    return type(value) is int and minimum <= value <= 9_007_199_254_740_991


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        fail()


def image(value):
    return type(value) is str and value.startswith('sha256:') and hash_value(value[7:])


def _version_order(value):
    if type(value) is not str or len(value) > 128 or _VERSION.fullmatch(value) is None:
        fail()
    core, separator, suffix = value.partition('-')
    identifiers = suffix.split('.') if separator else []
    if any(item.isdecimal() and str(int(item)) != item for item in identifiers):
        fail()
    prerelease = tuple((0, int(item)) if item.isdecimal() else (1, item) for item in identifiers)
    return (*map(int, core.split('.')), not separator, prerelease)


def contracts(value):
    exact(value, CONTRACTS)
    for name, (family, _) in CONTRACTS.items():
        exact(value[name], ('family', 'version'))
        if value[name]['family'] != family or not integer(value[name]['version'], 1):
            fail()


def _hashes(value, fields):
    exact(value, fields)
    if any(not hash_value(item) for item in value.values()):
        fail()


def _directory(value):
    exact(value, ('identity', 'mountId'))
    if (type(value['identity']) is not list or len(value['identity']) != 5
            or any(not integer(item) for item in value['identity'])
            or value['mountId'] is not None and not integer(value['mountId'], 1)):
        fail()


def _remember_file(checks, source):
    mounted = mount_id(source.fd)

    def check():
        source.verify()
        fresh = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                        dir_fd=source.directory.fd)
        try:
            if mount_id(source.fd) != mounted or mount_id(fresh) != mounted:
                fail()
        finally:
            os.close(fresh)
    checks.append(check)


def _pin_recovery_unit(stack, checks, expected):
    directory = stack.enter_context(_EnvironmentDirectory(RECOVERY_UNIT.parent))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(RECOVERY_UNIT.name, flags, dir_fd=directory.fd)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    if (info.st_uid != sessions._OWNER_UID or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644
            or info.st_nlink != 1 or not 0 < info.st_size <= 16384):
        fail()
    identity, mounted = seal(info), mount_id(fd)
    body = os.read(fd, 16385)
    if len(body) != info.st_size or digest(body) != expected:
        fail()

    def check():
        directory.verify()
        fresh = os.open(RECOVERY_UNIT.name, flags, dir_fd=directory.fd)
        try:
            if any(seal(os.fstat(item)) != identity or mount_id(item) != mounted for item in (fd, fresh)):
                fail()
        finally:
            os.close(fresh)

    check()
    checks.append(check)


def current_binding(value, *, prospective=False, schema=None):
    """Validate a comparison document, never self-reported runtime authority."""
    exact(value, ('main', 'host', 'sentinel', 'authWorker', 'sourceExporter',
                  'recoveryOrigin', 'configuration', 'storage', 'receipts'))
    main = value['main']
    exact(main, ('imageId', 'creationSha256', 'publicationSha256'))
    if not image(main['imageId']):
        fail()
    _hashes({k: v for k, v in main.items() if k != 'imageId'}, ('creationSha256', 'publicationSha256'))
    _hashes(value['host'], ('inventorySha256', 'unitSha256', 'environmentSha256'))
    sentinel = value['sentinel']
    exact(sentinel, ('version', 'inventorySha256', 'runtimeSha256', 'unitSha256', 'environmentSha256'))
    _version_order(sentinel['version'])
    _hashes({k: v for k, v in sentinel.items() if k != 'version'},
            ('inventorySha256', 'runtimeSha256', 'unitSha256', 'environmentSha256'))
    for name, fields in (('authWorker', ('imageId', 'anchorSha256', 'capabilitiesSha256')),
                         ('sourceExporter', ('imageId', 'programSha256', 'capabilitiesSha256'))):
        exact(value[name], fields)
        if not image(value[name]['imageId']):
            fail()
        _hashes({k: v for k, v in value[name].items() if k != 'imageId'}, fields[1:])
    # First contract intentionally retains the admitted Main/auth image equality.
    if value['authWorker']['imageId'] != main['imageId']:
        fail()
    sessions._origin(value['recoveryOrigin'])
    _hashes(value['configuration'], ('hostAdmissionSha256', 'recoveryConfigSha256', 'recoveryEnvironmentSha256'))
    binding = value['storage']
    if schema is None:
        schema = SCHEMA if type(binding) is dict and 'bridgeSha256' in binding else LEGACY_SCHEMA
    if schema == SCHEMA:
        exact(binding, ('bridgeSha256', 'parentFloorSha256', 'journalSchema'))
        if not hash_value(binding['bridgeSha256']) or not hash_value(binding['parentFloorSha256']):
            fail()
    else:
        exact(binding, ('namespace', 'journal', 'recovery', 'journalSchema'))
        for name in ('namespace', 'journal', 'recovery'):
            _directory(binding[name])
    if value['storage']['journalSchema'] != 'orbis.sentinel-writer-journal.v1':
        fail()
    receipts = ('bootstrapSha256', 'sourceSha256', 'activationSha256')
    exact(value['receipts'], receipts)
    if prospective:
        if any(item is not None for item in value['receipts'].values()):
            fail()
    else:
        _hashes(value['receipts'], receipts)


def _initialization(value, installation, current):
    exact(value, ('schema', 'operationId', 'installationId', 'kind', 'scope',
                  'imageId', 'creationSha256', 'storageSha256', 'issuedAtMs', 'expiresAtMs'))
    if (value['schema'] != 'orbis.credential-floor-initialization.v1'
            or not hash_value(value['operationId']) or value['installationId'] != installation
            or (value['kind'], value['scope']) not in {
                ('fresh-initialize', 'create-missing-auth'), ('legacy-adopt-existing', 'preserve-existing-auth')}
            or value['imageId'] != current['main']['imageId']
            or value['creationSha256'] != current['main']['creationSha256']
            or value['storageSha256'] != digest(encoded(current['storage']))
            or not integer(value['issuedAtMs'], 1) or not integer(value['expiresAtMs'], 1)
            or not 0 < value['expiresAtMs'] - value['issuedAtMs'] <= 600000):
        fail()


def record(value, installation):
    exact(value, ('schema', 'installationId', 'generation', 'managedEver', 'mode',
                  'configSha256', 'planSha256', 'sentinelVersion', 'writerProtocol',
                  'previousSha256', 'minimum', 'current', 'positiveNeverManaged'))
    if (value['schema'] not in (LEGACY_SCHEMA, SCHEMA) or not hash_value(installation)
            or value['installationId'] != installation
            or not integer(value['generation'], 1) or type(value['managedEver']) is not bool
            or value['mode'] not in ('managed', 'initializing-never-managed')
            or not hash_value(value['configSha256']) or not hash_value(value['planSha256'])
            or not integer(value['writerProtocol'], 1)
            or value['previousSha256'] is not None and not hash_value(value['previousSha256'])
            or (value['generation'] == 1) != (value['previousSha256'] is None)):
        fail()
    contracts(value['minimum'])
    current_binding(value['current'], prospective=value['mode'] == 'initializing-never-managed',
                    schema=value['schema'])
    if value['schema'] == SCHEMA and (value['minimum']['reader']['version'] < 3
            or value['previousSha256'] is None or value['mode'] != 'managed'):
        fail()
    if (value['configSha256'] != value['current']['configuration']['hostAdmissionSha256']
            or value['sentinelVersion'] != value['current']['sentinel']['version']
            or value['writerProtocol'] != value['minimum']['hostBroker']['version']):
        fail()
    if value['mode'] == 'managed':
        if not value['managedEver'] or value['positiveNeverManaged'] is not None:
            fail()
    else:
        if value['managedEver']:
            fail()
        _initialization(value['positiveNeverManaged'], installation, value['current'])


def _legacy_record(value, installation):
    exact(value, ('schema', 'installationId', 'generation', 'managedEver', 'mode',
                  'configSha256', 'planSha256', 'sentinelVersion', 'writerProtocol'))
    if (value['schema'] != 'orbis.recovery-admission-history.v1'
            or value['installationId'] != installation or not integer(value['generation'], 1)
            or type(value['managedEver']) is not bool or value['mode'] not in ('managed', 'unmanaged')
            or value['mode'] == 'managed' and not value['managedEver']
            or not hash_value(value['configSha256']) or not hash_value(value['planSha256'])
            or not integer(value['writerProtocol'], 1)):
        fail()
    _version_order(value['sentinelVersion'])


def _legacy(value, installation):
    _legacy_record(value, installation)
    raise _LegacyUpgrade()


def _bootstrap_parent(body, child, installation):
    """Validate one V1 lineage edge; published proof is still required for admission."""
    if type(body) is not bytes or not 0 < len(body) <= _MAX:
        fail()
    parent = decode(body)
    _legacy_record(parent, installation)
    record(child, installation)
    if (parent['mode'] != 'unmanaged' or parent['managedEver']
            or child['schema'] != SCHEMA or child['mode'] != 'managed'
            or child['previousSha256'] != digest(body) or child['generation'] != parent['generation'] + 1
            or child['current']['storage']['parentFloorSha256'] != digest(body)
            or child['writerProtocol'] < parent['writerProtocol']
            or child['minimum']['hostBroker']['version'] < parent['writerProtocol']
            or any(child['minimum'][name]['version'] < 1 for name in CONTRACTS)
            or _version_order(child['sentinelVersion']) < _version_order(parent['sentinelVersion'])):
        fail()
    return parent


@dataclass(frozen=True)
class FloorReport:
    classification: str
    reasons: tuple
    history_sha256: str | None = None
    generation: int | None = None


@dataclass(frozen=True)
class BindingComparison:
    """Differences only. Even an empty tuple is not a start/writer grant."""
    differences: tuple


class _InstallationDirectory:
    """Installation data may be user-owned; pin it, do not bless it as Root data."""
    def __init__(self, path):
        self.path, self.fd = Path(path), None
        try:
            if not self.path.is_absolute() or str(self.path) != os.path.realpath(self.path):
                fail()
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.identity, self.mount = directory_seal(os.fstat(self.fd)), mount_id(self.fd)
            self.verify()
        except BaseException:
            self.close()
            raise

    def verify(self):
        if self.fd is None or str(self.path) != os.path.realpath(self.path):
            fail()
        fresh = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if (directory_seal(os.fstat(fresh)) != self.identity
                    or directory_seal(os.fstat(self.fd)) != self.identity
                    or mount_id(fresh) != self.mount or mount_id(self.fd) != self.mount):
                fail()
        finally:
            os.close(fresh)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _EnvironmentDirectory(PrivateDirectory):
    """Protected Root parent may be 0755; its environment file remains 0600."""
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
            if os.fstat(self.fd).st_uid != sessions._OWNER_UID:
                fail()
            self.verify()
        except BaseException:
            self.close()
            raise


class FloorSnapshot:
    """Opaque, process-local, lifetime-bound observation; no serialized capability."""
    def __init__(self, issuer, reader, report, value, checks, directories, history_body):
        if issuer is not _ISSUER:
            fail()
        self._reader, self._value, self._checks = reader, value, checks
        self._directories, self._history_body = directories, history_body
        self._report, self._pid, self._closed = report, os.getpid(), False

    @property
    def report(self):
        self.recheck()
        return self._report

    def recheck(self):
        if self._closed or self._pid != os.getpid():
            fail()
        try:
            for check in self._checks:
                check()
        except Exception:
            fail()

    def compare_candidate(self, *, minimum, current):
        self.recheck()
        if self._value is None or self._report.classification != 'record-consistent':
            return BindingComparison(('history-held',))
        contracts(minimum)
        current_binding(current)
        differences = []
        for name, (_, supported) in CONTRACTS.items():
            version = minimum[name]['version']
            if version < self._value['minimum'][name]['version']:
                differences.append('minimum.' + name + '.below-floor')
            if version > supported:
                differences.append('minimum.' + name + '.unsupported')
        for name in self._value['current']:
            if current[name] != self._value['current'][name]:
                differences.append('current.' + name + '.changed')
        self.recheck()
        return BindingComparison(tuple(differences))


@dataclass(frozen=True)
class StorageUpgrade:
    """Exact migration inputs; possession of these bytes cannot admit a writer."""
    plan: bytes
    predecessor: bytes
    bridge: bytes
    history: bytes


@contextmanager
def prepare_storage_upgrade(snapshot, *, publication_operation, creation_transition=None):
    """Build an exact v3 successor while the old floor and publisher stay held.

    Only the retained Root admission transaction may commit a reviewed plan.
    This function creates no files and cannot re-anchor an unreadable v2 floor.
    """
    from .host_source_publication import read_completed

    if type(snapshot) is not FloorSnapshot or snapshot.report.classification != 'record-consistent':
        fail()
    before = snapshot._value
    if (before is None or before['schema'] != LEGACY_SCHEMA or not snapshot._directories
            or not hash_value(publication_operation)):
        fail()
    previous = snapshot.report.history_sha256
    with read_completed(publication_operation, floor_snapshot=snapshot) as issuer, ExitStack() as stack:
        checks = [snapshot.recheck, issuer.recheck]
        reader = snapshot._reader
        role_pins = snapshot._directories
        root_copy = issuer.observation['copy']['installationRoot']
        if root_copy != list(role_pins['installation'].identity):
            fail()
        unit_digest = before['current']['sentinel']['unitSha256']
        _pin_recovery_unit(stack, checks, unit_digest)
        roles = {name: storage.observe(role_pins[name]) for name in storage.ROLES}
        for name, role in roles.items():
            checks.append(lambda name=name, role=role: storage.verify_role(name, role_pins[name], role))
        bridge = {'schema': storage.BRIDGE_SCHEMA, 'installationId': before['installationId'],
                  'context': reader.context, 'daemon': reader.daemon_id, 'parentFloorSha256': previous,
                  'publicationOperation': publication_operation, 'publicationSha256': issuer.receipt_sha256,
                  'recoveryUnitSha256': unit_digest, 'roles': roles}
        storage.validate_bridge(bridge, installation=before['installationId'], context=reader.context,
                                daemon=reader.daemon_id, previous=previous)
        for check in checks:
            check()
        yield _storage_upgrade(snapshot._history_body, bridge, creation_transition)
        for check in checks:
            check()


def _storage_upgrade(predecessor, bridge, creation_transition):
    before, body = decode(predecessor), encoded(bridge)
    previous = digest(predecessor)
    if creation_transition is not None:
        exact(creation_transition, ('fromPolicy', 'toPolicy', 'beforeSha256', 'afterSha256'))
        if (creation_transition['fromPolicy'] != 'unless-stopped' or creation_transition['toPolicy'] not in ('', 'no')
                or creation_transition['beforeSha256'] != before['current']['main']['creationSha256']
                or not hash_value(creation_transition['afterSha256'])
                or creation_transition['beforeSha256'] == creation_transition['afterSha256']):
            fail()
    plan = encoded({'schema': 'orbis.credential-storage-upgrade-plan.v1',
                    'installationId': before['installationId'], 'generation': before['generation'] + 1,
                    'previousFloorSha256': previous, 'bridgeSha256': digest(body),
                    'publisherReceiptSha256': bridge['publicationSha256'],
                    'mainCreationTransition': creation_transition})
    successor = deepcopy(before)
    successor.update(schema=SCHEMA, generation=before['generation'] + 1,
                     previousSha256=previous, planSha256=digest(plan))
    successor['minimum']['reader']['version'] = 3
    if creation_transition is not None:
        successor['current']['main']['creationSha256'] = creation_transition['afterSha256']
    successor['current']['storage'] = {'bridgeSha256': digest(body), 'parentFloorSha256': previous,
                                       'journalSchema': before['current']['storage']['journalSchema']}
    record(successor, before['installationId'])
    return StorageUpgrade(plan, predecessor, body, encoded(successor))


class CredentialFloorReader:
    def __init__(self, installation_root, context, daemon_id, *, host_state_directory):
        # These are trusted local observations supplied by the retained Root
        # caller, not a Main request or a caller-provided qualification Boolean.
        self.root, self.host_state = Path(installation_root), Path(host_state_directory)
        if (os.geteuid() != sessions._OWNER_UID
                or type(context) is not str or not 0 < len(context) <= 128 or '\0' in context
                or type(daemon_id) is not str or not 0 < len(daemon_id) <= 256 or '\0' in daemon_id):
            fail()
        self.context, self.daemon_id = context, daemon_id

    def snapshot(self):
        """A full Root read requires the visible, held installation directory."""
        return self._snapshot(recovery=False)

    def recovery_snapshot(self):
        """Observe the fixed recovery unit's storage without accessing Main."""
        return self._snapshot(recovery=True)

    @contextmanager
    def _snapshot(self, *, recovery):
        checks, value, directories, history_body = [], None, None, None
        with ExitStack() as stack:
            try:
                installation, identity = None, None
                if recovery:
                    def service_view():
                        if not storage.in_recovery_unit():
                            fail()
                    service_view()
                    checks.append(service_view)
                else:
                    installation = _InstallationDirectory(self.root)
                    stack.callback(installation.close)
                    checks.append(installation.verify)
                    identity = digest(encoded({'root': str(self.root), 'context': self.context,
                        'daemon': self.daemon_id, 'rootIdentity': installation.identity}))
                namespace_path = STATE_ROOT / 'installations' / digest(os.fsencode(str(self.root)))
                if namespace_path.is_relative_to(self.root) or self.root.is_relative_to(namespace_path):
                    fail()
                namespace = stack.enter_context(PrivateDirectory(namespace_path))
                checks.append(namespace.verify)
                history_path = namespace_path / HISTORY
                if not os.path.lexists(history_path):
                    def absent():
                        if os.path.lexists(history_path):
                            fail()
                    checks.append(absent)
                    anchors = self._anchors(namespace_path)
                    classification = 'unknown' if anchors or recovery else 'legacy-unadmitted'
                    report = FloorReport(classification, ('history-missing-with-anchor' if anchors else 'history-absent-no-admission',))
                    # Absence observations must also remain absent/present exactly.
                    checks.append(lambda: self._same_anchors(namespace_path, anchors))
                else:
                    history = stack.enter_context(PrivateFile(namespace, HISTORY, _MAX))
                    _remember_file(checks, history)
                    history_body = history.body
                    raw = decode(history_body)
                    schema = raw.get('schema')
                    if schema == SCHEMA:
                        # The Root bridge verifies this issued identifier. Never
                        # re-derive it from the post-boot kernel device number.
                        identity = raw.get('installationId')
                    elif recovery or self._storage_started(namespace_path):
                        raise _StorageUpgradeRequired()
                    else:
                        # A staged/retained bridge prevents a restored legacy
                        # pointer from granting even a stable-record comparison.
                        def bridge_absent():
                            if self._storage_started(namespace_path):
                                fail()
                        checks.append(bridge_absent)
                    if schema == 'orbis.recovery-admission-history.v1':
                        _legacy(raw, identity)
                    else:
                        record(raw, identity)
                        publication = self._lineage(stack, checks, namespace_path, raw, identity, history_body=history.body)
                        value = raw
                        unsupported = tuple('minimum.' + name + '.unsupported' for name, (_, maximum) in CONTRACTS.items()
                            if raw['minimum'][name]['version'] > maximum)
                        if unsupported:
                            report = FloorReport('unknown', unsupported, digest(history.body), raw['generation'])
                        elif raw['mode'] == 'initializing-never-managed':
                            # Positive initialization scope is retained for a future
                            # startup consumer, never ordinary unmanaged permission.
                            anchors = self._anchors(namespace_path)
                            checks.append(lambda: self._same_anchors(namespace_path, anchors))
                            report = FloorReport('unknown' if anchors else 'held-transition',
                                ('initialization-crossed-anchor' if anchors else 'positive-initialization-recorded',),
                                digest(history.body), raw['generation'])
                        else:
                            directories = self._protected(stack, checks, namespace, raw, installation, recovery=recovery,
                                                          publication=publication)
                            pending = self._pending(namespace_path)
                            checks.append(lambda: self._same_pending(namespace_path, pending))
                            stable = 'recovery-storage-consistent' if recovery else 'record-consistent'
                            reason = 'main-installation-and-live-state-unverified' if recovery else 'publisher-runtime-and-live-state-unverified'
                            report = FloorReport('held-transition' if pending else stable,
                                ('pending-transition' if pending else reason,),
                                digest(history.body), raw['generation'])
            except _StorageUpgradeRequired:
                report, value = FloorReport('held-transition', ('history-stable-storage-upgrade-required',)), None
            except _LegacyUpgrade:
                report, value = FloorReport('held-transition', ('history-v1-upgrade-required',)), None
            except storage.UnsupportedCredentialStorage:
                report, value = FloorReport('held-transition', ('unsupported-credential-storage',)), None
            except Exception:
                report, value = FloorReport('unknown', ('protected-floor-unreadable-or-inconsistent',)), None
            result = FloorSnapshot(_ISSUER, self, report, value, checks, directories, history_body)
            try:
                yield result
                result.recheck()
            finally:
                result._closed = True

    def _lineage(self, stack, checks, namespace, newest, identity, *, history_body=None):
        child, seen = newest, set()
        child_body = encoded(newest) if history_body is None else history_body
        directory = None
        for _ in range(128):
            previous = child['previousSha256']
            if previous is None:
                return
            if previous in seen:
                fail()
            seen.add(previous)
            if directory is None:
                directory = stack.enter_context(PrivateDirectory(namespace / ARCHIVE))
                checks.append(directory.verify)
            source = stack.enter_context(PrivateFile(directory, previous + '.json', _MAX))
            _remember_file(checks, source)
            if digest(source.body) != previous:
                fail()
            parent = decode(source.body)
            # Only the exact first V3 child may adopt a never-managed V1 parent,
            # and only with the same operation's positive published proof.
            if parent.get('schema') == 'orbis.recovery-admission-history.v1':
                _legacy_record(parent, identity)
                if parent['mode'] != 'unmanaged' or parent['managedEver']:
                    _legacy(parent, identity)
                _bootstrap_parent(source.body, child, identity)
                from .bootstrap_publication import PublishedWitness, read_published
                try:
                    published = stack.enter_context(read_published(
                        namespace, recovery_directory=RECOVERY_ROOT, root=self.root, context=self.context,
                        daemon=self.daemon_id, history_body=child_body))
                except FileNotFoundError:
                    raise _LegacyUpgrade() from None
                if type(published) is not PublishedWitness or published.host_generation != child['generation']:
                    fail()
                checks.append(published.recheck)
                published.recheck()
                return published
            record(parent, identity)
            if child['schema'] == SCHEMA:
                if parent['schema'] == LEGACY_SCHEMA:
                    if child['current']['storage']['parentFloorSha256'] != previous:
                        fail()
                elif child['current']['storage'] != parent['current']['storage']:
                    fail()
            elif parent['schema'] == SCHEMA:
                fail()
            if (parent['generation'] + 1 != child['generation']
                    or parent['managedEver'] and not child['managedEver']
                    or _version_order(child['sentinelVersion']) < _version_order(parent['sentinelVersion'])
                    or any(child['minimum'][name]['version'] < parent['minimum'][name]['version'] for name in CONTRACTS)):
                fail()
            child = parent
            child_body = source.body
        fail()

    def _protected(self, stack, checks, namespace, value, installation, *, recovery, bridge_body=None, publication=None):
        current = value['current']
        directories = {'namespace': namespace,
            'journal': stack.enter_context(PrivateDirectory(namespace.path / 'credential-journal')),
            'recovery': stack.enter_context(PrivateDirectory(RECOVERY_ROOT))}
        for directory in directories.values():
            checks.append(directory.verify)
        if value['schema'] == SCHEMA:
            self._stable_storage(stack, checks, directories, value, installation, recovery=recovery,
                                 bridge_body=bridge_body, publication=publication)
        else:
            for name, directory in directories.items():
                expected = current['storage'][name]
                if expected != {'identity': list(directory_seal(os.fstat(directory.fd))), 'mountId': mount_id(directory.fd)}:
                    fail()
        host = stack.enter_context(PrivateDirectory(self.host_state))
        environment = stack.enter_context(_EnvironmentDirectory(RECOVERY_ENV.parent))
        checks.extend((host.verify, environment.verify))
        files = {}
        for name, directory, filename in (('hostAdmissionSha256', host, 'credential-admission.json'),
                ('recoveryConfigSha256', directories['recovery'], 'config.json'),
                ('recoveryEnvironmentSha256', environment, RECOVERY_ENV.name)):
            source = stack.enter_context(PrivateFile(directory, filename, 16384))
            _remember_file(checks, source)
            if digest(source.body) != current['configuration'][name]:
                fail()
            files[name] = source
        admission = decode(files['hostAdmissionSha256'].body)
        recovery = decode(files['recoveryConfigSha256'].body)
        RecoveryConfig._validate(recovery)
        exact(admission, ('schema', 'writerProtocol', 'root', 'context', 'installationId', 'mode', 'origin',
                          'recoveryEpoch', 'runtimeDirectory', 'runtimeFiles', 'journalDirectory',
                          'recoveryConfig', 'recoveryConfigSha256'))
        runtime_files = ('__init__.py', 'writer_broker.py', 'writer_control.py', 'writer_journal.py',
                         'recovery_sessions.py', 'recovery_config.py')
        _hashes(admission['runtimeFiles'], runtime_files)
        runtime = admission['runtimeDirectory']
        if (type(runtime) is not str or not Path(runtime).is_absolute() or runtime != os.path.realpath(runtime)
                or Path(runtime).is_relative_to(self.root) or self.root.is_relative_to(Path(runtime))
                or not hash_value(admission['recoveryEpoch']) or not integer(admission['writerProtocol'], 1)
                or admission['writerProtocol'] != value['writerProtocol']):
            fail()
        if (admission.get('schema') != 'orbis.host.credential-admission.v1'
                or admission.get('installationId') != value['installationId'] or admission.get('mode') != 'managed'
                or admission.get('root') != str(self.root) or admission.get('context') != self.context
                or admission.get('origin') != current['recoveryOrigin']
                or admission.get('recoveryConfig') != str(RECOVERY_ROOT / 'config.json')
                or admission.get('recoveryConfigSha256') != current['configuration']['recoveryConfigSha256']
                or admission.get('journalDirectory') != str(namespace.path / 'credential-journal')
                or recovery.get('schema') != 'orbis.sentinel-recovery-config.v1'
                or recovery.get('directory') != str(RECOVERY_ROOT)
                or recovery.get('origin') != current['recoveryOrigin']
                or recovery.get('imageId') != current['main']['imageId']):
            fail()
        return {**directories, 'installation': installation}

    def _stable_storage(self, stack, checks, directories, value, installation, *, recovery, bridge_body=None, publication=None):
        binding = value['current']['storage']
        if bridge_body is None:
            history = stack.enter_context(PrivateDirectory(directories['namespace'].path / storage.BRIDGE_DIRECTORY))
            checks.append(history.verify)
            source = stack.enter_context(PrivateFile(history, binding['bridgeSha256'] + '.json', _MAX))
            _remember_file(checks, source)
            bridge_body = source.body
        if digest(bridge_body) != binding['bridgeSha256']:
            fail()
        bridge = decode(bridge_body)
        validate = storage.validate_bridge if publication is None else storage.validate_bootstrap_bridge
        validate(bridge, installation=value['installationId'], context=self.context,
                 daemon=self.daemon_id, previous=binding['parentFloorSha256'])
        if (bridge['roles']['installation']['path'] != str(self.root)
                or bridge['recoveryUnitSha256'] != value['current']['sentinel']['unitSha256']):
            fail()
        _pin_recovery_unit(stack, checks, bridge['recoveryUnitSha256'])
        roles = dict(directories)
        if not recovery:
            roles['installation'] = installation
        for name, directory in roles.items():
            def qualified(name=name, directory=directory):
                storage.verify_role(name, directory, bridge['roles'][name], recovery=recovery)
            qualified()
            checks.append(qualified)

    @contextmanager
    def verify_storage_upgrade(self, upgrade, *, publication_operation):
        """Revalidate an exact Root-approved transition independently of its crash phase.

        This verifier is intentionally distinct from normal floor/start admission.
        """
        from .host_source_publication import read_completed_for_storage_upgrade

        if type(upgrade) is not StorageUpgrade or any(
                type(body) is not bytes or not 0 < len(body) <= _MAX
                for body in (upgrade.plan, upgrade.predecessor, upgrade.bridge, upgrade.history)):
            fail()
        before, bridge, after = map(decode, (upgrade.predecessor, upgrade.bridge, upgrade.history))
        identity, prior_sha = before['installationId'], digest(upgrade.predecessor)
        record(before, identity)
        if (before['schema'] != LEGACY_SCHEMA or before['mode'] != 'managed'
                or any(before['minimum'][name]['version'] > maximum for name, (_, maximum) in CONTRACTS.items())
                or upgrade != _storage_upgrade(upgrade.predecessor, bridge, decode(upgrade.plan)['mainCreationTransition'])):
            fail()
        storage.validate_bridge(bridge, installation=identity, context=self.context, daemon=self.daemon_id,
                                previous=prior_sha)
        if bridge['publicationOperation'] != publication_operation:
            fail()
        with ExitStack() as stack:
            installation = _InstallationDirectory(self.root)
            stack.callback(installation.close)
            namespace_path = STATE_ROOT / 'installations' / digest(os.fsencode(str(self.root)))
            if namespace_path.is_relative_to(self.root) or self.root.is_relative_to(namespace_path):
                fail()
            namespace = stack.enter_context(PrivateDirectory(namespace_path))
            checks = [namespace.verify, installation.verify]
            self._lineage(stack, checks, namespace_path, before, identity, history_body=upgrade.predecessor)
            self._protected(stack, checks, namespace, after, installation, recovery=False, bridge_body=upgrade.bridge)
            issuer = stack.enter_context(read_completed_for_storage_upgrade(
                publication_operation, root=self.root, context=self.context, current=before['current'],
                root_identity=installation.identity, receipt_sha256=bridge['publicationSha256']))
            checks.append(issuer.recheck)

            def actual_history():
                with ExitStack() as current_stack:
                    current = current_stack.enter_context(PrivateFile(namespace, HISTORY, _MAX))
                    if current.body not in (upgrade.predecessor, upgrade.history):
                        fail()
                    live = []
                    _remember_file(live, current)
                    if current.body == upgrade.history:
                        for folder, body in ((ARCHIVE, upgrade.predecessor),
                                             (storage.BRIDGE_DIRECTORY, upgrade.bridge)):
                            directory = current_stack.enter_context(PrivateDirectory(namespace_path / folder))
                            retained = current_stack.enter_context(PrivateFile(directory, digest(body) + '.json', _MAX))
                            if retained.body != body:
                                fail()
                            _remember_file(live, retained)
                    for check in live:
                        check()

            checks.append(actual_history)

            def recheck():
                for check in checks:
                    check()

            recheck()
            yield recheck
            recheck()

    @staticmethod
    def _storage_started(namespace):
        return any(os.path.lexists(namespace / name) for name in (
            storage.BRIDGE_DIRECTORY, 'credential-storage-migration.json',
            '.credential-storage-migration.json.pending', 'credential-storage-migration-complete.json'))

    def _anchors(self, namespace):
        paths = (RECOVERY_ROOT / 'config.json', RECOVERY_ROOT / 'recovery.sqlite3', RECOVERY_ENV,
                 RECOVERY_ROOT / 'bootstrap', RECOVERY_ROOT / 'profiles',
                 self.host_state / 'credential-admission.json', namespace / 'credential-journal',
                 namespace / ARCHIVE, namespace / storage.BRIDGE_DIRECTORY, namespace / 'credential-storage-migration-complete.json',
                 namespace / 'bootstrap-sources',
                 *(namespace / name for name in self._pending(namespace)))
        return tuple(str(path) for path in paths if os.path.lexists(path))

    def _same_anchors(self, namespace, expected):
        if self._anchors(namespace) != expected:
            fail()

    def _pending(self, namespace):
        # Presence alone holds. This reader never interprets an arbitrary JSON
        # operation as a live lock or as permission to reconcile it.
        names = ('recovery-admission-intent.json', 'credential-bootstrap-intent.json', 'credential-fence.json',
                 'credential-bootstrap-publication-hold.json',
                 '.credential-bootstrap-publication-hold.json.pending',
                 'credential-storage-migration.json', '.credential-storage-migration.json.pending')
        return tuple(name for name in names if os.path.lexists(namespace / name))

    def _same_pending(self, namespace, expected):
        if self._pending(namespace) != expected:
            fail()
