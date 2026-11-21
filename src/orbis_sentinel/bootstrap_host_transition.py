"""Retained Root writer for one private existing-V1 bootstrap transition."""
from contextlib import ExitStack, contextmanager
import fcntl
import os
from pathlib import Path
import stat
import time

from . import credential_floor as floor
from . import credential_storage as storage
from . import recovery_sessions as sessions
from .bootstrap_control import RootBootstrapControlClient
from .bootstrap_source import (
    ACTIVATION_BRIDGE, ACTIVATION_COMPLETE, ACTIVATION_PACKET, ACTIVATION_PROGRESS, CONFIG_ARCHIVE,
    PrivateDirectory, PrivateFile, RootFileSourceWitness, activation_completion, activation_intent, activation_progress,
    activation_packet, decode, digest, encoded, fail, hash_value, host_commit_view, review_documents,
    v1_contract_minima,
)
from .bootstrap_supervisor import PublishedBootstrapSupervisor
from .collector_execution import CollectorExecutionInventory, HOST_SOURCE, HOST_STATE, SNAPSHOTS, _ByteModules
from .host_source_publication import read_completed_for_bootstrap_review
from .recovery_worker import _Docker
from .recovery_worker_provision import require_retained_worker
from .writer_journal import seal, mount_id

INTENT = 'credential-bootstrap-intent.json'
CONFIG = 'credential-admission.json'


def _file(directory, name, maximum, *, optional=False):
    try:
        with PrivateFile(directory, name, maximum) as opened:
            if mount_id(opened.fd) != mount_id(directory.fd):
                fail()
            return opened.body
    except FileNotFoundError:
        if not optional:
            raise
        return None


class HostActivation:
    def __init__(self, verify_package):
        self.verify_package = verify_package
        self.client = RootBootstrapControlClient(str(floor.RECOVERY_ROOT / 'bootstrap-control.sock'))

    @staticmethod
    def _qualified_worker(namespace, review, docker, product, runtime_modules):
        worker = require_retained_worker(namespace, review, docker)
        capability_client = runtime_modules['writer_control'].WriterControlClient(str(floor.RECOVERY_ROOT / 'control.sock'), timeout=45)
        capability = product._capability(capability_client.call('operator-capability', {}))
        if worker['capabilitiesSha256'] != digest(encoded(capability)):
            fail()
        return worker

    @contextmanager
    def _scope(self, operation, review_sha, plan_sha):
        if not all(hash_value(item) for item in (operation, review_sha, plan_sha)):
            fail()
        with ExitStack() as resources:
            directory = resources.enter_context(PrivateDirectory(floor.RECOVERY_ROOT / 'bootstrap' / operation))
            fd = os.open('held-coordinator.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory.fd)
            resources.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size or mount_id(fd) != mount_id(directory.fd)):
                fail()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            review, verify_review = resources.enter_context(review_documents(directory, operation, review_sha))
            plan, verify_plan = resources.enter_context(RootFileSourceWitness.plan_documents(directory, operation, plan_sha))
            RootFileSourceWitness.check_review_plan(plan, review)
            if plan['reviewSha256'] != review_sha:
                fail()
            root = floor._InstallationDirectory(Path(review['root']))
            resources.callback(root.close)
            binding = {'root': review['root'], 'context': review['context'], 'daemon': review['daemon'],
                       'rootIdentity': root.identity}
            if digest(encoded(binding)) != review['installationId']:
                fail()
            host = {key: review['host'][key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')}
            publication = review['publisher']
            evidence = resources.enter_context(read_completed_for_bootstrap_review(publication['operationId'],
                root=root.path, context=review['context'], current={'main': review['main'], 'host': host},
                root_identity=root.identity, receipt_sha256=publication['receiptSha256']))
            inventory = resources.enter_context(CollectorExecutionInventory.open_installed(evidence.observation['copy']['inventory']))
            if (inventory.inventory_sha256 != review['collector']['inventorySha256']
                    or digest(inventory.bodies['orbis-host-recovery-source.py']) != review['collector']['programSha256']):
                fail()
            modules = _ByteModules(inventory)
            host_module = modules.load('orbis-host-service.py', '_bootstrap_writer_host')
            admission_module = modules.load('orbis-host-recovery-admission.py', '_bootstrap_writer_admission')
            source_module = modules.load('orbis-host-recovery-source.py', '_bootstrap_writer_source')
            service = host_module.HostService(root.path, review['context'], SNAPSHOTS, HOST_STATE, recover_interrupted_job=False)
            admission = admission_module.Admission(service)
            if service.state_dir != admission.layout.STATE_ROOT or service.state_dir != HOST_STATE:
                fail()
            journal_namespace = admission.layout.namespace(root.path)
            if journal_namespace != Path(review['captureRoot']).parent:
                fail()

            def verify():
                for check in (self.verify_package, root.verify, verify_plan, verify_review, inventory.verify, evidence.recheck):
                    check()
                if seal(os.fstat(fd)) != seal(info) or seal(os.stat('held-coordinator.lock', dir_fd=directory.fd,
                                                                    follow_symlinks=False)) != seal(info):
                    fail()

            verify()
            yield directory, review, plan, admission, admission_module, source_module, root, verify
            verify()

    @contextmanager
    def _observed(self, review, admission, product, root, guard, verify_scope):
        from .recovery_listener_install import read_setup_receipt

        with ExitStack() as resources:
            supervisor = admission.supervisor
            service, origin = admission.service, review['origin']
            runtime, runtime_modules, verify_runtime = resources.enter_context(supervisor._held_runtime(storage_floor=True))
            recovery, verify_recovery = resources.enter_context(
                supervisor.bootstrap_recovery(origin, review['main'], runtime, runtime_modules))
            if runtime != review['runtime'] or recovery != review['recovery']:
                fail()
            namespace = resources.enter_context(PrivateDirectory(Path(review['captureRoot']).parent))
            host = resources.enter_context(PrivateDirectory(service.state_dir))
            roles = {'installation': root, 'namespace': namespace,
                     'journal': resources.enter_context(PrivateDirectory(namespace.path / 'credential-journal')),
                     'recovery': resources.enter_context(PrivateDirectory(floor.RECOVERY_ROOT))}
            docker = _Docker(str(HOST_SOURCE))
            worker = self._qualified_worker(namespace, review, docker, product, runtime_modules)
            listener = read_setup_receipt(floor.RECOVERY_ROOT, review)

            def verify():
                if read_setup_receipt(floor.RECOVERY_ROOT, review) != listener:
                    fail()
                verify_scope()
                verify_runtime()
                verify_recovery()
                namespace.verify()
                host.verify()
                service.require_credential_idle(guard)
                guard.check(review['operationId'], digest(encoded(review)))
                installation, main, daemon = supervisor._main(origin, storage_transition=True)
                if ((installation, main, daemon) != (review['installationId'], review['main'], review['daemon'])
                        or digest(encoded(admission.layout.read(root.path, daemon, review['context']))) != review['layoutSha256']
                        or require_retained_worker(namespace, review, docker) != worker):
                    fail()
                stopped = supervisor._host_stopped()
                copy = stopped['custody']
                if review['host'] != {'inventorySha256': digest(encoded(copy['sourceFiles'])), 'unitSha256': copy['unitSha256'],
                                      'environmentSha256': copy['environmentSha256'], 'effectiveSha256': stopped['systemdSha256']}:
                    fail()
                if admission._journal({'namespace': str(namespace.path)}, runtime_modules, history=review) != review['journal']:
                    fail()
                for name, role in roles.items():
                    storage.verify_role(name, role, review['storage'][name])

            verify()
            yield namespace, host, worker, verify
            verify()

    @staticmethod
    def _previous(namespace, host, review, admission):
        prior = _file(namespace, floor.HISTORY, 16384)
        config = _file(host, CONFIG, 16384)
        admission._bootstrap_predecessor(namespace, prior, config, review['installationId'], review['origin'], review['runtime'])
        v1_contract_minima(review, prior, config)
        return prior, config

    @staticmethod
    def _write(product, admission, directory, name, body, previous):
        product._write_storage(admission.authority, directory.fd, name, body, previous=previous)
        if _file(directory, name, 65536) != body:
            fail()

    @staticmethod
    def _candidate(review, plan_sha, prior, config, request, projection, worker, exporter):
        if (set(projection) != {'stage', 'key', 'projectedCommitSha256', 'exporterCapabilitySha256'}
                or projection['exporterCapabilitySha256'] != exporter):
            fail()
        available = {name: {'family': family, 'version': supported} for name, (family, supported) in floor.CONTRACTS.items()}
        for name, inherited in v1_contract_minima(review, prior, config).items():
            if available[name]['version'] < inherited:
                fail()
        packet = {'schema': ACTIVATION_PACKET,
                  **{key: review[key] for key in ('operationId', 'installationId', 'root', 'context', 'daemon', 'origin')},
                  'reviewSha256': digest(encoded(review)), 'planSha256': plan_sha, 'publication': review['publisher'],
                  'prior': {'historySha256': digest(prior), 'configSha256': digest(config), 'generation': review['previousGeneration']},
                  'stage': projection['stage'], 'key': projection['key'], 'activationRequestId': request}
        runtime, recovery = review['runtime'], review['recovery']
        epoch_scope = {key: packet[key] for key in ('operationId', 'reviewSha256', 'prior', 'publication')}
        successor_config = {'schema': 'orbis.host.credential-admission.v1', 'mode': 'managed',
                            **{key: review[key] for key in ('installationId', 'root', 'context', 'origin')},
                            'writerProtocol': available['hostBroker']['version'], 'recoveryEpoch': digest(encoded(epoch_scope)),
                            'runtimeDirectory': runtime['runtimeDirectory'], 'runtimeFiles': runtime['runtimeFiles'],
                            'journalDirectory': str(Path(review['captureRoot']).parent / 'credential-journal'),
                            'recoveryConfig': str(floor.RECOVERY_ROOT / 'config.json'),
                            'recoveryConfigSha256': recovery['configSha256']}
        bridge = {'schema': ACTIVATION_BRIDGE, **{key: review[key] for key in ('installationId', 'context', 'daemon')},
                  'parentFloorSha256': digest(prior), 'publicationOperation': review['publisher']['operationId'],
                  'publicationSha256': review['publisher']['receiptSha256'], 'recoveryUnitSha256': recovery['unitSha256'],
                  'roles': review['storage']}
        config_body, bridge_body = encoded(successor_config), encoded(bridge)
        configuration = {'hostAdmissionSha256': digest(config_body), 'recoveryConfigSha256': recovery['configSha256'],
                         'recoveryEnvironmentSha256': recovery['environmentSha256']}
        history = {'schema': floor.SCHEMA, 'mode': 'managed', 'managedEver': True, 'previousSha256': digest(prior),
                   'installationId': review['installationId'], 'generation': review['previousGeneration'] + 1,
                   'configSha256': digest(config_body), 'planSha256': plan_sha, 'sentinelVersion': runtime['version'],
                   'writerProtocol': available['hostBroker']['version'], 'minimum': available, 'positiveNeverManaged': None,
                   'current': {'main': {'imageId': review['main']['imageId'], 'creationSha256': review['main']['definitionSha256'],
                                        'publicationSha256': review['main']['publicationSha256']},
                        'host': {key: review['host'][key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')},
                        'sentinel': {'version': runtime['version'], 'inventorySha256': runtime['inventorySha256'],
                                     'runtimeSha256': digest(encoded(runtime['runtimeFiles'])), 'unitSha256': recovery['unitSha256'],
                                     'environmentSha256': recovery['environmentSha256']},
                        'authWorker': worker, 'sourceExporter': {'imageId': review['collector']['imageId'],
                            'programSha256': review['collector']['programSha256'], 'capabilitiesSha256': exporter},
                        'recoveryOrigin': review['origin'], 'configuration': configuration,
                        'storage': {'bridgeSha256': digest(bridge_body), 'parentFloorSha256': digest(prior),
                                    'journalSchema': 'orbis.sentinel-writer-journal.v1'},
                        'receipts': {'bootstrapSha256': projection['stage']['terminalReceiptSha256'],
                                     'sourceSha256': projection['stage']['sourceSha256'],
                                     'activationSha256': projection['projectedCommitSha256']}}}
        floor.record(history, review['installationId'])
        history_body = encoded(history)
        packet['candidate'] = {'configSha256': digest(config_body), 'historySha256': digest(history_body),
                               'bridgeSha256': digest(bridge_body), 'projectedCommitSha256': projection['projectedCommitSha256']}
        return {'activation-config.json': config_body, 'activation-history.json': history_body,
                'activation-bridge.json': bridge_body, 'activation-packet.json': encoded(packet)}

    @contextmanager
    def _guarded(self, operation, review_sha, plan_sha):
        with self._scope(operation, review_sha, plan_sha) as (directory, review, plan, admission, product, source, root, verify_scope):
            service = admission.service
            with admission.host.credential_fence_lock(service.root, service.context) as guard:
                guard.check(operation, review_sha)
                with self._observed(review, admission, product, root, guard, verify_scope) as (namespace, host, worker, verify):
                    yield directory, review, plan, admission, product, source, namespace, host, worker, verify

    def prepare(self, operation, review_sha, plan_sha, *, request):
        if not hash_value(request):
            fail()
        with self._guarded(operation, review_sha, plan_sha) as (directory, review, _, admission, product, source, namespace, host, worker, verify):
            prior, config = self._previous(namespace, host, review, admission)
            self._quiet(namespace, allow_bootstrap=False)
            if (os.path.lexists(directory.path / 'activation-approval.json')
                    and not os.path.lexists(directory.path / 'activation-packet.json')):
                fail()
            projection = self.client.call('bootstrap-held-activation-projection',
                {'operationId': operation, 'planSha256': plan_sha, 'requestId': request})
            files = self._candidate(review, plan_sha, prior, config, request, projection, worker, digest(encoded(source.CAPABILITY)))
            for name, body in files.items():
                verify()
                actual = _file(directory, name, 65536, optional=True)
                if actual is None:
                    self._write(product, admission, directory, name, body, None)
                elif actual != body:
                    fail()
            return {'phase': 'activation-awaits-approval', 'operationId': operation,
                    'packetSha256': digest(files['activation-packet.json']), 'requestId': request}

    @staticmethod
    def _quiet(namespace, *, allow_bootstrap):
        foreign = ('recovery-admission-intent.json', '.recovery-admission-intent.json.pending',
                   'credential-storage-migration.json', '.credential-storage-migration.json.pending',
                   'credential-storage-migration-complete.json')
        if not allow_bootstrap:
            foreign += (INTENT, '.' + INTENT + '.pending', ACTIVATION_PROGRESS, '.' + ACTIVATION_PROGRESS + '.pending',
                        ACTIVATION_COMPLETE, '.' + ACTIVATION_COMPLETE + '.pending')
        if any(os.path.lexists(namespace.path / name) for name in foreign):
            fail()

    def arm(self, operation, review_sha, plan_sha, *, packet_sha, approval_sha):
        with self._guarded(operation, review_sha, plan_sha) as (directory, review, plan, admission, product, _, namespace, host, worker, verify):
            self._previous(namespace, host, review, admission)
            self._quiet(namespace, allow_bootstrap=True)
            if any(os.path.lexists(namespace.path / name) for name in (ACTIVATION_PROGRESS, ACTIVATION_COMPLETE)):
                fail()
            with activation_packet(directory, plan, review, packet_sha) as (packet, approval, verify_packet):
                if approval != approval_sha:
                    fail()
                self._candidate_worker(directory, packet, worker)
                request_id = packet['activationRequestId']
                args = {'operationId': operation, 'planSha256': plan_sha, 'packetSha256': packet_sha, 'requestId': request_id}
                challenge = self.client.call('bootstrap-held-activation-challenge', args)
                if set(challenge) != {'collectionNonce', 'issuedAtMs', 'expiresAtMs'}:
                    fail()
                nonce = challenge['collectionNonce']
                sessions._token(nonce)
                issued, expires = challenge['issuedAtMs'], challenge['expiresAtMs']
                if not sessions._integer(issued, 1) or type(expires) is not int or expires != issued + 120000:
                    fail()
                intent = {'schema': 'orbis.host.credential-bootstrap-intent.v1',
                    **{key: packet[key] for key in ('operationId', 'installationId', 'reviewSha256', 'planSha256', 'activationRequestId')},
                    'packetSha256': packet_sha, 'approvalSha256': approval_sha,
                    'nonceSha256': digest(nonce.encode('ascii')), 'issuedAtMs': issued, 'expiresAtMs': expires}
                body = encoded(intent)
                previous = _file(namespace, INTENT, 16384, optional=True)
                verify()
                verify_packet()
                if not issued <= time.time_ns() // 1_000_000 <= expires:
                    fail()
                if previous is None:
                    self._write(product, admission, namespace, INTENT, body, None)
                elif previous != body:
                    fail()
                item = {'nonce': nonce, 'created': issued, 'expires': expires}
                with activation_intent(review, packet, packet_sha, approval_sha, item) as (intent_sha, recheck):
                    recheck()
                    return {'phase': 'activation-armed', 'operationId': operation, 'packetSha256': packet_sha, 'intentSha256': intent_sha}

    def collect(self, operation, review_sha, plan_sha, *, packet_sha, approval_sha):
        # The existing coordinator owns the operation lock and the child holds
        # the Host locks. Release this read-only scope before entering either.
        with self._scope(operation, review_sha, plan_sha) as (directory, review, plan, *rest):
            with activation_packet(directory, plan, review, packet_sha) as (_, approval, verify):
                if approval != approval_sha:
                    fail()
                verify()
        supervisor = PublishedBootstrapSupervisor()
        return supervisor.activate_held(operation_id=operation, review_sha256=review_sha,
                                        plan_sha256=plan_sha, packet_sha256=packet_sha)

    @staticmethod
    def _candidate_worker(directory, packet, worker):
        history_body = _file(directory, 'activation-history.json', 65536)
        if digest(history_body) != packet['candidate']['historySha256']:
            fail()
        history = decode(history_body)
        if history['current']['authWorker'] != worker:
            fail()
        return history

    def _archive(self, product, admission, namespace, folder, body):
        path = namespace.path / folder
        if not os.path.lexists(path):
            try:
                os.mkdir(folder, 0o700, dir_fd=namespace.fd)
            except FileExistsError:
                pass
            os.fsync(namespace.fd)
        with PrivateDirectory(path) as directory:
            if mount_id(directory.fd) != mount_id(namespace.fd):
                fail()
            name = digest(body) + '.json'
            previous = _file(directory, name, 65536, optional=True)
            if previous is None:
                self._write(product, admission, directory, name, body, None)
            elif previous != body:
                fail()

    @staticmethod
    def _completion(directory, packet, packet_sha, intent_sha, receipt):
        expected = {'phase': 'activation-committed', 'operationId': packet['operationId'],
                    'packetSha256': packet_sha, 'planSha256': packet['planSha256'], 'requestId': packet['activationRequestId'],
                    'commitSha256': packet['candidate']['projectedCommitSha256'], 'generation': packet['stage']['pendingGeneration'] + 1,
                    'revision': packet['stage']['revision'], 'keyRevision': packet['key']['revision'],
                    'terminalReceiptSha256': receipt.get('terminalReceiptSha256')}
        if (receipt != expected or not hash_value(receipt['terminalReceiptSha256'])
                or digest(_file(directory, 'held-activation-terminal.json', 16384)) != receipt['terminalReceiptSha256']):
            fail()
        return activation_completion(packet, packet_sha, intent_sha, receipt)

    def commit(self, operation, review_sha, plan_sha, *, packet_sha, approval_sha):
        with self._guarded(operation, review_sha, plan_sha) as (directory, review, plan, admission, product, source, namespace, host, worker, verify):
            self._quiet(namespace, allow_bootstrap=True)
            with activation_packet(directory, plan, review, packet_sha) as (packet, approval, verify_packet):
                if approval != approval_sha:
                    fail()
                history = self._candidate_worker(directory, packet, worker)
                if (history['current']['sentinel']['runtimeSha256'] != digest(encoded(review['runtime']['runtimeFiles']))
                        or history['current']['sourceExporter']['capabilitiesSha256'] != digest(encoded(source.CAPABILITY))):
                    fail()
                args = {'operationId': operation, 'planSha256': plan_sha, 'packetSha256': packet_sha}
                intent_sha = digest(_file(namespace, INTENT, 16384))
                receipt = self.client.call('bootstrap-held-activation-reconcile', args)
                completion = self._completion(directory, packet, packet_sha, intent_sha, receipt)
                bodies = {name: _file(directory, file, maximum) for name, file, maximum in (
                    ('history', 'activation-history.json', 65536), ('config', 'activation-config.json', 16384),
                    ('bridge', 'activation-bridge.json', 32768))}
                if any(digest(body) != packet['candidate'][name + 'Sha256'] for name, body in bodies.items()):
                    fail()

                def observe():
                    verify()
                    verify_packet()
                    if (digest(_file(namespace, INTENT, 16384)) != intent_sha
                            or self.client.call('bootstrap-held-activation-reconcile', args) != receipt):
                        fail()
                    with host_commit_view(review, packet, packet_sha, approval_sha, completion) as (view, check):
                        check()
                        return view

                self._publish(product, admission, namespace, host, completion, approval_sha, bodies, observe)
                if observe().phase != 'complete':
                    fail()
                return {**completion, 'phase': 'host-config-committed-held', 'completionSha256': digest(encoded(completion))}

    def _publish(self, product, admission, namespace, host, completion, approval, bodies, observe):
        def put(directory, name, body, before):
            self._write(product, admission, directory, name, body, before)

        def advance(phase):
            current = _file(namespace, ACTIVATION_PROGRESS, 16384, optional=True)
            put(namespace, ACTIVATION_PROGRESS, activation_progress(phase, completion['packetSha256'], approval, completion), current)

        view = observe()
        candidate = decode(bodies['history'])
        if any(candidate['minimum'][name]['version'] < version for name, version in view.inherited_minima):
            fail()
        if view.phase is None:
            advance('terminal-verified')
            view = observe()
        if view.phase == 'terminal-verified':
            self._archive(product, admission, namespace, floor.ARCHIVE, view.prior_history)
            view = observe()
            self._archive(product, admission, namespace, CONFIG_ARCHIVE, view.prior_config)
            observe()
            advance('predecessor-archived')
            view = observe()
        if view.phase == 'predecessor-archived':
            self._archive(product, admission, namespace, storage.BRIDGE_DIRECTORY, bodies['bridge'])
            observe()
            advance('bridge-ready')
            view = observe()
        if view.phase == 'bridge-ready':
            if view.history != bodies['history']:
                put(namespace, floor.HISTORY, bodies['history'], view.prior_history)
                observe()
            advance('history-ready')
            view = observe()
        if view.phase == 'history-ready':
            if view.config != bodies['config']:
                put(host, CONFIG, bodies['config'], view.prior_config)
                observe()
            advance('config-verified')
            view = observe()
        if view.phase == 'config-verified':
            saved = _file(namespace, ACTIVATION_COMPLETE, 16384, optional=True)
            if saved is None:
                put(namespace, ACTIVATION_COMPLETE, encoded(completion), None)
            observe()
            advance('complete')

    def release(self, operation, review_sha, plan_sha, *, packet_sha, approval_sha):
        from .bootstrap_host_release import HostPublicationRelease
        return HostPublicationRelease(self).run(operation, review_sha, plan_sha,
                                               packet_sha=packet_sha, approval_sha=approval_sha)

def run(action, operation, review, plan, *, request, packet, approval, verify_package):
    writer = HostActivation(verify_package)
    if action == 'prepare-activation':
        return writer.prepare(operation, review, plan, request=request)
    method = {'arm-activation': writer.arm, 'collect-activation': writer.collect,
              'commit-activation': writer.commit, 'release-activation': writer.release}[action]
    return method(operation, review, plan, packet_sha=packet, approval_sha=approval)
