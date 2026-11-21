"""Retained Host retirement of one qualified paired-bootstrap operation."""

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path

from . import bootstrap_publication as publication
from . import bootstrap_source as source
from . import credential_floor as floor
from . import credential_storage as storage
from .bootstrap_control import RootBootstrapControlClient
from .bootstrap_host_transition import HOST_SOURCE, _Docker, _file, require_retained_worker
from .bootstrap_source import PrivateDirectory, decode, digest, encoded, fail

READY_FILE = 'credential-bootstrap-ready.json'
PUBLICATION_HOLD = 'credential-bootstrap-publication-hold.json'


class HostPublicationRelease:
    def __init__(self, activation):
        self.activation = activation

    @contextmanager
    def _live(self, resources, review, packet, admission, product, root, namespace, verify_scope, guard, directory):
        fence = admission.host.CREDENTIAL_FENCE
        if (getattr(fence, 'BOOTSTRAP_PUBLICATION_PROTOCOL', None) != 1
                or getattr(fence, 'BOOTSTRAP_PUBLICATION_HOLD', None) != PUBLICATION_HOLD):
            fail()
        supervisor = admission.supervisor
        runtime, modules, verify_runtime = resources.enter_context(supervisor._held_runtime(storage_floor=True))
        recovery, verify_recovery = resources.enter_context(supervisor.bootstrap_recovery(
            packet['origin'], review['main'], runtime, modules, installation_id=packet['installationId']))
        if (runtime != review['runtime']
                or {key: value for key, value in recovery.items() if key != 'process'}
                != {key: value for key, value in review['recovery'].items() if key != 'process'}):
            fail()
        marker = product.C.PinnedFile(product.RECOVERY_SETUP, limit=16384, private=True)
        resources.callback(marker.close)
        setup_sha = digest(marker.body)
        roles = {'installation': root, 'namespace': namespace,
                 'journal': resources.enter_context(PrivateDirectory(namespace.path / 'credential-journal')),
                 'recovery': resources.enter_context(PrivateDirectory(floor.RECOVERY_ROOT))}
        docker = _Docker(str(HOST_SOURCE))
        worker = self.activation._qualified_worker(namespace, review, docker, product, modules)
        self.activation._candidate_worker(directory, packet, worker)

        def check():
            verify_scope()
            verify_runtime()
            verify_recovery()
            marker.verify()
            admission.service.require_credential_idle(guard)
            for name, role in roles.items():
                storage.verify_role(name, role, review['storage'][name])
            installation, main, daemon = supervisor._main(packet['origin'], storage_transition=True)
            if (installation, main, daemon) != (packet['installationId'], review['main'], packet['daemon']):
                fail()
            if (digest(encoded(admission.layout.read(root.path, daemon, review['context']))) != review['layoutSha256']
                    or require_retained_worker(namespace, review, docker) != worker):
                fail()
            self.activation._candidate_worker(directory, packet, worker)
            stopped = supervisor._host_stopped()
            copy = stopped['custody']
            if review['host'] != {'inventorySha256': digest(encoded(copy['sourceFiles'])),
                    'unitSha256': copy['unitSha256'], 'environmentSha256': copy['environmentSha256'],
                    'effectiveSha256': stopped['systemdSha256']}:
                fail()
            if admission._journal({'namespace': str(namespace.path)}, modules, history=review) != review['journal']:
                fail()

        check()
        client = RootBootstrapControlClient(str(floor.RECOVERY_ROOT / 'bootstrap-control.sock'),
                                            timeout=8, expected_pid=recovery['process']['pid'])
        yield client, setup_sha, check
        check()

    @staticmethod
    def _document(directory, name):
        body = _file(directory, name, 16384)
        value = decode(body)
        if encoded(value) != body:
            fail()
        return value

    @staticmethod
    def _put(product, admission, directory, name, body):
        maximum = 32768 if name == publication.QUALIFICATION_EVIDENCE_FILE else 16384
        existing = _file(directory, name, maximum, optional=True)
        if existing is None:
            product._write_storage(admission.authority, directory.fd, name, body, previous=None)
        elif existing != body:
            fail()
        with source.PrivateFile(directory, name, maximum) as opened:
            if opened.body != body:
                fail()
            # A visible exact pathname may follow a failed post-rename sync.
            os.fsync(opened.fd)
            os.fsync(directory.fd)
            opened.verify()

    def run(self, operation, review_sha, plan_sha, *, packet_sha, approval_sha):
        from .bootstrap_host_qualification import ensure_qualification
        actor = self.activation
        with actor._scope(operation, review_sha, plan_sha) as (directory, review, plan, admission, product, _, root, verify_scope):
            service = admission.service
            with (admission.host.credential_fence_lock(service.root, service.context) as guard,
                  ExitStack() as resources):
                namespace = resources.enter_context(PrivateDirectory(Path(review['captureRoot']).parent))
                if namespace.path != admission.layout.namespace(service.root):
                    fail()
                resources.enter_context(PrivateDirectory(service.state_dir))
                packet, approval, verify_packet = resources.enter_context(source.activation_packet(
                    directory, plan, review, packet_sha))
                if approval != approval_sha:
                    fail()
                completion = self._document(namespace, source.ACTIVATION_COMPLETE)
                terminal_sha, intent_sha = completion.get('terminalSha256'), completion.get('intentSha256')
                if (not source.hash_value(terminal_sha) or not source.hash_value(intent_sha)
                        or completion != source.activation_completion(packet, packet_sha, intent_sha, {
                            'commitSha256': packet['candidate']['projectedCommitSha256'],
                            'terminalReceiptSha256': terminal_sha})):
                    fail()
                view, verify_commit = resources.enter_context(source.host_commit_view(
                    review, packet, packet_sha, approval_sha, completion))
                if view.phase != 'complete':
                    fail()
                client, setup_sha, verify_live = resources.enter_context(self._live(
                    resources, review, packet, admission, product, root, namespace, verify_scope, guard, directory))
                recovery = resources.enter_context(PrivateDirectory(floor.RECOVERY_ROOT))
                def qualify_check():
                    verify_scope()
                    verify_packet()
                    verify_commit()
                    verify_live()

                qualification, verify_qualification = ensure_qualification(self, resources, directory, namespace,
                    recovery, review, packet, completion, approval_sha, setup_sha, client, qualify_check,
                    guard, product, admission)
                publication._qualification(qualification, completion, review, setup_sha)
                evidence = publication._Evidence(resources)
                publication._setup_evidence(evidence, recovery, review, qualification)
                evidence.absent(namespace, '.' + publication.QUALIFICATION_FILE + '.pending',
                                '.' + publication.FENCE + '.pending')
                expected_ready = publication._ready(completion, setup_sha, qualification)
                expected_release = publication._release(expected_ready, packet, completion)
                expected_published = publication._published(expected_ready, digest(encoded(expected_release)), packet)
                hold_body = encoded({'schema': 'orbis.host.bootstrap-publication-hold.v1',
                                     'operationId': operation, 'planSha256': plan_sha,
                                     'packetSha256': packet_sha, 'releaseSha256': digest(encoded(expected_release))})
                arguments = {'operationId': operation, 'planSha256': plan_sha, 'packetSha256': packet_sha}
                fence_body = publication._fence(packet)
                intent_body = (_file(namespace, publication.INTENT, 16384, optional=True)
                               or _file(namespace, publication.RETIRED_INTENT, 16384, optional=True))
                if intent_body is None or digest(intent_body) != intent_sha:
                    fail()
                publication._intent(packet, completion, approval_sha, decode(intent_body))

                def check():
                    verify_scope()
                    verify_packet()
                    verify_commit()
                    verify_live()
                    verify_qualification()
                    evidence.recheck()
                    namespace.verify()
                    guard.read()
                    if self._document(namespace, publication.QUALIFICATION_FILE) != qualification:
                        fail()

                def state():
                    check()
                    active_fence = _file(namespace, publication.FENCE, 4096, optional=True)
                    active_intent = _file(namespace, publication.INTENT, 16384, optional=True)
                    retired_fence = _file(namespace, publication.RETIRED_FENCE, 4096, optional=True)
                    retired_intent = _file(namespace, publication.RETIRED_INTENT, 16384, optional=True)
                    released = _file(namespace, publication.RELEASE_FILE, 16384, optional=True)
                    hold = _file(namespace, PUBLICATION_HOLD, 16384, optional=True)
                    if (active_fence not in (None, fence_body) or active_intent not in (None, intent_body)
                            or retired_fence not in (None, fence_body) or retired_intent not in (None, intent_body)
                            or active_fence is not None and (active_intent is None or retired_intent is not None)
                            or active_fence is None and retired_fence != fence_body
                            or active_intent is None and retired_intent != intent_body
                            or hold not in (None, hold_body)
                            or active_fence is None and hold is None and not published()
                            or released is not None and (released != encoded(expected_release)
                                or active_fence is not None or active_intent is not None)):
                        fail()
                    pending = (
                        (READY_FILE, encoded(expected_ready), active_fence is not None
                            and _file(namespace, READY_FILE, 16384, optional=True) is None),
                        (PUBLICATION_HOLD, hold_body, active_fence is not None and hold is None),
                        (publication.RETIRED_FENCE, fence_body,
                            active_fence is not None and retired_fence is None),
                        (publication.RETIRED_INTENT, intent_body,
                            active_fence is None and active_intent is not None and retired_intent is None),
                        (publication.RELEASE_FILE, encoded(expected_release),
                            active_fence is None and active_intent is None and released is None),
                    )
                    for name, expected, allowed in pending:
                        body = _file(namespace, '.' + name + '.pending', 16384, optional=True)
                        if body is not None and (not allowed or body != expected):
                            fail()
                    return active_fence, active_intent

                def published():
                    if not os.path.lexists(directory.path / publication.PROOF_FILE):
                        return False
                    with publication.read_published(namespace.path, recovery_directory=recovery.path,
                            root=packet['root'], context=packet['context'], daemon=packet['daemon'],
                            history_body=_file(directory, 'activation-history.json', 65536)) as proof:
                        if (proof.operation_id, proof.plan_sha256, proof.packet_sha256, proof.receipt_sha256) != (
                                operation, plan_sha, packet_sha, digest(encoded(expected_published))):
                            fail()
                        proof.recheck()
                    return True

                ready_body = _file(namespace, READY_FILE, 16384, optional=True)
                if ready_body is None:
                    guard.check(operation, review_sha)
                    if (_file(namespace, publication.FENCE, 4096) != fence_body
                            or _file(namespace, publication.INTENT, 16384) != intent_body
                            or any(_file(namespace, name, 16384, optional=True) is not None for name in (
                                publication.RETIRED_FENCE, publication.RETIRED_INTENT, publication.RELEASE_FILE))):
                        fail()
                    if client.call('bootstrap-paired-publication-ready', arguments) != expected_ready:
                        fail()
                    check()
                elif ready_body != encoded(expected_ready):
                    fail()

                state()
                self._put(product, admission, namespace, READY_FILE, encoded(expected_ready))
                if _file(namespace, PUBLICATION_HOLD, 16384, optional=True) is not None or not published():
                    self._put(product, admission, namespace, PUBLICATION_HOLD, hold_body)
                state()
                self._put(product, admission, namespace, publication.RETIRED_FENCE, fence_body)

                def completed():
                    state()
                    if _file(namespace, READY_FILE, 16384) != encoded(expected_ready):
                        fail()
                    return True

                guard.finish(operation, review_sha, verify_completed=completed)
                _, live_intent = state()
                self._put(product, admission, namespace, publication.RETIRED_INTENT, intent_body)
                if live_intent is not None:
                    state()
                    os.unlink(publication.INTENT, dir_fd=namespace.fd)
                    os.fsync(namespace.fd)
                if state() != (None, None):
                    fail()
                self._put(product, admission, namespace, publication.RELEASE_FILE, encoded(expected_release))
                state()
                if client.call('bootstrap-paired-publication-publish', arguments) != expected_published:
                    fail()
                check()
                if not published():
                    fail()
                if _file(namespace, PUBLICATION_HOLD, 16384, optional=True) is not None:
                    with source.PrivateFile(namespace, PUBLICATION_HOLD, 16384) as hold:
                        if hold.body != hold_body:
                            fail()
                        hold.verify()
                        os.unlink(PUBLICATION_HOLD, dir_fd=namespace.fd)
                os.fsync(namespace.fd)
                namespace.verify()
                if not published():
                    fail()
                return {'phase': 'paired-published', 'operationId': operation,
                        'publicationSha256': digest(encoded(expected_published))}
