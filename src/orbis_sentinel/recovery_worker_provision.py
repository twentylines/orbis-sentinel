"""Retain an inert auth image and verify its actual independently owned probe."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import secrets

from . import credential_floor as floor, credential_storage as storage
from . import host_source_publication as publisher
from .bootstrap_source import PrivateDirectory, PrivateFile, decode, digest, encoded, fail, hash_value, v1_contract_minima
from .collector_execution import CollectorExecutionInventory, HOST_SOURCE, HOST_STATE, SNAPSHOTS, _ByteModules
from .recovery_worker import _Docker, capability_create_arguments, validate_capability
from .writer_journal import mount_id

OPERATIONS = 'retained-recovery-worker-operations'
RECEIPTS = 'retained-recovery-workers'
ANCHOR_LABEL = 'io.orbis.sentinel.retained-worker'
OWNER_LABEL = 'io.orbis.sentinel.retained-worker-operation'
PLAN = 'orbis.sentinel-retained-worker-review.v1'
APPROVAL = 'orbis.sentinel-retained-worker-approval.v1'
INTENT = 'orbis.sentinel-retained-worker-intent.v1'
RESULT = 'orbis.sentinel-retained-worker-receipt.v1'
PHASES = ('intent', 'anchor-creating', 'anchor-known', 'probe-creating', 'probe-known',
          'probe-running', 'probe-verified', 'probe-clean', 'complete')


def _read(directory, name, *, optional=False):
    try:
        with PrivateFile(directory, name, 65536) as pinned:
            if mount_id(pinned.fd) != mount_id(directory.fd):
                fail()
            return pinned.body
    except FileNotFoundError:
        if not optional:
            raise
        return None


@contextmanager
def _subdirectory(parent, name, *, create=False):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent.fd)
            os.fsync(parent.fd)
        except FileExistsError:
            pass
    with PrivateDirectory(parent.path / name) as directory:
        if mount_id(directory.fd) != mount_id(parent.fd):
            fail()
        yield directory


def _anchor_name(image):
    if not floor.image(image):
        fail()
    return 'orbis-sentinel-retained-' + image[7:39]


def _capability_command(name, image, owner, *, anchor):
    labels = [OWNER_LABEL + '=' + owner]
    if anchor:
        labels.append(ANCHOR_LABEL + '=' + image)
    return capability_create_arguments(name, labels, image)


def _profile_sha(image):
    return digest(encoded(_capability_command(_anchor_name(image), image, '0' * 64, anchor=True)))


def _image_facts(docker, image):
    value = decode(docker.run(['image', 'inspect', '--format', '{{json .}}', image], limit=2 * 1024 * 1024))
    config = value['Config']
    labels = config.get('Labels') or {}
    if (value['Id'] != image or config.get('Volumes') not in (None, {})
            or labels.get('org.opencontainers.image.source') != 'https://github.com/twentylines/orbis'
            or labels.get('io.orbis.credential-writer-protocol') != 'orbis.credentials.v1'):
        fail()
    # Names/tags can legitimately be added to the same image. Pin its immutable
    # config and layers, with publication checked separately through B/Main.
    return digest(encoded({'id': image, 'config': config, 'rootfs': value['RootFS']}))


def _find(docker, selector):
    lines = docker.run(['ps', '-a', '--no-trunc', '--filter', selector, '--format', '{{.ID}}']).decode('ascii').splitlines()
    if len(lines) > 1 or any(not hash_value(item) for item in lines):
        fail()
    return lines[0] if lines else None


def _inspect_child(docker, identity, name, image, owner, *, anchor, state):
    value = decode(docker.run(['inspect', '--format', '{{json .}}', identity], limit=2 * 1024 * 1024))
    config, host, observed = (value[key] for key in ('Config', 'HostConfig', 'State'))
    labels = config.get('Labels') or {}
    if (not hash_value(identity) or value['Id'] != identity or value['Name'] != '/' + name or value['Image'] != image
            or config['Image'] != image or labels.get(OWNER_LABEL) != owner
            or labels.get(ANCHOR_LABEL) != (image if anchor else None)
            or config['Entrypoint'] != ['/usr/local/bin/node'] or config['Cmd'] != ['/app/sentinel-recovery-auth.mjs', '--capability']
            or value['Path'] != config['Entrypoint'][0] or value['Args'] != config['Cmd']
            or config['User'] != '0:0' or config.get('Volumes') not in (None, {}) or value['Mounts'] != []
            or config.get('Healthcheck') != {'Test': ['NONE']} or config.get('OpenStdin') is not True
            or any(host.get(key) not in (None, []) for key in ('Binds', 'CapAdd', 'Devices', 'DeviceRequests', 'VolumesFrom'))
            or host.get('PortBindings') not in (None, {}) or host['PublishAllPorts'] is not False
            or host['Privileged'] is not False or host['ReadonlyRootfs'] is not True or host['AutoRemove'] is not False
            or host['NetworkMode'] != 'none' or host['IpcMode'] != 'none' or host['CapDrop'] != ['ALL']
            or host['SecurityOpt'] != ['no-new-privileges'] or host['LogConfig'].get('Type') != 'none'
            or host['RestartPolicy'] != {'Name': 'no', 'MaximumRetryCount': 0}
            or host['PidsLimit'] != 64 or host['Memory'] != 512 * 1024 * 1024 or host['NanoCpus'] != 1000000000
            or any(observed[key] is not False for key in ('Running', 'Paused', 'Restarting', 'Dead'))
            or observed['Status'] != state or type(observed['Pid']) is not int or observed['Pid'] != 0
            or type(observed['ExitCode']) is not int or observed['ExitCode'] != 0):
        fail()
    return digest(encoded({key: value[key] for key in ('Id', 'Name', 'Image', 'Config', 'HostConfig', 'Mounts', 'Path', 'Args')}))


def _approval(value, plan, plan_sha):
    if (value != {'schema': APPROVAL, 'publisherOperationId': plan['publication']['operationId'],
                  'installationId': plan['scope']['installationId'], 'reviewSha256': plan_sha,
                  'approvalId': value.get('approvalId')} or not hash_value(value.get('approvalId'))):
        fail()


def _receipt(plan, record):
    return {'schema': RESULT, 'scope': plan['scope'], 'publication': plan['publication'], 'imageId': plan['imageId'],
            'reviewSha256': record['reviewSha256'], 'approvalSha256': record['approvalSha256'],
            'operationId': record['operationId'], 'nonce': record['nonce'], 'anchorId': record['anchorId'],
            'anchorSha256': record['anchorSha256'], 'probeId': record['probeId'],
            'capabilitySha256': digest(encoded(validate_capability(record['capability'])))}


def _record_body(body, base):
    value = decode(body)
    extra = ('nonce', 'phase', 'anchorId', 'anchorSha256', 'probeId', 'capability')
    if (body != encoded(value) or set(value) != set(base).union(extra)
            or any(value[key] != item for key, item in base.items())
            or value['phase'] not in PHASES or not hash_value(value['nonce'])):
        fail()
    rank = PHASES.index(value['phase'])
    for name, threshold in (('anchorId', 2), ('anchorSha256', 2), ('probeId', 4)):
        if rank >= threshold and not hash_value(value[name]) or rank < threshold and value[name] is not None:
            fail()
    if value['anchorId'] is not None and value['anchorId'] == value['probeId']:
        fail()
    if rank >= 6:
        validate_capability(value['capability'])
    elif value['capability'] is not None:
        fail()
    return value


def _operation_base(plan, review_sha, approval_sha):
    operation = digest(encoded(['orbis.sentinel-retained-worker.v1', plan['publication']['operationId'], review_sha]))
    return {'schema': INTENT, 'operationId': operation, 'reviewSha256': review_sha,
            'approvalSha256': approval_sha, 'installationId': plan['scope']['installationId']}


def _owned_anchor(docker, plan, record):
    image, identity = plan['imageId'], record['anchorId']
    name = _anchor_name(image)
    if _find(docker, 'name=^/' + name + '$') != identity:
        fail()
    current = _inspect_child(docker, identity, name, image, record['nonce'], anchor=True, state='created')
    if current != record['anchorSha256']:
        fail()
    return current


def _missing_probe(docker, record):
    probe = 'orbis-sentinel-probe-' + record['nonce'][:32]
    if any(_find(docker, key) is not None for key in ('name=^/' + probe + '$', 'id=' + record['probeId'])):
        fail()


def require_retained_worker(namespace, review, docker, *, receipt_sha256=None):
    """Reopen the scoped receipt and prove the same live, still inert anchor."""
    image = review['main']['imageId']
    operation = review['publisher']['operationId']
    if not hash_value(operation) or not floor.image(image):
        fail()
    with (ExitStack() as resources, _subdirectory(namespace, OPERATIONS) as operations,
          _subdirectory(operations, operation) as directory, _subdirectory(namespace, RECEIPTS) as receipts):
        pins = []

        def read(parent, name):
            pinned = resources.enter_context(PrivateFile(parent, name, 65536))
            if mount_id(pinned.fd) != mount_id(parent.fd):
                fail()
            pins.append(pinned)
            return pinned.body

        plan_body = read(directory, 'review.json')
        review_sha = digest(plan_body)
        plan = decode(plan_body)
        verify_bound_plan(plan, review)
        approval_body = read(directory, 'approval.json')
        _approval(decode(approval_body), plan, review_sha)
        record = _record_body(read(directory, 'intent.json'), _operation_base(plan, review_sha, digest(approval_body)))
        if record['phase'] != 'complete':
            fail()
        receipt = _receipt(plan, record)
        if (read(receipts, image[7:] + '.json') != encoded(receipt)
                or receipt_sha256 is not None and digest(encoded(receipt)) != receipt_sha256
                or _image_facts(docker, image) != plan['imageDefinitionSha256']):
            fail()
        _owned_anchor(docker, plan, record)
        _missing_probe(docker, record)
        for pinned in pins:
            pinned.verify()
        return {'imageId': image, 'anchorSha256': receipt['anchorSha256'],
                'capabilitiesSha256': receipt['capabilitySha256']}


def verify_bound_plan(plan, review):
    scope = {key: review[key] for key in ('installationId', 'root', 'context', 'daemon', 'origin')}
    static = {'schema': PLAN, 'scope': scope, 'publication': review['publisher'],
              'main': review['main'], 'runtime': review['runtime'],
              'historySha256': review['hostHistorySha256'], 'configSha256': review['previousAdmissionSha256'],
              'imageId': review['main']['imageId'], 'profileSha256': _profile_sha(review['main']['imageId'])}
    if (set(plan) != set(static).union(('imageDefinitionSha256', 'storage'))
            or any(plan[key] != value for key, value in static.items())
            or not hash_value(plan['imageDefinitionSha256'])
            or plan['storage'] != {key: review['storage'][key] for key in ('installation', 'namespace', 'journal')}):
        fail()


class WorkerProvision:
    def __init__(self, verify_package):
        self.verify_package = verify_package

    @contextmanager
    def _scope(self, operation, receipt_sha):
        if not hash_value(operation) or not hash_value(receipt_sha):
            fail()

        def match(_, evidence):
            if evidence.receipt_sha256 != receipt_sha or evidence.observation['schema'] != publisher.SCHEMA_CUSTODY:
                fail()

        with ExitStack() as resources:
            evidence = resources.enter_context(publisher._completed(operation, match))
            copied = evidence.observation['copy']
            root = floor._InstallationDirectory(Path(copied['root']))
            resources.callback(root.close)
            inventory = resources.enter_context(CollectorExecutionInventory.open_installed(copied['inventory']))
            modules = _ByteModules(inventory)
            host_module = modules.load('orbis-host-service.py', '_worker_provision_host')
            product = modules.load('orbis-host-recovery-admission.py', '_worker_provision_admission')
            context = copied['context']
            service = host_module.HostService(root.path, context, SNAPSHOTS, HOST_STATE, recover_interrupted_job=False)
            admission = product.Admission(service)
            supervisor = admission.supervisor
            if service.state_dir != HOST_STATE or service.state_dir != admission.layout.STATE_ROOT:
                fail()
            guard = resources.enter_context(admission.host.credential_fence_lock(root.path, context))
            namespace = resources.enter_context(PrivateDirectory(admission.layout.namespace(root.path)))
            host = resources.enter_context(PrivateDirectory(service.state_dir))
            runtime, runtime_modules, check_runtime = resources.enter_context(supervisor._held_runtime(storage_floor=True))
            roles = {'installation': root, 'namespace': namespace,
                     'journal': resources.enter_context(PrivateDirectory(namespace.path / 'credential-journal'))}
            prior, config = _read(namespace, floor.HISTORY), _read(host, 'credential-admission.json')
            old = decode(prior)
            origin = decode(config)['origin']
            product._origin(origin)
            installation, main, daemon = supervisor._main(origin, storage_transition=True)
            scope = {'root': str(root.path), 'context': context, 'installationId': installation, 'daemon': daemon, 'origin': origin}
            binding = {key: scope[key] for key in ('root', 'context', 'daemon')}
            if digest(encoded({**binding, 'rootIdentity': root.identity})) != installation:
                fail()
            observed = supervisor._host_stopped()
            host_binding = {key: observed['custody'][key] for key in ('unitSha256', 'environmentSha256')}
            host_binding['inventorySha256'] = digest(encoded(observed['custody']['sourceFiles']))
            publisher._check_floor_publication(evidence, root.path, context, {'main': main, 'host': host_binding},
                                               root_identity=root.identity)
            if inventory.inventory_sha256 != host_binding['inventorySha256']:
                fail()
            journal = admission._journal({'namespace': str(namespace.path)}, runtime_modules, history=old)
            if journal is None:
                fail()
            docker = _Docker(str(HOST_SOURCE))
            image = main['imageId']
            plan = {'schema': PLAN, 'scope': scope, 'publication': {'operationId': operation, 'receiptSha256': receipt_sha},
                    'main': main, 'runtime': runtime, 'historySha256': digest(prior), 'configSha256': digest(config),
                    'imageId': image, 'profileSha256': _profile_sha(image), 'imageDefinitionSha256': _image_facts(docker, image),
                    'storage': {name: storage.observe(role) for name, role in roles.items()}}
            history_binding = {'hostHistorySha256': plan['historySha256'], 'previousAdmissionSha256': plan['configSha256'],
                               'previousGeneration': old.get('generation'), 'previousWriterProtocol': old.get('writerProtocol'),
                               'previousSentinelVersion': old.get('sentinelVersion'), 'installationId': installation}
            v1_contract_minima(history_binding, prior, config)

            def verify():
                for check in (self.verify_package, evidence.recheck, inventory.verify, check_runtime, root.verify,
                              namespace.verify, host.verify):
                    check()
                service.require_credential_idle(guard)
                if (_read(namespace, floor.HISTORY) != prior or _read(host, 'credential-admission.json') != config
                        or supervisor._main(origin, storage_transition=True) != (installation, main, daemon)
                        or supervisor._host_stopped() != observed or _image_facts(docker, image) != plan['imageDefinitionSha256']
                        or admission._journal({'namespace': str(namespace.path)}, runtime_modules, history=old) != journal
                        or admission._bootstrap_predecessor(namespace, prior, config, installation, origin, runtime) != old
                        or any(os.path.lexists(namespace.path / name) for name in (
                            'credential-bootstrap-intent.json', '.credential-bootstrap-intent.json.pending',
                            'recovery-admission-intent.json', '.recovery-admission-intent.json.pending',
                            'credential-storage-migration.json', '.credential-storage-migration.json.pending'))):
                    fail()
                for name, role in roles.items():
                    storage.verify_role(name, role, plan['storage'][name])

            verify()
            yield namespace, admission, product, guard, plan, docker, verify
            verify()

    @staticmethod
    def _write(product, admission, directory, name, body, previous):
        product._write_storage(admission.authority, directory.fd, name, body, previous=previous)
        if _read(directory, name) != body:
            fail()

    def review(self, operation, receipt_sha):
        with self._scope(operation, receipt_sha) as (namespace, admission, product, guard, plan, _, verify):
            if guard.read() is not None:
                fail()
            with (_subdirectory(namespace, OPERATIONS, create=True) as operations,
                  _subdirectory(operations, operation, create=True) as directory):
                existing = _read(directory, 'review.json', optional=True)
                body = encoded(plan)
                verify()
                if existing is None:
                    if os.path.lexists(directory.path / 'approval.json') or os.path.lexists(directory.path / 'intent.json'):
                        fail()
                    self._write(product, admission, directory, 'review.json', body, None)
                elif existing != body:
                    fail()
                return {'phase': 'worker-awaits-approval', 'publisherOperationId': operation, 'reviewSha256': digest(body)}

    def apply(self, operation, receipt_sha, review_sha, approval_sha):
        if not hash_value(review_sha) or not hash_value(approval_sha):
            fail()
        with (self._scope(operation, receipt_sha) as (namespace, admission, product, guard, plan, docker, verify),
              _subdirectory(namespace, OPERATIONS) as operations,
              _subdirectory(operations, operation) as directory,
              PrivateFile(directory, 'review.json', 65536) as reviewed,
              PrivateFile(directory, 'approval.json', 16384) as approved):
            if (reviewed.body != encoded(plan) or digest(reviewed.body) != review_sha
                    or digest(approved.body) != approval_sha
                    or any(mount_id(item.fd) != mount_id(directory.fd) for item in (reviewed, approved))):
                fail()
            _approval(decode(approved.body), plan, review_sha)
            base = _operation_base(plan, review_sha, approval_sha)
            previous = _read(directory, 'intent.json', optional=True)
            staged = _read(directory, '.intent.json.pending', optional=True)
            known_receipt = None
            if os.path.lexists(namespace.path / RECEIPTS):
                with _subdirectory(namespace, RECEIPTS) as receipts:
                    known_receipt = _read(receipts, plan['imageId'][7:] + '.json', optional=True)
                    if known_receipt is not None and _read(receipts, '.' + plan['imageId'][7:] + '.json.pending', optional=True) is not None:
                        fail()
            current_guard = guard.read()
            if current_guard is not None:
                guard.check(base['operationId'], review_sha)

            def check():
                verify()
                reviewed.verify()
                approved.verify()

            if previous is None:
                check()
                if (known_receipt is not None or staged is not None and current_guard is None
                        or _find(docker, 'name=^/' + _anchor_name(plan['imageId']) + '$') is not None):
                    fail()
                # Begin the common Host hold before publishing durable intent.
                # A crash between them can resume only this exact guard/body.
                guard.begin(base['operationId'], review_sha)
                if staged is None:
                    record = {**base, 'phase': 'intent', 'nonce': secrets.token_hex(32),
                              'anchorId': None, 'anchorSha256': None, 'probeId': None, 'capability': None}
                else:
                    record = _record_body(staged, base)
                    if record['phase'] != 'intent':
                        fail()
                previous = encoded(record)
                self._write(product, admission, directory, 'intent.json', previous, None)
            else:
                record = _record_body(previous, base)
                if current_guard is None and record['phase'] != 'complete':
                    fail()
                if known_receipt is not None and (record['phase'] not in ('probe-clean', 'complete')
                        or known_receipt != encoded(_receipt(plan, record))):
                    fail()
                if staged is not None:
                    candidate = _record_body(staged, base)
                    if PHASES.index(candidate['phase']) != PHASES.index(record['phase']) + 1:
                        fail()
                    updates = {'anchor-known': ('anchorId', 'anchorSha256'), 'probe-known': ('probeId',),
                               'probe-verified': ('capability',)}.get(candidate['phase'], ())
                    expected = {**record, 'phase': candidate['phase'], **{key: candidate[key] for key in updates}}
                    if candidate != expected:
                        fail()

            def advance(phase, **values):
                nonlocal previous, record
                guard.check(base['operationId'], review_sha)
                check()
                if PHASES.index(phase) != PHASES.index(record['phase']) + 1:
                    fail()
                candidate = {**record, **values, 'phase': phase}
                body = encoded(candidate)
                self._write(product, admission, directory, 'intent.json', body, previous)
                previous, record = body, candidate
                return candidate

            if record['phase'] != 'complete':
                if record['phase'] == 'probe-running':
                    staged = _read(directory, '.intent.json.pending', optional=True)
                    if staged is not None:
                        candidate = _record_body(staged, base)
                        if candidate != {**record, 'phase': 'probe-verified', 'capability': candidate['capability']}:
                            fail()
                        name = 'orbis-sentinel-probe-' + record['nonce'][:32]
                        _inspect_child(docker, record['probeId'], name, plan['imageId'], record['nonce'], anchor=False, state='exited')
                        advance('probe-verified', capability=candidate['capability'])
                record = self._provision(plan, record, docker, advance)

            receipt = _receipt(plan, record)
            receipt_body = encoded(receipt)
            name = plan['imageId'][7:] + '.json'
            with _subdirectory(namespace, RECEIPTS, create=True) as receipts:
                def verified():
                    check()
                    _owned_anchor(docker, plan, record)
                    _missing_probe(docker, record)
                    return _read(receipts, name, optional=True) == receipt_body

                saved = _read(receipts, name, optional=True)
                if record['phase'] == 'probe-clean':
                    guard.check(base['operationId'], review_sha)
                    if saved is None:
                        check()
                        _owned_anchor(docker, plan, record)
                        _missing_probe(docker, record)
                        self._write(product, admission, receipts, name, receipt_body, None)
                    elif saved != receipt_body:
                        fail()
                    if not verified():
                        fail()
                    advance('complete')
                if record['phase'] != 'complete' or not verified():
                    fail()
                guard.finish(base['operationId'], review_sha, verify_completed=verified)
                return {'phase': 'retained-worker-verified', 'operationId': base['operationId'],
                        'receiptSha256': digest(receipt_body), 'imageId': plan['imageId']}

    @staticmethod
    def _provision(plan, record, docker, advance):
        image, nonce = plan['imageId'], record['nonce']
        anchor, probe = _anchor_name(image), 'orbis-sentinel-probe-' + nonce[:32]

        def create(name, starting, creating, *, anchor):
            existing = _find(docker, 'name=^/' + name + '$')
            if record['phase'] == starting:
                if existing is not None:
                    fail()
                advance(creating)
                identity = docker.run(_capability_command(name, image, nonce, anchor=anchor)).decode('ascii').strip()
                if not hash_value(identity) or _find(docker, 'name=^/' + name + '$') != identity:
                    fail()
                return identity
            if existing is None:
                fail()
            return existing

        if record['phase'] in ('intent', 'anchor-creating'):
            identity = create(anchor, 'intent', 'anchor-creating', anchor=True)
            seal = _inspect_child(docker, identity, anchor, image, nonce, anchor=True, state='created')
            record = advance('anchor-known', anchorId=identity, anchorSha256=seal)
        _owned_anchor(docker, plan, record)
        if record['phase'] in ('anchor-known', 'probe-creating'):
            identity = create(probe, 'anchor-known', 'probe-creating', anchor=False)
            _inspect_child(docker, identity, probe, image, nonce, anchor=False, state='created')
            record = advance('probe-known', probeId=identity)
        if record['phase'] == 'probe-known':
            _inspect_child(docker, record['probeId'], probe, image, nonce, anchor=False, state='created')
            advance('probe-running')
            output = docker.run(['start', '--attach', '--interactive', record['probeId']], timeout=15)
            _inspect_child(docker, record['probeId'], probe, image, nonce, anchor=False, state='exited')
            record = advance('probe-verified', capability=validate_capability(decode(output)))
        if record['phase'] == 'probe-running':
            # No exact completed result exists. Exit status and labels cannot
            # serve as capability evidence and cannot justify another start.
            fail()
        if record['phase'] == 'probe-verified':
            owned = _find(docker, 'id=' + record['probeId'])
            if owned is not None:
                if owned != record['probeId'] or _find(docker, 'name=^/' + probe + '$') != owned:
                    fail()
                _inspect_child(docker, owned, probe, image, nonce, anchor=False, state='exited')
                docker.run(['rm', owned])
            _missing_probe(docker, record)
            record = advance('probe-clean')
        return record


def run(action, operation, publication_sha, review, approval, *, verify_package):
    writer = WorkerProvision(verify_package)
    if action == 'review':
        return writer.review(operation, publication_sha)
    if action == 'apply':
        return writer.apply(operation, publication_sha, review, approval)
    fail()
