"""Retained Root installation of the fixed pre-enrollment recovery listener."""

from contextlib import ExitStack, closing, contextmanager
from http.cookies import SimpleCookie
import fcntl
import http.client
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import subprocess
import threading
import time
from urllib.parse import urlsplit

from . import credential_floor as floor, credential_storage as storage, host_source_publication as publisher
from .bootstrap_source import PrivateDirectory, PrivateFile, decode, digest, encoded, fail, hash_value
from .bootstrap_source import (LISTENER_RECEIPT_FILE, BUILTIN_LISTENER_RECEIPT, PAIRED_TRANSPORT_SCHEMA,
                               PAIRED_TRANSPORT_FILE, listener_review_binding)
from .recovery_config import RecoveryConfig, builtin_effective_profile
from .recovery_sessions import _LISTENER_SETUP_STORE as STORE_BINDING
from .recovery_worker import validate_capability
from .recovery_worker_provision import WorkerProvision, _read, _subdirectory, require_retained_worker
from .writer_journal import mount_id, seal

OPERATIONS = 'recovery-listener-install-operations'
SETUP_CONFIG = Path('/etc/orbis-sentinel/recovery-setup.json')
RECOVERY_CONFIG = floor.RECOVERY_ROOT / 'config.json'
PROC_ROOT = Path('/proc')
RECEIPT_FILE = LISTENER_RECEIPT_FILE
STATUS_SOCKET = '/run/orbis-sentinel/api.sock'
MARKER = 'orbis.sentinel-recovery-listener-setup.v1'
BUILTIN_MARKER = 'orbis.sentinel-recovery-listener-setup.v2'
BUILTIN_PLAN = 'orbis.sentinel-recovery-listener-review.v2'
BUILTIN_INTENT = 'orbis.sentinel-recovery-listener-intent.v2'
PLAN = 'orbis.sentinel-recovery-listener-review.v1'
APPROVAL = 'orbis.sentinel-recovery-listener-approval.v1'
INTENT = 'orbis.sentinel-recovery-listener-intent.v1'
RECEIPT = 'orbis.sentinel-recovery-listener-receipt.v1'
BUILTIN_RECEIPT = BUILTIN_LISTENER_RECEIPT
PAIRED = PAIRED_TRANSPORT_SCHEMA
PAIRED_FILE = PAIRED_TRANSPORT_FILE
BUILTIN_STEPS = ('backend-prepared','configured','starting','running','attaching','attached','paired','complete')
_SETUP_OWNER_KEY = object()
PROBE_TTL = 20
PROBE_LIMIT = 8
ASSETS = ('recovery.html', 'recovery.css', 'recovery.js')
PHASES = ('intent', 'configured', 'starting', 'running', 'qualified', 'complete')


def _canonical(body):
    value = decode(body)
    if type(value) is not dict or encoded(value) != body:
        fail()
    return value


def _read_fixed(pins, path, mode, *, optional=False, maximum=16384):
    try:
        body = pins.file(path, maximum, mode)
    except FileNotFoundError:
        if optional:
            return None
        raise
    parent, _, mounted, _ = pins.directories[path.parent]
    if not body or mount_id(parent) != mounted or pins.files[path][2] != mounted:
        fail()
    return body


def _new_file(path, body, mode):
    """Publish exact absent-target bytes, or resume their exact pending write."""
    temporary = path.with_name('.' + path.name + '.pending')
    with closing(publisher._Pins()) as pins:
        current = _read_fixed(pins, path, mode, optional=True)
        staged = _read_fixed(pins, temporary, mode, optional=True)
        if current is not None:
            if current != body or staged is not None:
                fail()
            pins.verify()
            return
        parent = pins.directory(path.parent)
        if staged is None:
            fd = os.open(temporary.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                         dir_fd=parent)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            staged = _read_fixed(pins, temporary, mode)
        if staged != body:
            fail()
        fd, identity, _, _ = pins.files[temporary]
        os.fsync(fd)
        pins.verify()
        if publisher._exists(parent, path.name) or seal(os.stat(temporary.name, dir_fd=parent, follow_symlinks=False)) != identity:
            fail()
        os.replace(temporary.name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    with closing(publisher._Pins()) as pins:
        if _read_fixed(pins, path, mode) != body:
            fail()
        pins.verify()


class SetupBinding:
    """Pinned startup identity and transient observation in the sole HTTP owner."""

    def __init__(self, config, body, check, *, backend=None, monotonic=time.monotonic):
        value = _canonical(body)
        builtin = value.get('schema') == BUILTIN_MARKER
        fields = {'schema','operationId','installationId','configSha256','origin'}
        if builtin:
            from .recovery_backend_tls import ListenerPeer, MODE
            transport = value.get('transport')
            if (type(backend) is not ListenerPeer or type(transport) is not dict
                    or transport != {'mode':MODE,'pairId':transport.get('pairId')}
                    or not hash_value(transport['pairId'])):
                fail()
            fields.add('transport')
        elif backend is not None:
            fail()
        if (set(value) != fields or value['schema'] not in (MARKER, BUILTIN_MARKER)
                or any(not hash_value(value[name]) for name in ('operationId', 'installationId', 'configSha256'))
                or value['origin'] != config['origin'] or value['configSha256'] != digest(encoded(dict(config)))):
            fail()
        self.operation = value['operationId']
        self.installation = value['installationId']
        self.origin = value['origin']
        self.sha256 = digest(body)
        self._check = check
        self.backend = backend
        self._clock = monotonic
        self._mutex = threading.Lock()
        self._window = None

    def verify(self):
        self._check()
        if self.backend is not None:
            self.backend.verify()

    def arm(self, operation, marker_sha):
        self.verify()
        if (operation, marker_sha) != (self.operation, self.sha256):
            fail()
        with self._mutex:
            now = self._clock()
            if self._window is not None and now < self._window[1]:
                fail()
            nonce = secrets.token_hex(32)
            self._window = (nonce, now + PROBE_TTL, set())
            return nonce

    def observe(self, binding):
        with self._mutex:
            if self._window is None or self._clock() >= self._window[1]:
                self._window = None
                return
            issued = self._window[2]
            if len(issued) <= PROBE_LIMIT:
                issued.add(digest(binding.encode('ascii')))

    def confirm(self, operation, marker_sha, nonce, binding_sha):
        self.verify()
        if ((operation, marker_sha) != (self.operation, self.sha256)
                or not hash_value(nonce) or not hash_value(binding_sha)):
            fail()
        with self._mutex:
            window = self._window
            if window is None or window[0] != nonce:
                fail()
            self._window = None
            if self._clock() >= window[1] or len(window[2]) > PROBE_LIMIT or binding_sha not in window[2]:
                fail()


@contextmanager
def setup_profile(config, path):
    if Path(path) != RECOVERY_CONFIG:
        yield None
        return
    with closing(publisher._Pins()) as pins:
        body = _read_fixed(pins, SETUP_CONFIG, 0o600, optional=True)
        if body is None:
            from .recovery_backend_tls import LISTENER_ROOT
            if os.path.lexists(LISTENER_ROOT):
                fail()
            yield None
            return

        def check():
            config.verify()
            pins.verify()

        check()
        marker = _canonical(body)
        if marker.get('schema') == BUILTIN_MARKER:
            from .recovery_backend_tls import MODE, open_listener
            transport = marker.get('transport')
            if (type(transport) is not dict or transport != {'mode':MODE,'pairId':transport.get('pairId')}
                    or not hash_value(transport['pairId'])):
                fail()
            with open_listener(marker,digest(body),config.data) as backend:
                yield SetupBinding(config.data,body,check,backend=backend)
        else:
            yield SetupBinding(config.data,body,check)


def reserve_store(directory, setup):
    """Reserve a new sole-owner store before creating SQLite, without adopting one."""
    if type(setup) is not SetupBinding:
        fail()
    setup.verify()
    path = Path(directory)
    expected = encoded({'operationId': setup.operation, 'markerSha256': setup.sha256})
    with PrivateDirectory(path) as root:
        current = _read(root, STORE_BINDING, optional=True)
        if current is None:
            if set(os.listdir(root.fd)) - {'config.json', 'recovery.lock', '.' + STORE_BINDING + '.pending'}:
                fail()
            _new_file(path / STORE_BINDING, expected, 0o600)
        elif current != expected or _read(root, '.' + STORE_BINDING + '.pending', optional=True) is not None:
            fail()
    resources = ExitStack()
    try:
        root = resources.enter_context(PrivateDirectory(path))
        pinned = resources.enter_context(PrivateFile(root, STORE_BINDING, 2048))
        if pinned.body != expected or mount_id(pinned.fd) != mount_id(root.fd):
            fail()
        # Keep the reservation and its directory held across credential callbacks.
        return _HeldReservation(resources.pop_all(), pinned)
    finally:
        resources.close()


class _HeldReservation:
    def __init__(self, resources, pinned):
        self.resources, self.pinned = resources, pinned

    def verify(self):
        self.pinned.verify()

    def close(self):
        self.resources.close()


def _tls_get(origin, context, path, content_type, cookie=None, *, retained=None, document=None, probe=None):
    url = urlsplit(origin)
    with closing(http.client.HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=4)) as connection:
        if retained is not None:
            endpoint = retained.request['profile']
            if endpoint['origin'] != origin:
                fail()
            connection._create_connection = lambda _address,timeout,*_: socket.create_connection(
                (endpoint['bind'],url.port),timeout)
        connection.connect()
        certificate = digest(connection.sock.getpeercert(binary_form=True))
        if retained is not None:
            retained.verify()
            if certificate != retained.facts['certificateSha256']:
                fail()
        headers = {'Host': url.netloc, 'Connection': 'close'}
        if probe is not None:
            headers['X-Orbis-Sentinel-Return-Probe'] = encoded(probe).hex()
        if cookie is not None:
            headers['Cookie'] = cookie
        if document is None:
            connection.request('GET', path, headers=headers)
        else:
            headers.update({'Origin': origin, 'Content-Type': 'application/json'})
            connection.request('POST', path, body=encoded(document), headers=headers)
        response = connection.getresponse()
        pairs = response.getheaders()
        singletons = ('content-length', 'transfer-encoding', 'content-type', 'cache-control',
                      'content-security-policy', 'x-content-type-options')
        metadata = {}
        for key, value in pairs:
            key = key.lower()
            if key in singletons:
                if key in metadata:
                    fail()
                metadata[key] = value
        body = response.read(65537)
        size, transfer = metadata.get('content-length'), metadata.get('transfer-encoding')
        from .recovery_gateway import CSP
        if (len(body) > 65536 or sum(len(name) + len(value) for name, value in pairs) > 16384
                or (size is not None and (size != str(len(body)) or transfer is not None))
                or (size is None and transfer != 'chunked')
                or metadata.get('content-type') != content_type
                or metadata.get('cache-control') != 'no-store'
                or metadata.get('content-security-policy') != CSP
                or metadata.get('x-content-type-options') != 'nosniff'
                or response.getheader('Location') is not None or response.getheader('Content-Encoding') is not None):
            fail()
        return response.status, body, pairs, certificate


def _binding_cookie(pairs):
    seen = set()
    binding = None
    for name, value in pairs:
        if name.lower() != 'set-cookie':
            continue
        jar = SimpleCookie()
        jar.load(value)
        if len(jar) != 1:
            fail()
        item = next(iter(jar.values()))
        if (item.key in seen or item['path'] != '/' or item['domain'] or not item['secure']
                or item['samesite'] != 'Strict'):
            fail()
        seen.add(item.key)
        if item.key == '__Host-orbis-sentinel-binding':
            if not item['httponly'] or not re.fullmatch(r'[A-Za-z0-9_-]{43}', item.value):
                fail()
            binding = item.value
        elif (item.key not in ('__Host-orbis-sentinel-session', '__Host-orbis-sentinel-csrf')
              or item.value or item['max-age'] != '0'):
            fail()
    if binding is None:
        fail()
    return binding


def signed_out_https(origin, asset_sha, *, context=None, retained=None):
    """Credential-free proof of the exact signed-out route through trusted TLS."""
    from .recovery_gateway import API, ASSETS as PREFIX, BASE, _ASSETS as TYPES
    context = ssl.create_default_context() if context is None else context
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        fail()
    options = {'retained':retained} if retained is not None else {}
    status, landing, headers, certificate = _tls_get(origin, context, BASE + '/', 'text/html; charset=utf-8',**options)
    if status != 200 or digest(landing) != asset_sha['recovery.html']:
        fail()
    binding = _binding_cookie(headers)
    cookie = '__Host-orbis-sentinel-binding=' + binding
    paths = [(PREFIX + name, TYPES[name], 200, asset_sha[name]) for name in ASSETS[1:]]
    json_type = 'application/json; charset=utf-8'
    paths.extend(((API + '/session', json_type, 200, digest(b'{"authenticated":false}')),
                  (API + '/options', json_type, 401, digest(b'{"error":"Sign-in could not be completed. Try again."}'))))
    for path, content_type, expected_status, expected_sha in paths:
        observed, body, pairs, peer = _tls_get(origin, context, path, content_type, cookie,**options)
        if (observed != expected_status or digest(body) != expected_sha or peer != certificate
                or any(name.lower() == 'set-cookie' for name, _ in pairs)):
            fail()
    return {'bindingSha256': digest(binding.encode('ascii')), 'certificateSha256': certificate}


def https_child():
    """Internal held-launcher probe. Selection comes only from the fixed setup files."""
    from .collector_execution import _root
    from .recovery_gateway import _asset
    _root()
    assets = {name: digest(_asset(name)) for name in ASSETS}
    with (RecoveryConfig(RECOVERY_CONFIG) as config, closing(publisher._Pins()) as pins):
        marker = _read_fixed(pins,SETUP_CONFIG,0o600)
        if _canonical(marker).get('schema') == BUILTIN_MARKER:
            with _probe_edge(config,marker) as edge:
                result = signed_out_https(config.data['origin'],assets,context=edge.context(),retained=edge)
                config.verify()
                pins.verify()
        else:
            with setup_profile(config,RECOVERY_CONFIG) as setup:
                if setup is None:
                    fail()
                result = signed_out_https(setup.origin,assets)
                setup.verify()
        return {**result,'assetSha256':assets}


def _review_binding(review):
    return listener_review_binding(review)


def read_setup_receipt(directory, review, *, marker_sha=None, setup=None):
    """Read same-installation setup evidence without entering the writer or store."""
    binding = _review_binding(review)
    operation = _operation_id(binding)
    with (PrivateDirectory(directory) as root, PrivateFile(root, RECEIPT_FILE, 32768) as pinned,
          PrivateDirectory(Path(review['captureRoot']).parent) as namespace,
          _subdirectory(namespace, OPERATIONS) as operations, _subdirectory(operations, operation) as journal,
          PrivateFile(journal, 'review.json', 65536) as reviewed, PrivateFile(journal, 'approval.json', 16384) as approved,
          PrivateFile(journal, 'intent.json', 32768) as intent_source):
        value = _canonical(pinned.body)
        plan = _canonical(reviewed.body)
        approval_sha = digest(approved.body)
        review_sha = digest(reviewed.body)
        if plan.get('schema') == BUILTIN_PLAN:
            return _read_builtin_terminal(root,namespace,journal,review,
                (pinned,reviewed,approved,intent_source),plan,setup=setup,marker_sha=marker_sha)
        if (builtin_setup_required() or plan['schema'] != PLAN or plan['operationId'] != operation
                or _read(journal, '.intent.json.pending', optional=True) is not None
                or any(plan[key] != item for key, item in binding.items())):
            fail()
        _approval(_canonical(approved.body), plan, review_sha)
        intent = _intent(intent_source.body, _operation(plan, review_sha, approval_sha), plan)
        if (set(value) != set(binding).union(('schema', 'operationId', 'reviewSha256', 'approvalSha256', 'markerSha256',
                                             'workerReceiptSha256', 'recovery', 'storage', 'certificateSha256', 'assetSha256'))
                or value['schema'] != RECEIPT
                or intent['phase'] != 'complete' or _result(plan, intent) != value
                or value['recovery'] != review['recovery'] or value['storage'] != review['storage']['recovery']
                or (marker_sha is not None and value['markerSha256'] != marker_sha)
                or any(not hash_value(value[key]) for key in ('operationId', 'reviewSha256', 'approvalSha256', 'markerSha256',
                                                              'workerReceiptSha256', 'certificateSha256'))):
            fail()
        _validate_assets(value['assetSha256'])
        for item, parent in ((pinned, root), *((item, journal) for item in (reviewed, approved, intent_source))):
            item.verify()
            if mount_id(item.fd) != mount_id(parent.fd):
                fail()
        return value


def _validate_assets(value):
    if (type(value) is not dict or set(value) != set(ASSETS)
            or any(not hash_value(item) for item in value.values())):
        fail()


def _worker_review(plan):
    return {**plan['scope'], 'publisher': plan['publication'], 'main': plan['main'], 'runtime': plan['runtime'],
            'hostHistorySha256': plan['historySha256'], 'previousAdmissionSha256': plan['configSha256'],
            'storage': plan['storage']}


def _proxy_stopped(docker, scope):
    """Use a positively identified stopped stock proxy and verify no running maintenance responder."""
    proxy = decode(docker.run(['inspect', '--format', '{{json .}}', 'runtipi-reverse-proxy'], limit=2 * 1024 * 1024))
    labels = proxy['Config'].get('Labels') or {}
    state = proxy['State']
    if (not hash_value(proxy['Id']) or proxy['Name'] != '/runtipi-reverse-proxy'
            or labels.get('com.docker.compose.service') != 'runtipi-reverse-proxy'
            or labels.get('com.docker.compose.project') != 'runtipi'
            or labels.get('com.docker.compose.project.working_dir') != scope['root']
            or any(state[key] is not False for key in ('Running', 'Paused', 'Restarting', 'Dead'))
            or type(state['Pid']) is not int or state['Pid'] != 0 or state['Status'] not in ('created', 'exited')
            or docker.run(['ps', '--no-trunc', '--filter', 'label=io.orbis.restore.role=responder',
                           '--format', '{{.ID}}'], limit=4096).strip()):
        fail()
    return proxy['Id']


def _make_protected_directory(path, *, private):
    with closing(publisher._Pins()) as pins:
        parent = pins.directory(path.parent)
        pins.verify()
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        pins.directory(path, 0o700 if private else None)
        pins.verify()


def _service_run(product, args, *, allowed=(0,)):
    return product._run(['/usr/bin/systemctl', *args], maximum=32768, allowed=allowed,
                        environment={'PATH': '/usr/bin:/bin', 'LANG': 'C'})


def _status(product):
    fields = ('LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload',
              'MainPID', 'ControlPID', 'UnitFileState')
    body = _service_run(product, ('show', '--no-pager', '--all', *('--property=' + field for field in fields), product.UNIT),
                        allowed=(0, 4))
    values = {}
    for line in body.decode('utf8').splitlines():
        field, sep, value = line.partition('=')
        if not sep or field in values:
            fail()
        values[field] = value
    if set(values) != set(fields) or values['DropInPaths']:
        fail()
    return values


def _inactive_profile(product, plan):
    effective = product._systemd(product.UNIT, effective_recovery=True)
    required = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead',
                'FragmentPath': str(floor.RECOVERY_UNIT), 'DropInPaths': '', 'NeedDaemonReload': 'no',
                'ControlPID': '0', 'MainPID': '0', 'KillMode': 'control-group', 'User': 'root', 'Group': 'root',
                'ProtectHome': 'yes', 'ProtectProc': 'invisible', 'ProtectSystem': 'strict',
                'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': ''}
    literal = (str(product.RECOVERY_INTERPRETER) + ' -I ${ORBIS_SENTINEL_RECOVERY_RUNTIME}'
               ' --recovery-profile ${ORBIS_SENTINEL_RECOVERY_PROFILE}')
    expanded = f"{product.RECOVERY_INTERPRETER} -I {plan['launch']} --recovery-profile {RECOVERY_CONFIG}"
    start = re.fullmatch(r'\{ path=([^ ;]+) ; argv\[\]=(.+?) ; ignore_errors=no(?: ; [^{}]*)? \}',
                         effective.get('ExecStart', ''))
    if (any(effective.get(key) != value for key, value in required.items()) or start is None
            or start[1] != str(product.RECOVERY_INTERPRETER) or start[2] not in (literal, expanded)):
        fail()


def _new_listener_footprint(product, port):
    with closing(publisher._Pins()) as pins:
        states = ((SETUP_CONFIG, 0o600), (RECOVERY_CONFIG, 0o600), (floor.RECOVERY_ENV, 0o600), (floor.RECOVERY_UNIT, 0o644))
        for path, mode in states:
            if any(_read_fixed(pins, target, mode, optional=True) is not None
                   for target in (path, path.with_name('.' + path.name + '.pending'))):
                fail()
        pins.verify()
    if os.path.lexists(floor.RECOVERY_ROOT):
        with PrivateDirectory(floor.RECOVERY_ROOT) as directory:
            if os.listdir(directory.fd):
                fail()
    status = _status(product)
    if (status['LoadState'] != 'not-found' or status['ActiveState'] != 'inactive' or status['SubState'] != 'dead'
            or status['FragmentPath'] or status['MainPID'] != '0' or status['ControlPID'] != '0'
            or status['NeedDaemonReload'] != 'no' or status['UnitFileState'] not in ('', 'not-found')):
        fail()
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', port))


def _approval(value, plan, review_sha):
    if (value != {'schema': APPROVAL, 'operationId': plan['operationId'], 'installationId': plan['scope']['installationId'],
                  'reviewSha256': review_sha, 'approvalId': value.get('approvalId')}
            or not hash_value(value['approvalId'])):
        fail()


def _operation(plan, review_sha, approval_sha):
    return {'schema': INTENT, 'operationId': plan['operationId'], 'installationId': plan['scope']['installationId'],
            'reviewSha256': review_sha, 'approvalSha256': approval_sha}


def _operation_id(plan):
    return digest(encoded([PLAN, plan['publication']['operationId'], plan['scope']['installationId']]))


def _result(plan, intent):
    fields = ('scope', 'publication', 'main', 'runtime', 'historySha256', 'admissionSha256',
              'workerReceiptSha256', 'assetSha256', 'markerSha256')
    return {**{key: plan[key] for key in fields}, 'schema': RECEIPT, 'operationId': plan['operationId'],
            'reviewSha256': intent['reviewSha256'], 'approvalSha256': intent['approvalSha256'],
            'recovery': intent['recovery'], 'storage': intent['storage'],
            'certificateSha256': intent['certificateSha256']}


def _recovery_binding(plan, evidence):
    if (type(evidence) is not dict or set(evidence) != {'configSha256', 'environmentSha256', 'unitSha256', 'effectiveSha256', 'process'}
            or any(evidence[key] != plan[key] for key in ('configSha256', 'environmentSha256', 'unitSha256'))
            or not hash_value(evidence['effectiveSha256'])):
        fail()
    process = evidence['process']
    if (type(process) is not dict or set(process) != {'pid', 'startTicks', 'invocationId', 'executableIdentity'}
            or any(type(process[key]) is not int or process[key] <= 0 for key in ('pid', 'startTicks'))
            or type(process['invocationId']) is not str or not re.fullmatch(r'[a-f0-9]{32}', process['invocationId'])
            or type(process['executableIdentity']) is not list or len(process['executableIdentity']) != 2
            or any(type(value) is not int or value <= 0 for value in process['executableIdentity'])):
        fail()


def _intent(body, base, plan):
    value = _canonical(body)
    extra = ('phase', 'recovery', 'storage', 'certificateSha256')
    if (set(value) != set(base).union(extra) or any(value[key] != item for key, item in base.items())
            or value['phase'] not in PHASES):
        fail()
    phase = PHASES.index(value['phase'])
    if phase < PHASES.index('running'):
        if value['recovery'] is not None or value['storage'] is not None:
            fail()
    else:
        _recovery_binding(plan, value['recovery'])
        if type(value['storage']) is not dict:
            fail()
    if phase >= PHASES.index('qualified'):
        if not hash_value(value['certificateSha256']):
            fail()
    elif value['certificateSha256'] is not None:
        fail()
    return value


class ListenerInstall:
    def __init__(self, verify_package):
        self.verify_package = verify_package

    @contextmanager
    def _scope(self, publication_id, publication_sha, worker_sha, port, builtin=None):
        if (not hash_value(worker_sha) or type(port) is not int or not 1024 <= port <= 65535
                or builtin is not None and (type(builtin) is not tuple or len(builtin) != 2
                                           or not all(hash_value(value) for value in builtin))):
            fail()
        with (WorkerProvision(self.verify_package)._scope(publication_id, publication_sha) as
              (namespace, admission, product, guard, source, docker, verify), closing(publisher._Pins()) as pins,
              ExitStack() as resources):
            worker_review = _worker_review(source)
            worker = require_retained_worker(namespace, worker_review, docker, receipt_sha256=worker_sha)
            proxy = _proxy_stopped(docker, source['scope'])
            with admission.supervisor._held_runtime(storage_floor=True) as (runtime, modules, check_runtime):
                root = publisher.ROOT / 'releases' / runtime['version']
                launcher = root / 'bin' / 'orbis-sentinel'
                unit = _read_fixed(pins, root / 'packaging' / 'systemd' / product.UNIT, 0o644)
                if (runtime != source['runtime'] or digest(unit) != product.UNIT_SHA256
                        or (product.RECOVERY_CONFIG, product.RECOVERY_ENV, product.UNITS / product.UNIT) !=
                        (RECOVERY_CONFIG, floor.RECOVERY_ENV, floor.RECOVERY_UNIT)):
                    fail()
                assets = {name: digest(_read_fixed(pins, root / 'web' / name, 0o644, maximum=65536)) for name in ASSETS}
                environment = (f'ORBIS_SENTINEL_RECOVERY_RUNTIME={launcher}\n'
                               f'ORBIS_SENTINEL_RECOVERY_PROFILE={RECOVERY_CONFIG}\n').encode()
                config = {'schema': 'orbis.sentinel-recovery-config.v1', 'origin': source['scope']['origin'],
                          'directory': str(floor.RECOVERY_ROOT), 'imageId': source['imageId'], 'listenPort': port,
                          'statusSocket': STATUS_SOCKET}
                RecoveryConfig._validate(config)
                config_body = encoded(config)
                operation = _operation_id(source)
                marker_value = {'schema':MARKER,'operationId':operation,'installationId':source['scope']['installationId'],
                                'configSha256':digest(config_body),'origin':config['origin']}
                transport = {}
                if builtin is not None:
                    from .recovery_backend_tls import MODE, retained_origin
                    origin, recheck_origin = resources.enter_context(retained_origin(namespace,admission,product,source,*builtin))
                    pair = digest(encoded([MODE,operation,origin,source['publication'],worker_sha,runtime,port,
                                           digest(config_body)]))
                    marker_value.update(schema=BUILTIN_MARKER,transport={'mode':MODE,'pairId':pair})
                    transport = {'transport':{**marker_value['transport'],'origin':origin}}
                marker = encoded(marker_value)
                public_fields = ('scope', 'publication', 'main', 'runtime', 'historySha256')
                plan = {**{key:source[key] for key in public_fields}, 'schema':BUILTIN_PLAN if transport else PLAN,
                        'operationId':operation, **transport,
                        'workerReceiptSha256': worker_sha, 'workerCapabilitySha256': worker['capabilitiesSha256'],
                        'admissionSha256': source['configSha256'], 'proxyContainerId': proxy, 'listenPort': port,
                        'launch': str(launcher), 'unitSha256': digest(unit), 'environmentSha256': digest(environment),
                        'configSha256': digest(config_body), 'markerSha256': digest(marker), 'assetSha256': assets}
                files = ((SETUP_CONFIG, marker, 0o600), (RECOVERY_CONFIG, config_body, 0o600),
                         (floor.RECOVERY_UNIT, unit, 0o644), (floor.RECOVERY_ENV, environment, 0o600))

                def check():
                    verify()
                    check_runtime()
                    pins.verify()
                    if builtin is not None:
                        recheck_origin()
                    if (require_retained_worker(namespace, worker_review, docker, receipt_sha256=worker_sha) != worker
                            or _proxy_stopped(docker, source['scope']) != proxy):
                        fail()

                check()
                yield namespace, admission, product, guard, plan, modules, files, check
                check()

    def review(self, publication, publication_sha, worker_sha, port, builtin=None):
        with self._scope(publication, publication_sha, worker_sha, port, builtin) as (namespace, admission, product, guard, plan, _, _, check):
            if guard.read() is not None:
                fail()
            _new_listener_footprint(product, port)
            with (_subdirectory(namespace, OPERATIONS, create=True) as operations,
                  _subdirectory(operations, plan['operationId'], create=True) as directory):
                body = encoded(plan)
                existing = _read(directory, 'review.json', optional=True)
                check()
                if existing is None:
                    if any(os.path.lexists(directory.path / name) for name in ('approval.json', 'intent.json')):
                        fail()
                    WorkerProvision._write(product, admission, directory, 'review.json', body, None)
                elif existing != body:
                    fail()
                return {'phase': 'listener-awaits-approval', 'operationId': plan['operationId'], 'reviewSha256': digest(body)}

    def prepare_backend(self, publication, publication_sha, worker_sha, port, review_sha, approval_sha, builtin):
        from .recovery_backend_tls import prepare_pair, require_fresh

        if builtin is None or not all(hash_value(value) for value in (review_sha,approval_sha)):
            fail()
        with (self._scope(publication,publication_sha,worker_sha,port,builtin) as
              (namespace,admission,product,guard,plan,_,_,check_scope),
              _subdirectory(namespace,OPERATIONS) as operations,
              _subdirectory(operations,plan['operationId']) as directory,
              PrivateFile(directory,'review.json',65536) as reviewed,
              PrivateFile(directory,'approval.json',16384) as approved):
            if (plan['schema'] != BUILTIN_PLAN or reviewed.body != encoded(plan) or digest(reviewed.body) != review_sha
                    or digest(approved.body) != approval_sha
                    or any(mount_id(item.fd) != mount_id(directory.fd) for item in (reviewed,approved))):
                fail()
            _approval(_canonical(approved.body),plan,review_sha)
            base = {**_operation(plan,review_sha,approval_sha),'schema':BUILTIN_INTENT,
                    'pairId':plan['transport']['pairId']}
            absent = {**base,'phase':'intent','pairSha256':None}

            def pinned():
                check_scope()
                reviewed.verify()
                approved.verify()
                _new_listener_footprint(product,port)

            def check():
                guard.check(plan['operationId'],review_sha)
                pinned()

            before = _read(directory,'intent.json',optional=True)
            pending = _read(directory,'.intent.json.pending',optional=True)
            if before is None:
                held = guard.read()
                if held is not None:
                    guard.check(plan['operationId'],review_sha)
                if pending is not None and (held is None or pending != encoded(absent)):
                    fail()
                pinned()
                require_fresh(base['pairId'])
                guard.begin(plan['operationId'],review_sha)
                before = encoded(absent)
                WorkerProvision._write(product,admission,directory,'intent.json',before,None)
                pending = None
            intent = _canonical(before)
            if (intent != absent and (intent != {**base,'phase':'backend-prepared','pairSha256':intent.get('pairSha256')}
                                      or not hash_value(intent['pairSha256']))):
                fail()
            expected = intent['pairSha256']
            if pending is not None:
                staged = _canonical(pending)
                if (intent['phase'] != 'intent'
                        or staged != {**base,'phase':'backend-prepared','pairSha256':staged.get('pairSha256')}
                        or not hash_value(staged['pairSha256'])):
                    fail()
                expected = staged['pairSha256']
            check()
            pair_sha = prepare_pair(plan,intent,check,expected_sha=expected)
            terminal = encoded({**base,'phase':'backend-prepared','pairSha256':pair_sha})
            if pending is not None and pending != terminal or intent['phase'] == 'backend-prepared' and before != terminal:
                fail()
            if before != terminal:
                check()
                WorkerProvision._write(product,admission,directory,'intent.json',terminal,before)
            check()
            if _read(directory,'intent.json') != terminal or _read(directory,'.intent.json.pending',optional=True) is not None:
                fail()
            return {'operationId':plan['operationId'],'phase':'backend-prepared','pairSha256':pair_sha}

    def apply_builtin(self, publication, publication_sha, worker_sha, port, review_sha, approval_sha, builtin):
        from .recovery_backend_tls import held_prepared_pair
        from .recovery_https_install import (EdgeAttachment,STATE,_worker_identity,boot_identity,held_public_edge,
                                             socket_identity)

        if builtin is None or not all(hash_value(sha) for sha in (review_sha,approval_sha)):
            fail()
        with (self._scope(publication,publication_sha,worker_sha,port,builtin) as observed,
              ExitStack() as resources):
            namespace,admission,product,guard,plan,modules,files,check_scope = observed
            operations = resources.enter_context(_subdirectory(namespace,OPERATIONS))
            journal = resources.enter_context(_subdirectory(operations,plan['operationId']))
            reviewed = resources.enter_context(PrivateFile(journal,'review.json',65536))
            approved = resources.enter_context(PrivateFile(journal,'approval.json',16384))
            if (plan['schema'] != BUILTIN_PLAN or reviewed.body != encoded(plan) or digest(reviewed.body) != review_sha
                    or digest(approved.body) != approval_sha or any(
                        mount_id(item.fd) != mount_id(journal.fd) for item in (reviewed,approved))):
                fail()
            _approval(_canonical(approved.body),plan,review_sha)
            base = _builtin_plan_intent(plan,reviewed.body,approved.body)
            before = _read(journal,'intent.json')
            intent = _v2_intent(before,base,plan)
            if guard.read() is None:
                if intent['phase'] != 'complete':
                    fail()
                result = read_setup_receipt(floor.RECOVERY_ROOT,_readback_review(plan,intent,namespace))
                check_scope()
                return {'phase':'listener-verified','operationId':base['operationId'],'receiptSha256':digest(encoded(result))}

            def approved_scope():
                check_scope()
                reviewed.verify()
                approved.verify()

            owner = SetupOwner(_SETUP_OWNER_KEY,guard,base,approved_scope)
            pending_body = _read(journal,'.intent.json.pending',optional=True)
            pending = _v2_intent(pending_body,base,plan) if pending_body is not None else None
            if pending is not None and BUILTIN_STEPS.index(pending['phase']) != BUILTIN_STEPS.index(intent['phase'])+1:
                fail()
            pair = resources.enter_context(held_prepared_pair(plan,intent))
            edge_root = resources.enter_context(PrivateDirectory(STATE))
            fcntl.flock(edge_root.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            public = resources.enter_context(held_public_edge(plan['transport']['origin']['publicEdge'],
                                                              base['installationId'],self.verify_package))
            config = public.request['profile']
            if (config['upstreamPort'] != port or config['origin'] != plan['scope']['origin']
                    or public.package['binding']['packageSha256'] != plan['runtime']['artifactSha256']):
                fail()
            attachment = EdgeAttachment(pair.envelope(digest(encoded(config)),public.facts['certificateSha256']),public,edge_root)
            system = _edge_system()

            def authorize():
                owner.check()
                pair.verify()
                public.verify()
                edge_root.verify()

            def advance(phase, **updates):
                nonlocal before,intent,pending
                authorize()
                candidate = {**intent,'phase':phase,**updates}
                body = encoded(candidate)
                if (BUILTIN_STEPS.index(phase) != BUILTIN_STEPS.index(intent['phase'])+1
                        or pending is not None and pending != candidate or _v2_intent(body,base,plan) != candidate):
                    fail()
                WorkerProvision._write(product,admission,journal,'intent.json',body,before)
                before,intent,pending = body,candidate,None

            if intent['phase'] == 'backend-prepared':
                status = _status(product)
                if status['ActiveState'] != 'inactive' or status['MainPID'] != '0' or status['ControlPID'] != '0':
                    fail()
                authorize()
                _make_protected_directory(SETUP_CONFIG.parent,private=False)
                _make_protected_directory(floor.RECOVERY_ROOT,private=True)
                for path,body,mode in files:
                    authorize()
                    _new_file(path,body,mode)
                advance('configured')
            fixed = resources.enter_context(_listener_files(files))
            if intent['phase'] == 'configured':
                authorize()
                _service_run(product,('daemon-reload',))
                _inactive_profile(product,plan)
                advance('starting')
            if intent['phase'] == 'starting':
                current = _status(product)['ActiveState']
                if current == 'inactive':
                    authorize()
                    fixed()
                    _inactive_profile(product,plan)
                    _service_run(product,('start',product.UNIT))
                elif current != 'active':
                    fail()
            recovery, check_recovery = resources.enter_context(admission.supervisor.bootstrap_recovery(
                plan['scope']['origin'],plan['main'],plan['runtime'],modules,builtin_marker_sha=plan['markerSha256']))
            _recovery_binding(plan,recovery)
            root = resources.enter_context(PrivateDirectory(floor.RECOVERY_ROOT))
            role = storage.observe(root)

            def listener_live():
                authorize()
                fixed()
                check_recovery()
                root.verify()
                storage.verify_role('recovery',root,role)
                return {'recovery':recovery,'storage':role,'boot':boot_identity(),
                        'listenerSocket':socket_identity(recovery['process']['pid'],'127.0.0.1',port)}

            listener_observed = listener_live()
            if intent['phase'] == 'starting':
                advance('running',**listener_observed)
            if any(intent[key] != value for key,value in listener_observed.items()):
                fail()

            if intent['phase'] == 'running':
                # The sole listener and its Root control socket must already
                # be the same live process before enabling any edge relay.
                client = _root_probe_client(plan,recovery,listener_live)
                with client._connection():
                    listener_live()
                before_edge = system.loaded(public.package,public.request,socket_active=True)
                observed_edge = _worker_identity(before_edge,public.package['launcher'])
                before_pid, before_invocation, before_ticks = observed_edge
                public.probe()
                if _worker_identity(system.loaded(public.package,public.request,socket_active=True),
                                    public.package['launcher']) != observed_edge:
                    fail()
                advance('attaching',attachment=attachment.value(),previousEdge=[int(before_pid),before_invocation,int(before_ticks)])
            if intent['attachment'] != attachment.value():
                fail()
            if intent['phase'] == 'attaching':
                attachment.install(system,authorize)
                current = _start_edge(attachment,intent,authorize)
                advance('attached',edge=current)
            if _existing_rollback(journal,root,attachment,intent,owner):
                return {'phase':'listener-edge-rolled-back','operationId':base['operationId']}

            def live():
                if listener_live() != listener_observed or attachment.observe(system) != intent['edge']:
                    fail()
                public.probe()

            live()
            if intent['phase'] == 'attached':
                paired = _prove_attempt(journal,plan,intent,live)
                _new_file(root.path/PAIRED_FILE,encoded(paired),0o600)
                advance('paired',pairedSha256=digest(encoded(paired)))
            paired = _canonical(_read(root,PAIRED_FILE))
            _read_attempt(journal,plan,intent,paired)
            if digest(encoded(paired)) != intent['pairedSha256']:
                fail()
            result = _v2_result(plan,intent,paired)
            if intent['phase'] == 'paired':
                live()
                _new_file(root.path/RECEIPT_FILE,encoded(result),0o600)
                if _status(product)['UnitFileState'] == 'disabled':
                    authorize()
                    _service_run(product,('enable',product.UNIT))
                if _status(product)['UnitFileState'] != 'enabled':
                    fail()
                live()
                advance('complete')
            if intent['phase'] != 'complete' or _status(product)['UnitFileState'] != 'enabled':
                fail()
            owner.finish(root,journal,plan,intent,before,paired,result,live)
            terminal = read_setup_receipt(root.path,_readback_review(plan,intent,namespace))
            if terminal != result:
                fail()
            return {'phase':'listener-verified','operationId':base['operationId'],'receiptSha256':digest(encoded(result))}

    def apply(self, publication, publication_sha, worker_sha, port, review_sha, approval_sha):
        if not hash_value(review_sha) or not hash_value(approval_sha):
            fail()
        with (self._scope(publication, publication_sha, worker_sha, port) as
              (namespace, admission, product, guard, plan, modules, files, check_scope),
              _subdirectory(namespace, OPERATIONS) as operations, _subdirectory(operations, plan['operationId']) as directory,
              PrivateFile(directory, 'review.json', 65536) as approved_review,
              PrivateFile(directory, 'approval.json', 16384) as approved):
            if (approved_review.body != encoded(plan) or digest(approved_review.body) != review_sha
                    or digest(approved.body) != approval_sha
                    or any(mount_id(item.fd) != mount_id(directory.fd) for item in (approved_review, approved))):
                fail()
            _approval(_canonical(approved.body), plan, review_sha)
            base = _operation(plan, review_sha, approval_sha)
            op = base['operationId']

            def check():
                check_scope()
                approved_review.verify()
                approved.verify()

            previous = _read(directory, 'intent.json', optional=True)
            staged = _read(directory, '.intent.json.pending', optional=True)
            owned = guard.read() is not None
            if owned:
                guard.check(op, review_sha)
            if previous is None:
                check()
                _new_listener_footprint(product, port)
                intent = {**base, 'phase': 'intent', 'recovery': None, 'storage': None, 'certificateSha256': None}
                if staged is not None and (not owned or staged != encoded(intent)):
                    fail()
                guard.begin(op, review_sha)
                previous = encoded(intent)
                WorkerProvision._write(product, admission, directory, 'intent.json', previous, None)
                staged = None
            else:
                intent = _intent(previous, base, plan)
                if not owned and intent['phase'] != 'complete':
                    fail()
            pending = _intent(staged, base, plan) if staged is not None else None
            if pending is not None and PHASES.index(pending['phase']) != PHASES.index(intent['phase']) + 1:
                fail()

            def advance(phase, **updates):
                nonlocal previous, intent, pending
                guard.check(op, review_sha)
                check()
                candidate = {**intent, 'phase': phase, **updates}
                body = encoded(candidate)
                if (PHASES.index(phase) != PHASES.index(intent['phase']) + 1
                        or (pending is not None and candidate != pending)):
                    fail()
                _intent(body, base, plan)
                WorkerProvision._write(product, admission, directory, 'intent.json', body, previous)
                previous, intent, pending = body, candidate, None

            if intent['phase'] == 'intent':
                _make_protected_directory(SETUP_CONFIG.parent, private=False)
                _make_protected_directory(floor.RECOVERY_ROOT, private=True)
                for path, body, mode in files:
                    guard.check(op, review_sha)
                    check()
                    _new_file(path, body, mode)
                advance('configured')

            with closing(publisher._Pins()) as pins:
                for path, body, mode in files:
                    if _read_fixed(pins, path, mode) != body:
                        fail()
                pins.verify()

                if intent['phase'] == 'configured':
                    guard.check(op, review_sha)
                    check()
                    _service_run(product, ('daemon-reload',))
                    _inactive_profile(product, plan)
                    advance('starting')
                if intent['phase'] == 'starting':
                    status = _status(product)
                    if status['ActiveState'] == 'inactive':
                        guard.check(op, review_sha)
                        check()
                        pins.verify()
                        _inactive_profile(product, plan)
                        _service_run(product, ('start', product.UNIT))
                    elif status['ActiveState'] != 'active':
                        fail()

                supervisor = admission.supervisor
                with (supervisor.bootstrap_recovery(plan['scope']['origin'], plan['main'], plan['runtime'], modules)
                      as (observed, check_recovery), PrivateDirectory(floor.RECOVERY_ROOT) as recovery_directory):
                    _recovery_binding(plan, observed)
                    role = storage.observe(recovery_directory)
                    if intent['phase'] == 'starting':
                        advance('running', recovery=observed, storage=role)

                    def live():
                        check()
                        check_recovery()
                        pins.verify()
                        recovery_directory.verify()
                        if (intent['recovery'], intent['storage']) != (observed, role):
                            fail()
                        storage.verify_role('recovery', recovery_directory, role)

                    live()
                    if intent['phase'] == 'running':
                        certificate = pending['certificateSha256'] if pending is not None else _prove(plan, observed, live)
                        advance('qualified', certificateSha256=certificate)
                    result = _result(plan, intent)
                    result_body = encoded(result)
                    receipt_path = recovery_directory.path / RECEIPT_FILE

                    def terminal():
                        live()
                        with PrivateFile(recovery_directory, RECEIPT_FILE, 32768) as pinned:
                            return pinned.body == result_body and mount_id(pinned.fd) == mount_id(recovery_directory.fd)

                    if intent['phase'] == 'qualified':
                        guard.check(op, review_sha)
                        live()
                        _new_file(receipt_path, result_body, 0o600)
                        state = _status(product)['UnitFileState']
                        if state == 'disabled':
                            _service_run(product, ('enable', product.UNIT))
                        elif state != 'enabled':
                            fail()
                        if _status(product)['UnitFileState'] != 'enabled' or not terminal():
                            fail()
                        advance('complete')
                    if intent['phase'] != 'complete' or _status(product)['UnitFileState'] != 'enabled' or not terminal():
                        fail()
                    guard.finish(op, review_sha, verify_completed=terminal)
                    return {'phase': 'listener-verified', 'operationId': op, 'receiptSha256': digest(result_body)}


def _root_probe_client(plan, observed, check):
    from .bootstrap_control import RootBootstrapControlClient
    from .writer_control import WriterControlClient
    deadline = time.monotonic() + 5
    path = floor.RECOVERY_ROOT / 'bootstrap-control.sock'
    broker = floor.RECOVERY_ROOT / 'control.sock'
    while not (path.is_socket() and broker.is_socket()):
        check()
        if time.monotonic() >= deadline:
            fail()
        time.sleep(0.05)
    check()
    capability = WriterControlClient(str(broker), timeout=8).call('operator-capability', {})
    if digest(encoded(validate_capability(capability))) != plan['workerCapabilitySha256']:
        fail()
    return RootBootstrapControlClient(str(path), timeout=3, expected_pid=observed['process']['pid'])


def _proof_facts(plan, observed, check, *, before_arm=None):
    client = _root_probe_client(plan,observed,check)
    arguments = {'operationId': plan['operationId'], 'markerSha256': plan['markerSha256']}
    if before_arm is not None:
        before_arm()
    arm = client.call('bootstrap-listener-probe-arm', arguments)
    nonce = arm.get('nonce')
    expected = {**arguments, 'nonce': nonce, 'process': observed['process']}
    if not hash_value(nonce) or arm != expected:
        fail()
    tls = _https_process(plan['launch'])
    if set(tls) != {'bindingSha256', 'certificateSha256', 'assetSha256'} or tls['assetSha256'] != plan['assetSha256']:
        fail()
    if any(not hash_value(tls[name]) for name in ('bindingSha256', 'certificateSha256')):
        fail()
    binding = tls['bindingSha256']
    observed_proof = client.call('bootstrap-listener-probe-confirm',
                                 {**arguments, 'nonce': nonce, 'bindingSha256': binding})
    if observed_proof != {**expected, 'bindingSha256': binding}:
        fail()
    check()
    return {'certificateSha256':tls['certificateSha256'],'bindingSha256':binding,
            'nonceSha256':digest(nonce.encode('ascii'))}


def _prove(plan, observed, check):
    return _proof_facts(plan,observed,check)['certificateSha256']


def _https_process(launcher):
    result = subprocess.run(['/usr/bin/python3', '-I', launcher, '--listener-https-probe'],
                            capture_output=True, timeout=12,
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'})
    if result.returncode or result.stderr or not 0 < len(result.stdout) <= 4096:
        fail()
    return decode(result.stdout)


def run(action, publication, publication_sha, worker_sha, port, review, approval, *, verify_package, builtin=None):
    writer = ListenerInstall(verify_package)
    if action == 'review':
        return writer.review(publication, publication_sha, worker_sha, port, builtin)
    if action == 'prepare-backend':
        return writer.prepare_backend(publication,publication_sha,worker_sha,port,review,approval,builtin)
    if action == 'apply-builtin':
        return writer.apply_builtin(publication,publication_sha,worker_sha,port,review,approval,builtin)
    if action == 'apply' and builtin is None:
        return writer.apply(publication, publication_sha, worker_sha, port, review, approval)
    fail()


class SetupOwner:
    """The live v2 writer's concrete owner, never accepted by receipt consumers."""
    def __init__(self, key, guard, base, verify):
        if key is not _SETUP_OWNER_KEY:
            fail()
        self.guard,self.base,self._verify = guard,base,verify
        self.check()

    def check(self):
        self.guard.check(self.base['operationId'],self.base['reviewSha256'])
        self._verify()

    def finish(self, root, journal, plan, intent, terminal, paired, result, live):
        self.check()
        def verified():
            self.check()
            _terminal_files(root,journal,terminal,paired,result)
            live()
            _read_attempt(journal,plan,intent,paired)
            self.check()
            return True
        self.guard.finish(self.base['operationId'],self.base['reviewSha256'],verify_completed=verified)


def _v2_intent(body, base, plan):
    value = _canonical(body)
    phase = value.get('phase')
    if phase not in BUILTIN_STEPS:
        fail()
    rank = BUILTIN_STEPS.index(phase)
    fields = {'phase','pairSha256'}
    if rank >= BUILTIN_STEPS.index('running'):
        fields |= {'recovery','storage','listenerSocket','boot'}
    if rank >= BUILTIN_STEPS.index('attaching'):
        fields |= {'attachment','previousEdge'}
    if rank >= BUILTIN_STEPS.index('attached'):
        fields.add('edge')
    if rank >= BUILTIN_STEPS.index('paired'):
        fields.add('pairedSha256')
    if (set(value) != set(base)|fields or any(value[k] != v for k,v in base.items())
            or not hash_value(value['pairSha256'])):
        fail()
    if 'recovery' in fields:
        _recovery_binding(plan,value['recovery'])
        _socket_record(value['listenerSocket'],'127.0.0.1',plan['listenPort'])
        if type(value['storage']) is not dict or not hash_value(value['boot']):
            fail()
    if 'attachment' in fields:
        edge = value['previousEdge']
        if (type(value['attachment']) is not dict or type(edge) is not list or len(edge) != 3
                or type(edge[0]) is not int or edge[0] <= 0 or type(edge[2]) is not int or edge[2] <= 0
                or type(edge[1]) is not str or not re.fullmatch('[a-f0-9]{32}',edge[1])):
            fail()
    if 'edge' in fields:
        edge = value['edge']
        if (type(edge) is not dict or set(edge) != {'pid','startTicks','invocationId','effectiveSha256','socket'}
                or any(type(edge[k]) is not int or edge[k] <= 0 for k in ('pid','startTicks'))
                or type(edge['invocationId']) is not str or not re.fullmatch('[a-f0-9]{32}',edge['invocationId'])
                or not hash_value(edge['effectiveSha256'])):
            fail()
        _socket_record(edge['socket'],edge['socket']['address'],urlsplit(plan['scope']['origin']).port,fd=3)
    if 'pairedSha256' in fields and not hash_value(value['pairedSha256']):
        fail()
    return value


def _socket_record(value, address, port, *, fd=None):
    if (type(value) is not dict or set(value) != {'inode','fd','address','port'}
            or type(value['inode']) is not int or value['inode'] <= 0
            or type(value['fd']) is not int or value['fd'] < 0 or fd is not None and value['fd'] != fd
            or (value['address'],value['port']) != (address,port)):
        fail()


def _v2_result(plan, intent, paired):
    fields = ('scope','publication','main','runtime','historySha256','admissionSha256','workerReceiptSha256',
              'assetSha256','markerSha256','operationId')
    return {**{k:plan[k] for k in fields},'schema':BUILTIN_RECEIPT,'reviewSha256':intent['reviewSha256'],
            'approvalSha256':intent['approvalSha256'],'recovery':intent['recovery'],'storage':intent['storage'],
            'certificateSha256':paired['proof']['certificateSha256'],'pairedSha256':digest(encoded(paired))}


def _paired_body(plan, intent, proof, attempt):
    fields = ('operationId','installationId','reviewSha256','approvalSha256','pairSha256','recovery','storage',
              'listenerSocket','edge','attachment','boot')
    public = plan['transport']['origin']['publicEdge']
    if (type(proof) is not dict or set(proof) != {'certificateSha256','bindingSha256','nonceSha256'}
            or not all(hash_value(v) for v in proof.values()) or proof['certificateSha256'] != public['certificateSha256']):
        fail()
    return {'schema':PAIRED,**{key:intent[key] for key in fields},'markerSha256':plan['markerSha256'],
            'pairId':plan['transport']['pairId'],'originAdmission':plan['transport']['origin'],
            'publication':plan['publication'],'workerReceiptSha256':plan['workerReceiptSha256'],
            'packageSha256':plan['runtime']['artifactSha256'],'assetSha256':plan['assetSha256'],
            'proof':proof,'attempt':attempt}


def _attempt_name(value):
    if type(value) is not int or not 1 <= value <= 8:
        fail()
    return 'proof-'+str(value)


def _read_attempt(journal, plan, intent, paired):
    attempt = paired.get('attempt')
    with _subdirectory(journal,_attempt_name(attempt)) as scope:
        raw = _read(scope,'proof.json')
        if (_attempt_arm(scope,intent,attempt) is None
                or _read(scope,'.proof.json.pending',optional=True) is not None or raw != encoded(paired)
                or paired != _paired_body(plan,intent,paired['proof'],attempt)
                or _read(scope,'bound.json') != encoded(_attempt_binding(intent,attempt))):
            fail()
        return raw


def _attempt_binding(intent, ordinal):
    return {'schema':'orbis.sentinel-recovery-transport-attempt.v1','operationId':intent['operationId'],
            'reviewSha256':intent['reviewSha256'],'pairSha256':intent['pairSha256'],'boot':intent['boot'],
            'listener':intent['recovery']['process'],'edge':intent['edge'],'attempt':ordinal}


def _attempt_arm(scope, intent, ordinal):
    body = _read(scope,'arm.json',optional=True)
    pending = _read(scope,'.arm.json.pending',optional=True)
    if body is None and pending is None:
        return None
    if body is not None and pending is not None:
        fail()
    binding = _attempt_binding(intent,ordinal)
    value = _canonical(body if body is not None else pending)
    opened = value.get('openedMonotonicNs')
    if (type(opened) is not int or not 0 < opened <= time.monotonic_ns()
            or value != {**binding,'openedMonotonicNs':opened}):
        fail()
    # The protected arm record becomes visible before the RPC may be sent.
    return opened if body is not None else None


def _prove_attempt(journal, plan, intent, check):
    ordinal = 1
    completed = []
    while ordinal <= 8 and os.path.lexists(journal.path/_attempt_name(ordinal)):
        with _subdirectory(journal,_attempt_name(ordinal)) as scope:
            bound = _read(scope,'bound.json',optional=True)
            expected = encoded(_attempt_binding(intent,ordinal))
            body = _read(scope,'proof.json',optional=True)
            partial = _read(scope,'.proof.json.pending',optional=True)
            if bound is None and body is None and partial is None:
                # A crash between mkdir and the immutable initial bound write.
                if set(os.listdir(scope.fd)) - {'.bound.json.pending'}:
                    fail()
                staged = _read(scope,'.bound.json.pending',optional=True)
                if staged not in (None,expected):
                    fail()
                break
            if bound != expected or _read(scope,'.bound.json.pending',optional=True) is not None:
                fail()
            opened = _attempt_arm(scope,intent,ordinal)
            if body is not None:
                value = _canonical(body)
                if opened is None or partial is not None or value != _paired_body(plan,intent,value.get('proof'),ordinal):
                    fail()
                completed.append(value)
            else:
                if partial is not None:
                    value = _canonical(partial)
                    if opened is None or value != _paired_body(plan,intent,value.get('proof'),ordinal):
                        fail()
                # Allow the original RPC budget and the owner observation
                # window to elapse before allocating another attempt.
                if opened is not None and time.monotonic_ns() < opened + int((3 + PROBE_TTL) * 1_000_000_000):
                    fail()
        ordinal += 1
    if len(completed) > 1:
        fail()
    if completed:
        check()
        return completed[0]
    with _subdirectory(journal,_attempt_name(ordinal),create=True) as scope:
        check()
        binding = _attempt_binding(intent,ordinal)
        _new_file(scope.path/'bound.json',encoded(binding),0o600)

        def before_arm():
            check()
            _new_file(scope.path/'arm.json',encoded({**binding,'openedMonotonicNs':time.monotonic_ns()}),0o600)

        proof = _proof_facts(plan,intent['recovery'],check,before_arm=before_arm)
        paired = _paired_body(plan,intent,proof,ordinal)
        check()
        _new_file(scope.path/'proof.json',encoded(paired),0o600)
        return paired


def _terminal_files(root, journal, terminal, paired, result):
    if (_read(journal,'intent.json') != terminal or _read(journal,'.intent.json.pending',optional=True) is not None
            or _read(root,PAIRED_FILE) != encoded(paired) or _read(root,RECEIPT_FILE) != encoded(result)
            or any(_read(root,'.'+name+'.pending',optional=True) is not None for name in (PAIRED_FILE,RECEIPT_FILE))):
        fail()


@contextmanager
def _listener_files(files):
    with closing(publisher._Pins()) as pins:
        for path,body,mode in files:
            if _read_fixed(pins,path,mode) != body:
                fail()
        pins.verify()
        yield pins.verify
        pins.verify()


def _readback_review(plan,intent,namespace):
    scope = plan['scope']
    return {**scope,'publisher':plan['publication'],'main':plan['main'],'runtime':plan['runtime'],
            'hostHistorySha256':plan['historySha256'],'previousAdmissionSha256':plan['admissionSha256'],
            'recovery':intent['recovery'],'storage':{'recovery':intent['storage']},
            'captureRoot':str(namespace.path/'bootstrap-sources')}


def _start_edge(attachment, intent, authorize):
    return attachment.activate(_edge_system(),intent['previousEdge'],authorize)


def _edge_system():
    from .recovery_https_install import EdgeSystem
    return EdgeSystem()


def _builtin_plan_intent(plan, reviewed, approved):
    return {**_operation(plan,digest(reviewed),digest(approved)),'schema':BUILTIN_INTENT,
            'pairId':plan['transport']['pairId']}


@contextmanager
def _probe_edge(config, marker_body, *, live=False):
    from .recovery_https_install import ATTACHMENT,ATTACHMENTS,EdgeAttachment,STATE,held_public_edge

    marker = _canonical(marker_body)
    op = marker.get('operationId')
    if not hash_value(op) or marker.get('configSha256') != digest(encoded(dict(config.data))):
        fail()
    with (PrivateDirectory(STATE) as root,_subdirectory(root,ATTACHMENTS) as attachments,
          _subdirectory(attachments,op) as directory,
          PrivateFile(directory,'public.json',8192) as public,
          PrivateFile(directory,'edge.json',8192) as edge_source):
        reference, packet = _canonical(public.body),_canonical(edge_source.body)
        if (packet['operationId'] != op or packet['origin'] != config.data['origin']
                or packet['pairId'] != marker['transport']['pairId'] or packet['markerSha256'] != digest(marker_body)
                or packet['installationId'] != marker['installationId']):
            fail()
        with held_public_edge(reference,packet['installationId'],lambda:None) as edge:
            attachment = EdgeAttachment(packet,edge,root)
            if _read(root,ATTACHMENT) != encoded(attachment.value()):
                fail()
            attachment.verify_files()
            public.verify()
            edge_source.verify()
            observed = attachment.observe(_edge_system()) if live else None

            def check():
                edge.verify()
                if live and attachment.observe(_edge_system()) != observed:
                    fail()
                attachment.verify_files()
                public.verify()
                edge_source.verify()

            yield (edge, observed, check) if live else edge
            check()


@contextmanager
def held_controller_handoff_portal(config, marker_body, asset_sha):
    """Observe the active, independently attached edge and its sign-in options."""
    from .recovery_gateway import API, ASSETS as PREFIX, BASE, _ASSETS as TYPES

    _validate_assets(asset_sha)
    with _probe_edge(config, marker_body, live=True) as (edge, observed, check_edge):
        origin = config.data['origin']
        context = edge.context()
        status, body, headers, certificate = _tls_get(
            origin, context, BASE + '/', 'text/html; charset=utf-8', retained=edge)
        if status != 200 or digest(body) != asset_sha['recovery.html']:
            fail()
        cookie = '__Host-orbis-sentinel-binding=' + _binding_cookie(headers)
        for name in ASSETS[1:]:
            status, body, headers, peer = _tls_get(origin, context, PREFIX + name, TYPES[name], retained=edge)
            if status != 200 or peer != certificate or digest(body) != asset_sha[name] or any(
                    key.lower() == 'set-cookie' for key, _ in headers):
                fail()
        status, body, headers, peer = _tls_get(
            origin, context, API + '/options', 'application/json; charset=utf-8', cookie, retained=edge)
        options = decode(body)
        if (status != 200 or peer != certificate or any(key.lower() == 'set-cookie' for key, _ in headers)
                or type(options) is not dict or set(options) != {'password', 'recoveryKey', 'passkey', 'totp'}
                or options['password'] is not True or options['recoveryKey'] is not True
                or type(options['passkey']) is not bool or type(options['totp']) is not dict
                or set(options['totp']) != {'password', 'passkey'}
                or any(type(value) is not bool for value in options['totp'].values())):
            fail()
        proof = {'certificateSha256': certificate, 'optionsSha256': digest(body),
                 'attachment': edge.reference, 'invocationId': observed['invocationId']}

        def check():
            check_edge()
            edge.probe()
            check_edge()

        check()
        yield proof, check
        check()


def controller_handoff_portal(config, marker_body, asset_sha):
    """One-shot compatibility reader; transactions use the held witness."""
    with held_controller_handoff_portal(config, marker_body, asset_sha) as (proof, check):
        check()
        return proof


def verify_controller_return_portal(config, marker_body, proof, challenge, arm):
    """Challenge the exact deployed Gateway and its concrete bound return handlers."""
    from .controller_return_readiness import APPROVAL, READINESS, RETURN, readiness_reply
    from .recovery_gateway import API

    with _probe_edge(config, marker_body, live=True) as (edge, observed, check_edge):
        if (edge.reference != proof['attachment'] or observed['invocationId'] != proof['invocationId']
                or edge.facts['certificateSha256'] != proof['certificateSha256']):
            fail()
        origin, context = config.data['origin'], edge.context()

        def read(route, document=None, *, probe=False):
            status, body, headers, certificate = _tls_get(
                origin, context, API + '/' + route, 'application/json; charset=utf-8',
                retained=edge, document=document, **({'probe': challenge} if probe else {}))
            if certificate != proof['certificateSha256'] or any(key.lower() == 'set-cookie' for key, _ in headers):
                fail()
            return status, decode(body)

        check_edge()
        arm()
        for method, route, document in (('GET', 'handoff-status', None), ('POST', APPROVAL, {}), ('POST', RETURN, {})):
            expected = {**readiness_reply(challenge), 'method': method, 'path': API + '/' + route}
            if read(route, document, probe=True) != (200, expected):
                fail()
        if read(READINESS, challenge) != (200, readiness_reply(challenge)):
            fail()
        check_edge()


def builtin_setup_required():
    from .recovery_backend_tls import LISTENER_ROOT
    if os.path.lexists(LISTENER_ROOT):
        return True
    with closing(publisher._Pins()) as pins:
        body = _read_fixed(pins,SETUP_CONFIG,0o600,optional=True)
        pins.verify()
        return body is not None and _canonical(body).get('schema') != MARKER


def _consumer_fence(namespace, review, setup_operation):
    body = _read(namespace,'credential-fence.json',optional=True)
    if _read(namespace,'.credential-fence.json.pending',optional=True) is not None:
        fail()
    if body is not None:
        caller = review.get('operationId')
        if not hash_value(caller) or caller == setup_operation:
            fail()
        expected = {'schema':'orbis.host-credential-fence.v1','root':review['root'],'context':review['context'],
                    'operationId':caller,'admissionBinding':digest(encoded(review))}
        if body != encoded(expected)+b'\n':
            fail()


def _assert_v2_public_files(plan,intent,pins):
    from .recovery_https_install import (ATTACHMENT,ATTACHMENTS,ATTACH_DROPIN,SERVICE,STATE,UNIT_ROOT,
                                        _certificate_sha,_prior_link)
    reference = plan['transport']['origin']['publicEdge']
    op = plan['operationId']
    directory = STATE/ATTACHMENTS/op
    dropin = UNIT_ROOT/(SERVICE+'.d')/ATTACH_DROPIN
    packet = _read_fixed(pins,directory/'edge.json',0o600)
    if (_read_fixed(pins,STATE/ATTACHMENT,0o600) != encoded(intent['attachment'])
            or _read_fixed(pins,directory/'public.json',0o600) != encoded(reference)
            or digest(packet) != intent['attachment']['edgeSha256']
            or digest(_read_fixed(pins,dropin,0o644)) != intent['attachment']['dropinSha256']
            or set(os.listdir(pins.directory(dropin.parent))) != {ATTACH_DROPIN}):
        fail()
    info = _canonical(packet)
    with PrivateDirectory(STATE) as edge:
        if (_prior_link(edge) != reference['generation'] or any(
                _read(edge,name,optional=True) is not None for name in ('.active.pending','writer-fence.json',
                    '.writer-fence.json.pending','.'+ATTACHMENT+'.pending'))):
            fail()
    public_generation = STATE/'generations'/reference['generation']
    public_profile = _read_fixed(pins,public_generation/'profile.json',0o600)
    chain = _read_fixed(pins,public_generation/'chain.pem',0o600,maximum=65536)
    issuer = STATE/'operations'/reference['generation']/'complete.json'
    public_record = _read_fixed(pins,issuer,0o600,maximum=65536)
    certificate = _canonical(public_record)
    now = time.time()
    if (digest(public_record) != reference['receiptSha256'] or certificate['profileSha256'] != reference['profileSha256']
            or certificate['certificateSha256'] != reference['certificateSha256']
            or certificate['chainSha256'] != digest(chain) or type(certificate['leafExpiresAtSec']) is not int
            or certificate['leafExpiresAtSec'] <= now
            or info['profileSha256'] != digest(public_profile) or _certificate_sha(chain) != reference['certificateSha256']
            or info['publicLeafSha256'] != reference['certificateSha256']
            or info['pairSha256'] != intent['pairSha256'] or info['markerSha256'] != plan['markerSha256']
            or info['pairId'] != plan['transport']['pairId'] or info['operationId'] != op
            or type(info['notBeforeSec']) is not int or type(info['notAfterSec']) is not int
            or not info['notBeforeSec'] <= now < info['notAfterSec']):
        fail()
    pins.verify()
    return dropin


def _restricted_live(plan,intent,setup,dropin):
    from .recovery_bootstrap import _receiver_invocation
    from .recovery_https_install import SERVICE,boot_identity
    setup.verify()
    if (setup.backend is None or setup.backend.pair_sha256 != intent['pairSha256']
            or intent['recovery']['process'] != _receiver_invocation() or intent['boot'] != boot_identity()):
        fail()
    names = ('LoadState','ActiveState','MainPID','InvocationID','DropInPaths','NeedDaemonReload')
    actual = _edge_system().show(SERVICE,names)
    expected = {'LoadState':'loaded','ActiveState':'active','MainPID':str(intent['edge']['pid']),
                'InvocationID':intent['edge']['invocationId'],'DropInPaths':str(dropin),'NeedDaemonReload':'no'}
    if actual != expected:
        fail()


def _root_listener_live(plan,intent):
    from .recovery_https_install import socket_identity
    if plan.get('schema') != BUILTIN_PLAN:
        fail()
    arguments = ('/usr/bin/python3','-I',plan['launch'],'--recovery-profile',str(RECOVERY_CONFIG))
    state = _edge_system().listener_profile()
    observed = intent['recovery']
    process = observed['process']
    if (digest(encoded(builtin_effective_profile(state,arguments))) != observed['effectiveSha256']
            or state['MainPID'] != str(process['pid'])
            or state['InvocationID'] != process['invocationId']):
        fail()
    path = PROC_ROOT/state['MainPID']
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        def take(name,limit):
            descriptor = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(descriptor,'rb') as source:
                body = source.read(limit+1)
            if not 0 < len(body) <= limit:
                fail()
            return body
        fields = take('stat',4096).rsplit(b') ',1)[-1].split()
        expected = b'\0'.join(os.fsencode(part) for part in arguments)+b'\0'
        executable = os.stat('exe',dir_fd=fd)
        if (len(fields) < 20 or int(fields[19]) != process['startTicks']
                or [executable.st_dev,executable.st_ino] != process['executableIdentity']
                or take('cmdline',4096) != expected
                or [item for item in take('environ',8192).split(b'\0') if item.startswith(b'INVOCATION_ID=')]
                != [b'INVOCATION_ID='+process['invocationId'].encode('ascii')]
                or socket_identity(process['pid'],'127.0.0.1',plan['listenPort']) != intent['listenerSocket']
                or not os.path.samestat(os.fstat(fd),path.stat())):
            fail()
    finally:
        os.close(fd)


def _outside_live(plan,intent):
    from .recovery_backend_tls import held_prepared_pair
    from .recovery_https_install import EdgeAttachment,STATE,boot_identity,held_public_edge
    reference = plan['transport']['origin']['publicEdge']
    if intent['boot'] != boot_identity():
        fail()
    with (held_prepared_pair(plan,intent) as pair,PrivateDirectory(STATE) as edge_root,
          held_public_edge(reference,intent['installationId'],lambda:None) as public):
        packet = pair.envelope(digest(encoded(public.request['profile'])),reference['certificateSha256'])
        attachment = EdgeAttachment(packet,public,edge_root)
        if attachment.value() != intent['attachment'] or attachment.observe(_edge_system()) != intent['edge']:
            fail()
        public.probe()
        _root_listener_live(plan,intent)
        if attachment.observe(_edge_system()) != intent['edge'] or intent['boot'] != boot_identity():
            fail()


def _read_builtin_terminal(root,namespace,journal,review,held,plan,*,setup,marker_sha):
    pinned,reviewed,approved,source = held
    if (plan['operationId'] != journal.path.name or any(plan[key] != value for key,value in _review_binding(review).items())
            or type(plan.get('transport')) is not dict):
        fail()
    _approval(_canonical(approved.body),plan,digest(reviewed.body))
    intent = _v2_intent(source.body,_builtin_plan_intent(plan,reviewed.body,approved.body),plan)
    if intent['phase'] != 'complete' or intent['recovery'] != review['recovery'] or intent['storage'] != review['storage']['recovery']:
        fail()
    _consumer_fence(namespace,review,plan['operationId'])
    with (PrivateFile(root,PAIRED_FILE,32768) as paired_file, closing(publisher._Pins()) as pins):
        paired = _canonical(paired_file.body)
        result = _v2_result(plan,intent,paired)
        if (digest(paired_file.body) != intent['pairedSha256'] or _canonical(pinned.body) != result
                or marker_sha is not None and marker_sha != result['markerSha256']):
            fail()
        _read_attempt(journal,plan,intent,paired)
        _validate_assets(result['assetSha256'])
        marker_body = _read_fixed(pins,SETUP_CONFIG,0o600)
        config = _read_fixed(pins,RECOVERY_CONFIG,0o600)
        if (digest(marker_body) != plan['markerSha256'] or digest(config) != plan['configSha256']
                or _canonical(marker_body) != {'schema':BUILTIN_MARKER,'operationId':plan['operationId'],
                   'installationId':intent['installationId'],'origin':plan['scope']['origin'],
                   'configSha256':plan['configSha256'],
                   'transport':{name:plan['transport'][name] for name in ('mode','pairId')}}
                or digest(_read_fixed(pins,floor.RECOVERY_ENV,0o600)) != plan['environmentSha256']
                or digest(_read_fixed(pins,floor.RECOVERY_UNIT,0o644)) != plan['unitSha256']):
            fail()
        for item,parent in ((pinned,root),(paired_file,root),*((item,journal) for item in held[1:])):
            item.verify()
            if mount_id(item.fd) != mount_id(parent.fd):
                fail()
        dropin = _assert_v2_public_files(plan,intent,pins)
        if setup is None:
            _outside_live(plan,intent)
        else:
            if type(setup) is not SetupBinding or setup.sha256 != plan['markerSha256']:
                fail()
            _restricted_live(plan,intent,setup,dropin)
        storage.verify_role('recovery',root,intent['storage'],recovery=setup is not None)
        _consumer_fence(namespace,review,plan['operationId'])
        _terminal_files(root,journal,source.body,paired,result)
        pins.verify()
        return result


def _existing_rollback(journal,root,attachment,intent,owner):
    approval = _read(journal,'rollback-approval.json',optional=True)
    previous = _read(journal,'rollback-intent.json',optional=True)
    terminal = _read(journal,'rolled-back.json',optional=True)
    if approval is None:
        if previous is not None or terminal is not None:
            fail()
        return False
    request = _canonical(approval)
    base = {'operationId':intent['operationId'],'reviewSha256':intent['reviewSha256'],
            'pairSha256':intent['pairSha256'],'edgeSha256':intent['attachment']['edgeSha256']}
    expected = {**base,'schema':'orbis.sentinel-recovery-attachment-rollback-approval.v1',
                'approvalId':request.get('approvalId')}
    if (request != expected or not hash_value(request['approvalId']) or intent['phase'] != 'attached'
            or any(_read(root,name,optional=True) is not None for name in
                   (PAIRED_FILE,RECEIPT_FILE,'.'+PAIRED_FILE+'.pending','.'+RECEIPT_FILE+'.pending'))):
        fail()
    value = {**base,'schema':'orbis.sentinel-recovery-attachment-rollback.v1',
             'approvalSha256':digest(approval),'edge':intent['edge']}
    def authorize():
        owner.check()
        if _read(journal,'rollback-approval.json') != approval:
            fail()
    authorize()
    if previous is None:
        if terminal is not None or attachment.observe(_edge_system()) != intent['edge']:
            fail()
        _new_file(journal.path/'rollback-intent.json',encoded(value),0o600)
    elif previous != encoded(value):
        fail()
    restored = None
    if terminal is not None:
        result = _canonical(terminal)
        restored = result.get('restoredEdge')
        if (type(restored) is not list or len(restored) != 3 or type(restored[0]) is not int or restored[0] <= 0
                or type(restored[1]) is not str or not re.fullmatch('[a-f0-9]{32}',restored[1])
                or type(restored[2]) is not int or restored[2] <= 0 or result != {**value,'restoredEdge':restored}):
            fail()
    restored = attachment.rollback(_edge_system(),intent['edge'],authorize,restored=restored)
    authorize()
    _new_file(journal.path/'rolled-back.json',encoded({**value,'restoredEdge':restored}),0o600)
    return True
