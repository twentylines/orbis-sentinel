"""Exercise the retained setup writer against a real sole owner and local TLS."""

from contextlib import ExitStack, closing, contextmanager, nullcontext, redirect_stderr, redirect_stdout
import http.client
import http.server
import io
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_control, bootstrap_host_transition, bootstrap_source, recovery_bootstrap, recovery_config, recovery_control
from orbis_sentinel import collector_execution, recovery_backend_tls, recovery_gateway, recovery_https_install, recovery_https_edge
from orbis_sentinel import recovery_listener_install as listener
from orbis_sentinel import recovery_runtime, recovery_sessions, recovery_worker_provision as worker, runtime, writer_control
from orbis_sentinel.bootstrap_source import PrivateDirectory, decode, digest, encoded
from test_bootstrap_host_transition import portable_write
import test_recovery_worker_provision as d1
import test_recovery_https_edge as edge_fixtures

ASSETS = {name: digest(recovery_gateway._asset(name)) for name in listener.ASSETS}
RECEIVER = {'pid': os.getpid(), 'startTicks': 781, 'invocationId': '7' * 32, 'executableIdentity': [1, 2]}
ROLE = {'filesystem': 'controlled-fixture'}
VERIFY_STORAGE_ROLE = listener.storage.verify_role


class SetupBindingTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='s')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        self.start(mock.patch.object(recovery_sessions, '_OWNER_UID', os.getuid()))
        self.config = {'origin': 'https://localhost:4443'}
        self.marker = encoded({'schema': listener.MARKER, 'operationId': '0' * 64,
            'installationId': 'a' * 64, 'origin': self.config['origin'], 'configSha256': digest(encoded(self.config))})
        self.time = 20
        self.binding = self.make_binding()

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def make_binding(self, marker=None):
        return listener.SetupBinding(self.config, marker or self.marker, lambda: None, monotonic=lambda: self.time)

    def test_mode_persists_without_reopening_normal_auth_or_writer_on_restart(self):
        for _ in range(2):
            with self.subTest(), recovery_store(self.root, self.binding) as store:
                self.assertEqual(store._transaction(store._operator_status)['state'], 'never-enrolled')
                with self.assertRaises(recovery_sessions.RecoverySessionError):
                    store.prepare_recovery_key(origin=self.config['origin'], expected_revision=None)
                with self.assertRaises(recovery_sessions.RecoverySessionError):
                    store.revoke_operator(expected_generation=0, expected_revision=None)
                with self.assertRaises(recovery_sessions.RecoverySessionError):
                    store.authentication_options()
                with self.assertRaises(BlockingIOError):
                    recovery_sessions.RecoverySessions(self.root, setup=self.binding)
        with self.assertRaises(ValueError):
            recovery_sessions.RecoverySessions(self.root)
        crossed = self.make_binding(encoded({**decode(self.marker), 'operationId': 'b' * 64}))
        with self.assertRaises(ValueError):
            recovery_sessions.RecoverySessions(self.root, setup=crossed)

    def test_empty_preexisting_legacy_store_cannot_be_adopted(self):
        with recovery_store(self.root) as store:
            self.assertEqual(store.operator_status()['state'], 'never-enrolled')
        original = (self.root / 'recovery.sqlite3').read_bytes()
        with self.assertRaises(ValueError):
            recovery_sessions.RecoverySessions(self.root, setup=self.binding)
        self.assertEqual((self.root / 'recovery.sqlite3').read_bytes(), original)
        self.assertFalse((self.root / listener.STORE_BINDING).exists())

    def test_lost_first_store_rename_recovers_only_exact_owned_pending(self):
        pending = self.root / ('.' + listener.STORE_BINDING + '.pending')
        binding = encoded({'operationId': self.binding.operation, 'markerSha256': self.binding.sha256})
        pending.write_bytes(binding + b' ')
        pending.chmod(0o600)
        with self.assertRaises(ValueError):
            recovery_sessions.RecoverySessions(self.root, setup=self.binding)
        self.assertFalse((self.root / 'recovery.sqlite3').exists())
        with self.assertRaises(ValueError):
            recovery_sessions.RecoverySessions(self.root)
        pending.write_bytes(binding)
        with recovery_store(self.root, self.binding):
            self.assertFalse(pending.exists())
            self.assertEqual((self.root / listener.STORE_BINDING).read_bytes(), binding)

    def test_cookie_witness_is_single_use_and_rejects_replay_expiry_or_overflow(self):
        setup = self.binding
        nonce = setup.arm(setup.operation, setup.sha256)
        with self.assertRaises(ValueError):
            setup.arm(setup.operation, setup.sha256)
        setup.observe('A' * 43)
        proof = digest(b'A' * 43)
        with self.assertRaises(ValueError):
            setup.confirm(setup.operation, setup.sha256, 'c' * 64, proof)
        setup.confirm(setup.operation, setup.sha256, nonce, proof)
        with self.assertRaises(ValueError):
            setup.confirm(setup.operation, setup.sha256, nonce, proof)
        nonce = setup.arm(setup.operation, setup.sha256)
        setup.observe('A' * 43)
        self.time += listener.PROBE_TTL
        with self.assertRaises(ValueError):
            setup.confirm(setup.operation, setup.sha256, nonce, proof)
        nonce = setup.arm(setup.operation, setup.sha256)
        for index in range(listener.PROBE_LIMIT + 1):
            setup.observe(chr(65 + index) * 43)
        with self.assertRaises(ValueError):
            setup.confirm(setup.operation, setup.sha256, nonce, proof)
        nonce = setup.arm(setup.operation, setup.sha256)
        with self.assertRaises(ValueError):
            setup.confirm(setup.operation, setup.sha256, nonce, proof)


@contextmanager
def recovery_store(directory, setup=None):
    store = recovery_sessions.RecoverySessions(directory, setup=setup)
    try:
        yield store
    finally:
        store.close()


class ListenerInstallTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory(prefix='j')
        self.addCleanup(work.cleanup)
        self.base = Path(work.name).resolve()
        self.recovery = self.base / 'r'
        self.config = self.recovery / 'config.json'
        self.etc = self.base / 'etc'
        self.units = self.base / 'systemd'
        self.units.mkdir(mode=0o700)
        self.marker = self.etc / 'recovery-setup.json'
        self.environment = self.etc / 'recovery.env'
        self.unit = self.units / 'orbis-sentinel-recovery.service'
        self.prefix = self.base / 'prefix'
        self.release = self.prefix / 'releases' / '1.2.3'
        for relative in ('web', 'packaging/systemd'):
            (self.release / relative).mkdir(parents=True, mode=0o755)
        self.unit_bytes = (Path(__file__).resolve().parents[1] / 'packaging/systemd/orbis-sentinel-recovery.service').read_bytes()
        unit_source = self.release / 'packaging' / 'systemd' / self.unit.name
        unit_source.write_bytes(self.unit_bytes)
        unit_source.chmod(0o644)
        for name in listener.ASSETS:
            asset = self.release / 'web' / name
            asset.write_bytes(recovery_gateway._asset(name))
            asset.chmod(0o644)
        self.start(mock.patch.object(listener.floor, 'RECOVERY_ROOT', self.recovery))
        self.start(mock.patch.object(listener.floor, 'RECOVERY_ENV', self.environment))
        self.start(mock.patch.object(listener.floor, 'RECOVERY_UNIT', self.unit))
        self.start(mock.patch.object(listener, 'RECOVERY_CONFIG', self.config))
        self.start(mock.patch.object(listener, 'SETUP_CONFIG', self.marker))
        self.start(mock.patch.object(listener.publisher, 'ROOT', self.prefix))
        self.start(mock.patch.object(listener.storage, 'observe', return_value=ROLE))
        self.start(mock.patch.object(listener.storage, 'verify_role', side_effect=self.verify_storage))
        self.start(mock.patch.object(recovery_runtime, '_require_root'))
        self.start(mock.patch.object(recovery_config, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(bootstrap_control, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(writer_control, '_OWNER_UID', os.getuid()))
        self.start(mock.patch.object(recovery_control, '_OWNER_UID', os.getuid()))
        if not hasattr(socket, 'SO_PEERCRED'):
            self.start(mock.patch.object(recovery_control.RecoveryControlServer, '_peer_uid', return_value=os.getuid()))
            self.start(mock.patch.object(bootstrap_control.RootBootstrapControlClient, '_peer', return_value=True))
            self.start(mock.patch.object(bootstrap_control.RootBootstrapControlClient, '_peer_pid', return_value=os.getpid()))
            self.start(mock.patch.object(writer_control.WriterControlClient, '_peer', return_value=True))
        self.start(mock.patch.object(recovery_runtime.RecoveryWorker, 'capability', return_value=d1.CAPABILITY))
        self.start(mock.patch.object(recovery_bootstrap, '_receiver_invocation', side_effect=lambda: dict(self.process)))
        self.start(mock.patch.object(listener, '_https_process', side_effect=self.tls_proof))
        self.process = dict(RECEIVER)
        self.systemd_commands = []
        self.errors = []
        self.started = False
        self.enabled = False
        self.loaded = False
        self.listener_thread = None
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.start_lost = False
        self.fail_phase = None
        self.disable_probe = False
        self.alter_response = None
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.port = reserve.getsockname()[1]
        self.origin = 'https://localhost:4443'
        self.provision = d1.WorkerProvisionTests()
        self.provision.setUp()
        self.addCleanup(self.provision.doCleanups)
        self.prepare_proxy_docker()
        self.product = SimpleNamespace(UNIT=self.unit.name, UNIT_SHA256=digest(self.unit_bytes),
            RECOVERY_CONFIG=self.config, RECOVERY_ENV=self.environment, UNITS=self.units, RECOVERY_INTERPRETER=Path('/usr/bin/python3'),
            _write_storage=self.write_journal, _systemd=self.effective, _run=self.control_unit)
        self.actor = listener.ListenerInstall(lambda: None)

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def prepare_proxy_docker(self):
        p = self.provision
        original = p.docker.run
        self.proxy = {'Id': '9' * 64, 'Name': '/runtipi-reverse-proxy', 'Config': {'Labels': {
            'com.docker.compose.service': 'runtipi-reverse-proxy', 'com.docker.compose.project': 'runtipi',
            'com.docker.compose.project.working_dir': p.review['root']}},
            'State': {'Running': False, 'Paused': False, 'Restarting': False, 'Dead': False, 'Pid': 0, 'Status': 'exited'}}
        self.responder = False

        def docker(arguments, **kwargs):
            if arguments[0] == 'inspect' and arguments[-1] == 'runtipi-reverse-proxy':
                return encoded(self.proxy)
            if 'label=io.orbis.restore.role=responder' in arguments:
                return b'active\n' if self.responder else b''
            return original(arguments, **kwargs)

        p.docker.run = docker

    @staticmethod
    def verify_storage(role, directory, expected, *, recovery=False):
        if role != 'recovery' or expected != ROLE:
            raise ValueError('Fixture crossed recovery storage')
        directory.verify()

    def write_journal(self, authority, directory, name, body, *, previous):
        portable_write(authority, directory, name, body, previous=previous)
        if name == 'intent.json' and decode(body)['phase'] == self.fail_phase:
            self.fail_phase = None
            raise OSError('Fixture lost durable reply')

    def prepare_source(self):
        p = self.provision
        p.review['origin'] = self.origin
        p.plan['scope']['origin'] = self.origin
        p.plan['runtime']['version'] = '1.2.3'
        self.host = self.base / 'host'
        p.namespace = self.host / 'installations' / digest(os.fsencode(p.review['root']))
        for path in (self.host, p.namespace.parent, p.namespace):
            path.mkdir(mode=0o700)
        p.guard = d1.HostGuard(p.namespace)
        prior = encoded({'origin': self.origin, 'mode': 'unmanaged'})
        self.write_private(self.host / 'credential-admission.json', prior)
        previous = encoded({'schema': 'orbis.recovery-admission-history.v1', 'installationId': p.review['installationId'],
            'mode': 'unmanaged', 'managedEver': False, 'generation': 7, 'configSha256': digest(prior)})
        self.write_private(p.namespace / 'recovery-admission-history.json', previous)
        p.review['previousAdmissionSha256'] = p.plan['configSha256'] = digest(prior)
        p.review['hostHistorySha256'] = p.plan['historySha256'] = digest(previous)
        self.start(mock.patch.object(bootstrap_source, 'HOST_STATE', self.host))
        worker_result = p.actor().apply(*p.prepare())

        @contextmanager
        def scope(operation, receipt):
            if (operation, receipt) != (p.operation, p.publication_sha):
                raise ValueError('Fixture crossed the retained B source')
            with PrivateDirectory(p.namespace) as namespace:
                admission = SimpleNamespace(authority=None, supervisor=SimpleNamespace(
                    bootstrap_recovery=self.observe_running, _held_runtime=lambda **kw: nullcontext((p.plan['runtime'], {}, namespace.verify)),
                    ), **getattr(self,'origin_admission',{}))
                yield namespace, admission, self.product, p.guard, p.plan, p.docker, namespace.verify

        self.start(mock.patch.object(worker.WorkerProvision, '_scope', side_effect=scope))
        return p.operation, p.publication_sha, worker_result['receiptSha256'], self.port

    @staticmethod
    def write_private(path, body):
        path.write_bytes(body)
        path.chmod(0o600)

    def prepare_approval(self):
        params = self.prepare_source()
        response = self.actor.review(*params)
        self.assertEqual(self.actor.review(*params), response)
        self.assertFalse(self.recovery.exists())
        p = self.provision
        self.journal = p.namespace / listener.OPERATIONS / response['operationId']
        self.assertFalse((self.journal / 'approval.json').exists())
        body = encoded({'schema': listener.APPROVAL, 'operationId': response['operationId'],
             'installationId': p.plan['scope']['installationId'], 'reviewSha256': response['reviewSha256'], 'approvalId': '6' * 64})
        approval = self.journal / 'approval.json'
        approval.write_bytes(body)
        approval.chmod(0o600)
        return (*params, response['reviewSha256'], digest(body))

    def effective(self, name, *, effective_recovery):
        if name != self.unit.name or not effective_recovery:
            raise AssertionError('Wrong unit scope')
        argv = '/usr/bin/python3 -I ${ORBIS_SENTINEL_RECOVERY_RUNTIME} --recovery-profile ${ORBIS_SENTINEL_RECOVERY_PROFILE}'
        return {**self.unit_status(), 'KillMode': 'control-group', 'User': 'root', 'Group': 'root',
                'ProtectHome': 'yes', 'ProtectProc': 'invisible', 'ProtectSystem': 'strict',
                'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': '',
                'ExecStart': '{ path=/usr/bin/python3 ; argv[]=' + argv + ' ; ignore_errors=no }'}

    def unit_status(self):
        return {'LoadState': 'loaded' if self.loaded else 'not-found',
                'ActiveState': 'active' if self.started else 'inactive', 'SubState': 'running' if self.started else 'dead',
                'FragmentPath': str(self.unit) if self.loaded else '', 'DropInPaths': '', 'NeedDaemonReload': 'no',
                'MainPID': str(self.process['pid']) if self.started else '0', 'ControlPID': '0',
                'UnitFileState': 'enabled' if self.enabled else 'disabled' if self.loaded else 'not-found'}

    def control_unit(self, argv, **options):
        self.assertEqual(argv[0], '/usr/bin/systemctl')
        command = argv[1]
        if command == 'show':
            self.assertEqual(argv[-1], self.unit.name)
            return ''.join(f'{key}={value}\n' for key, value in self.unit_status().items()).encode()
        self.systemd_commands.append(command)
        if command == 'daemon-reload':
            self.assertEqual(self.unit.read_bytes(), self.unit_bytes)
            self.loaded = True
        elif command == 'start':
            self.assertEqual(argv[2:], [self.unit.name])
            self.assertTrue(self.loaded and not self.started)
            self.start_owner()
            if self.start_lost:
                self.start_lost = False
                raise OSError('Fixture lost the successful systemd start reply')
        elif command == 'enable':
            self.assertEqual(argv[2:], [self.unit.name])
            self.assertTrue(self.started and not self.enabled and (self.recovery / listener.RECEIPT_FILE).exists())
            self.enabled = True
        else:
            raise AssertionError('Unexpected systemd command')
        return b''

    @contextmanager
    def observe_running(self, origin, main, runtime_info, _, *, builtin_marker_sha=None):
        self.assertEqual(origin, self.origin)
        self.assertEqual(main, self.provision.plan['main'])
        self.assertEqual(runtime_info, self.provision.plan['runtime'])
        if not self.started:
            raise ValueError('Fixture unit did not start')
        process = dict(self.process)
        if getattr(self,'paired',False):
            if builtin_marker_sha is not None:
                self.assertEqual(builtin_marker_sha, digest(self.marker.read_bytes()))
            arguments = ('/usr/bin/python3','-I',str(self.release/'bin/orbis-sentinel'),'--recovery-profile',str(self.config))
            profile = digest(encoded(recovery_config.builtin_effective_profile(self.paired_listener_profile(), arguments)))
        else:
            self.assertIsNone(builtin_marker_sha)
            profile = 'd'*64
        observation = {'process': process, 'effectiveSha256': profile, 'environmentSha256': digest(self.environment.read_bytes()),
                       'configSha256': digest(self.config.read_bytes()), 'unitSha256': digest(self.unit.read_bytes())}

        def check():
            if self.process != process or not self.started or self.errors:
                raise ValueError('Fixture recovery invocation changed')
        check()
        yield observation, check
        check()

    def paired_listener_profile(self):
        profile = self.effective(self.unit.name,effective_recovery=True)
        profile.pop('UnitFileState')
        start, pid = ('[n/a]', '0') if getattr(self,'listener_status_reset',False) else (
            '[Fri 2026-11-20 05:20:59 UTC]', str(self.process['pid']))
        profile['ExecStart'] = (profile['ExecStart'][:-2] + f' ; start_time={start} ; stop_time=[n/a] ; pid={pid}'
                                ' ; code=(null) ; status=0/0 }')
        return {**profile,'InvocationID':self.process['invocationId']}

    def start_owner(self):
        def serve():
            try:
                with recovery_config.RecoveryConfig(self.config) as config, listener.setup_profile(config, self.config) as setup:
                    self.owner_setup = setup
                    recovery_runtime.run_recovery(directory=str(self.recovery), image_id=d1.IMAGE, origin=self.origin,
                        address=('127.0.0.1', self.port), status=lambda: {}, stop=self.stop, ready=lambda _: self.ready.set(),
                        control=True, installed_listener=True, setup=setup, check=setup.verify,backend=setup.backend)
            except BaseException as error:
                self.errors.append(error)
                self.ready.set()
        self.listener_thread = threading.Thread(target=serve)
        self.listener_thread.start()
        self.addCleanup(self.stop_owner)
        self.assertTrue(self.ready.wait(5))
        self.assertEqual(self.errors, [])
        self.started = True

    def stop_owner(self):
        self.stop.set()
        self.listener_thread.join(5)
        self.assertFalse(self.listener_thread.is_alive())
        self.assertEqual(self.errors, [])

    def tls_proof(self, _launcher):
        if self.disable_probe:
            raise ssl.SSLError('Fixture independent TLS unavailable')
        if not hasattr(self, 'trusted_context'):
            # A direct socket exchange exercises production Root IPC and cookie
            # observation for filesystem crash cases that do not exercise TLS.
            with closing(http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)) as proxy:
                proxy.request('GET', recovery_gateway.BASE + '/', headers={'Host': self.origin.split('//')[1]})
                reply = proxy.getresponse()
                cookie = listener._binding_cookie(reply.getheaders())
                reply.read()
            return {'bindingSha256': digest(cookie.encode()), 'certificateSha256': '5' * 64, 'assetSha256': ASSETS}
        return {**listener.signed_out_https(self.origin, ASSETS, context=self.trusted_context), 'assetSha256': ASSETS}

    def start_tls(self):
        openssl = shutil.which('openssl')
        if not openssl:
            self.skipTest('OpenSSL required to create local synthetic test certificate')
        chain, key = self.base / 'cert.pem', self.base / 'tls-key.pem'
        subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
                        '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(chain)],
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=True)
        self.trusted_context = ssl.create_default_context(cafile=str(chain))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(chain, key)
        fixture = self

        class Proxy(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *_):
                pass

            def do_GET(self):
                request_headers = {'Host': self.headers['Host']}
                if 'Cookie' in self.headers:
                    request_headers['Cookie'] = self.headers['Cookie']
                with closing(http.client.HTTPConnection('127.0.0.1', fixture.port, timeout=3)) as upstream:
                    upstream.request('GET', self.path, headers=request_headers)
                    reply = upstream.getresponse()
                    status, headers, body = reply.status, reply.getheaders(), reply.read()
                if fixture.alter_response is not None:
                    status, headers, body = fixture.alter_response(self.path, status, headers, body)
                self.send_response_only(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

        edge = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        edge.socket = context.wrap_socket(edge.socket, server_side=True)
        self.origin = 'https://localhost:' + str(edge.server_port)
        serving = threading.Thread(target=lambda: edge.serve_forever(poll_interval=0.05))
        serving.start()

        def cleanup():
            edge.shutdown()
            serving.join(5)
            edge.server_close()
        self.addCleanup(cleanup)

    def receipt_review(self):
        receipt = decode((self.recovery / listener.RECEIPT_FILE).read_bytes())
        p = self.provision
        review = {**p.review, 'captureRoot': str(p.namespace / 'bootstrap-sources'), 'recovery': receipt['recovery'],
                  'storage': {**p.review['storage'], 'recovery': ROLE}}
        return review, receipt

    @contextmanager
    def observed_host_transition(self, review):
        namespace = self.provision.namespace
        (namespace/'credential-journal').mkdir(mode=0o700,exist_ok=True)
        host_copy = {'sourceFiles':{},'unitSha256':'8'*64,'environmentSha256':'9'*64}
        observed = {**review,'operationId':'3'*64,'host':{'inventorySha256':digest(encoded({})),'unitSha256':'8'*64,
                    'environmentSha256':'9'*64,'effectiveSha256':'a'*64},'layoutSha256':digest(encoded({})),
                    'journal':{}}
        supervisor = SimpleNamespace(_held_runtime=lambda **_:nullcontext((review['runtime'],{},lambda:None)),
            bootstrap_recovery=self.observe_running,_main=lambda *_a,**_kw:
            (review['installationId'],review['main'],review['daemon']),
            _host_stopped=lambda:{'custody':host_copy,'systemdSha256':'a'*64})
        admission = SimpleNamespace(supervisor=supervisor,_journal=lambda *_a,**_kw:{},
            service=SimpleNamespace(state_dir=self.host,require_credential_idle=mock.Mock()),
            layout=SimpleNamespace(read=lambda *_:{}))
        actor = bootstrap_host_transition.HostActivation(lambda:None)
        selected = {'controlledFixture':'retained Worker'}

        def role_check(role, directory, expected, *, recovery=False):
            self.assertEqual(expected,review['storage'][role])
            directory.verify()

        with (mock.patch.object(actor,'_qualified_worker',return_value=selected),
              mock.patch.object(bootstrap_host_transition,'require_retained_worker',return_value=selected),
              mock.patch.object(listener.storage,'verify_role',side_effect=role_check),
              PrivateDirectory(self.host) as root,
              actor._observed(observed,admission,self.product,root,mock.Mock(),lambda:None) as result):
            yield result[-1]

    def approve_c1_fixture(self, review):
        operation = '3' * 64
        directory = self.recovery / 'bootstrap' / operation
        directory.parent.mkdir(mode=0o700)
        directory.mkdir(mode=0o700)
        content = {**review, 'schema': 'orbis.sentinel-bootstrap-review.v2', 'operationId': operation,
                   'previousGeneration': 7, 'previousSentinelVersion': '1.2.3',
                   'previousWriterProtocol': 1, 'layoutSha256': '2' * 64, 'journal': {},
                   'host': {}, 'collector': {'protocol': 'orbis.stopped-main-source.v1',
                   'programSha256': 'b' * 64, 'imageId': d1.IMAGE, 'inventorySha256': 'c' * 64}}
        review_sha = digest(encoded(content))
        self.write_private(directory / 'review-plan.json', encoded(content))
        self.write_private(directory / 'review-approval.json', encoded({'schema': 'orbis.sentinel-bootstrap-review-approval.v2',
            'operationId': operation, 'reviewSha256': review_sha, 'installationId': review['installationId'],
            'approvalId': 'b' * 64}))
        return {'operationId': operation, 'reviewSha256': review_sha}

    def test_retained_worker_to_real_independent_tls_and_same_owner_receipt(self):
        self.start_tls()
        params = self.prepare_approval()
        result = self.actor.apply(*params)
        self.assertEqual(self.actor.apply(*params), result)
        self.assertEqual(self.systemd_commands, ['daemon-reload', 'start', 'enable'])
        self.assertIsNone(self.provision.guard.read())
        review, receipt = self.receipt_review()
        self.assertEqual(listener.read_setup_receipt(self.recovery, review), receipt)
        with self.observed_host_transition(review) as recheck:
            recheck()
        self.assertEqual(result['receiptSha256'], digest(encoded(receipt)))
        self.assertEqual(receipt['recovery']['process'], self.process)
        args = self.approve_c1_fixture(review)
        root_path = str(self.recovery / 'bootstrap-control.sock')
        bootstrap = bootstrap_control.RootBootstrapControlClient(root_path, timeout=2, expected_pid=os.getpid())
        self.assertEqual(bootstrap.call('bootstrap-held-review', args), {**args, 'phase': 'review-capture-ready'})
        wrong_peer = bootstrap_control.RootBootstrapControlClient(root_path, timeout=2, expected_pid=os.getpid() + 1)
        with self.assertRaises(bootstrap_control.RootBootstrapControlError):
            wrong_peer.call('bootstrap-held-review', args)
        receipt_path = self.recovery / listener.RECEIPT_FILE
        receipt_path.write_bytes(encoded({**receipt, 'markerSha256': '0' * 64}))
        with self.assertRaises(bootstrap_control.RootBootstrapControlError):
            bootstrap.call('bootstrap-held-review', args)
        receipt_path.write_bytes(encoded(receipt))
        with self.assertRaises(BlockingIOError):
            recovery_sessions.RecoverySessions(self.recovery)
        client = writer_control.WriterControlClient(str(self.recovery / 'control.sock'), timeout=2)
        self.assertEqual(client.call('operator-capability', {}), d1.CAPABILITY)
        for operation, args in (('operator-status', {}), ('operator-stage', {'identityBase64': 'YQ=='})):
            with self.subTest(operation=operation), self.assertRaises(writer_control.WriterControlError):
                client.call(operation, args)
        self.assertFalse((self.recovery / 'profiles').exists())

    def make_origin_terminal(self,public_edge=None):
        # Controlled installed Docker/B observations surround real retained D1
        # state and the production reader of the protected 2A file graph.
        p = self.provision
        operation = '8'*64
        root = Path(p.review['root'])
        root.mkdir(mode=0o700)
        env = f'KEEP_EXACT_PRIOR_BYTES=yes\nORBIS_SENTINEL_RECOVERY_ORIGIN={self.origin}\n'.encode('ascii')
        self.write_private(root/'.env',env)
        definition = '4'*64
        main = {key:p.plan['main'][key] for key in ('id','imageId','publicationSha256','definitionSha256','protocol')}
        scope = p.plan['scope']
        request = {'mode':'unmanaged','origin':self.origin,'unmanagedAdoption':'root-approved-no-managed-claim.v1'}
        choose = lambda values: {key:digest(encoded([key,values])) for key in ('certificateSha256','profileSha256')}
        edge = public_edge or {**choose(self.origin),'generation':'9'*64,'receiptSha256':'3'*64}
        older_config = encoded({'origin':'https://earlier.fixture','mode':'unmanaged'})+b'\n'
        older_history = encoded({'generation':6,'managedEver':False,'installationId':scope['installationId'],
                                'configSha256':digest(older_config)})+b'\n'
        older_env = b'KEEP_EXACT_PRIOR_BYTES=yes\n'
        current_config = decode((self.host/'credential-admission.json').read_bytes())
        current_history = decode((p.namespace/'recovery-admission-history.json').read_bytes())
        original_encoder = lambda value: encoded(value)
        names = {'ORIGIN_OPERATIONS':'recovery-origin-operations','ORIGIN_COMPLETE':'orbis.recovery-origin-complete.v1',
                 'ORIGIN_REVIEW':'orbis.recovery-origin-review.v1','ORIGIN_APPROVAL':'orbis.recovery-origin-approval.v1',
                 'ORIGIN_INTENT':'orbis.recovery-origin-intent.v1','ORIGIN_READY':'orbis.recovery-origin-v1-ready.v1',
                 'ORIGIN_INGRESS':'orbis.recovery-origin-ingress.v1','SCHEMA':'orbis.recovery-admission-plan.v1'}
        for key,value in names.items():
            setattr(self.product,key,value)
        path = p.namespace/names['ORIGIN_OPERATIONS']/operation
        path.parent.mkdir(mode=0o700)
        path.mkdir(mode=0o700)
        approval_directory = p.namespace/'recovery-admission-approvals'
        approval_directory.mkdir(mode=0o700)
        observed_request = {**scope,'operationId':operation,'schema':'orbis.recovery-origin-request.v1'}
        review = {'schema':names['ORIGIN_REVIEW'],**{key:scope[key] for key in ('root','context','origin','installationId')},
                  'operationId':operation,'requestSha256':digest(encoded(observed_request)),'oldOrigin':'https://earlier.fixture',
                  'custody':{'hostCopySha256':'c'*64},'ingress':{'proxyId':self.proxy['Id']},'edge':edge,
                  'oldHistorySha256':digest(older_history),'oldAdmissionSha256':digest(older_config),
                  'oldEnvironmentSha256':digest(older_env),'newEnvironmentSha256':digest(env)}
        approval = {'schema':names['ORIGIN_APPROVAL'],'operationId':operation,'installationId':scope['installationId'],
                    'reviewSha256':digest(encoded(review)),'approvalId':'d'*64}
        bind = {key:approval[key] for key in ('operationId','installationId','reviewSha256')}
        bind['approvalSha256'] = digest(encoded(approval))
        plan = {'schema':names['SCHEMA'],'request':request,'managedEver':False,'previousGeneration':6,
                'dependencies':{'main':main,'installationId':scope['installationId'],'sentinel':p.plan['runtime']},
                'previousHistorySha256':digest(older_history),'previousConfigSha256':digest(older_config)}
        ready = {'schema':names['ORIGIN_READY'],**bind,'main':main,'origin':self.origin,
                 'planSha256':digest(encoded(plan)),'envSha256':digest(env)}
        authorization = encoded({'root':str(root),'planSha256':ready['planSha256'],'approvalId':'5'*64})
        authorization_sha = digest(authorization)
        self.write_private(approval_directory/(operation+'.json'),authorization)
        archive_id = digest(encoded({'plan':ready['planSha256'],'authorization':authorization_sha}))
        auth = {'sha256':authorization_sha}
        archive = encoded({'phase':'complete','operationId':archive_id,'authorization':auth,'plan':plan,
                           'history':current_history,'candidate':current_config})
        self.write_private(p.namespace/('recovery-admission-'+archive_id+'.json'),archive)
        terminal = {'schema':names['ORIGIN_COMPLETE'],**bind,'main':main,'origin':self.origin,'envSha256':digest(env),
                    'planSha256':ready['planSha256'],'v1AuthorizationSha256':authorization_sha,'v1ArchiveSha256':digest(archive),
                    'historySha256':p.plan['historySha256'],'admissionSha256':p.plan['configSha256']}
        networks = {'tipi':{'NetworkID':'e'*64}}
        candidate = {'id':main['id'],'definitionSha256':definition,'networksSha256':digest(encoded(networks))}
        for filename,value in {'request.json':observed_request,'review.json':review,'approval.json':approval,
                              'complete.json':terminal,'v1-ready.json':ready,'v1-plan.json':plan,
                              'intent.json':{'schema':names['ORIGIN_INTENT'],**bind},'candidate.json':candidate,
                              'ingress-receipt.json':{'schema':names['ORIGIN_INGRESS'],**bind,
                                                       'ingress':review['ingress'],'edge':edge},
                              'prior-history.json':older_history,'prior-admission.json':older_config,
                              'prior-environment.json':older_env}.items():
            self.write_private(path/filename,value if type(value) is bytes else encoded(value))
        self.product.MAXIMUM = 2*1024*1024
        self.product._encoded = original_encoder
        raw = {'Id':main['id'],'definition':definition,'networks':networks,'initial':True}
        self.product.OriginObservations = lambda _:SimpleNamespace(named=lambda _name:raw,network=lambda _name:networks)
        def stopped_note(_fd, seen, reviewed, binding):
            if (seen,reviewed,binding) != (observed_request,review,bind):
                raise ValueError('Fixture switched observed 2A ingress')
        self.product.OriginTransition = lambda *_:SimpleNamespace(_stopped=stopped_note)
        def require_inert(candidate):
            if not candidate['initial']:
                raise ValueError('Fixture previously started')
        self.product._origin_never_started = require_inert
        self.product._origin_definition = lambda value:value['definition']
        self.product._origin_networks = lambda value,_network:value['networks']
        self.origin_admission = {'service':SimpleNamespace(root=root),'request':lambda *_args,**_kw:request,
            '_authorization':lambda path,sha,seen:auth if seen==plan and digest(path.read_bytes())==sha else None,
            '_candidate':lambda _:current_config,'_desired':lambda *_:current_history}

        @contextmanager
        def completed(publisher_operation, verify):
            if publisher_operation != p.operation:
                raise ValueError('Wrong retained B fixture')
            evidence = SimpleNamespace(observation={'schema':listener.publisher.SCHEMA_CUSTODY,'copyCustodySha256':'c'*64},
                                       receipt_sha256=p.publication_sha,recheck=lambda:None)
            verify(None,evidence)
            yield evidence

        self.start(mock.patch.object(listener.publisher,'_completed',side_effect=completed))
        return (operation,digest(encoded(terminal))),path

    def test_prepare_builtin_pair_from_retained_origin_and_worker_holds_for_real_public_proof(self):
        self.provision.plan['main'].update(publicationSha256='b'*64,definitionSha256='4'*64,
                                          protocol='orbis.credentials.v1',storageRestartPolicy='no')
        params = self.prepare_source()
        origin,path = self.make_origin_terminal()
        self.start(mock.patch.object(recovery_backend_tls,'LISTENER_ROOT',self.base/'listener-pair'))
        self.start(mock.patch.object(recovery_backend_tls,'AUTHORITY_ROOT',self.base/'issuer-pair'))
        result = self.actor.review(*params,builtin=origin)
        journal = self.provision.namespace/listener.OPERATIONS/result['operationId']
        review = decode((journal/'review.json').read_bytes())
        self.assertEqual(review['schema'],listener.BUILTIN_PLAN)
        self.assertEqual(review['transport']['origin']['receiptSha256'],origin[1])
        body = encoded({'schema':listener.APPROVAL,'operationId':result['operationId'],
                        'installationId':review['scope']['installationId'],'reviewSha256':result['reviewSha256'],
                        'approvalId':'6'*64})
        self.write_private(journal/'approval.json',body)
        arguments = (*params,result['reviewSha256'],digest(body),origin)
        previous = (path/'candidate.json').read_bytes()
        self.write_private(path/'candidate.json',encoded({**decode(previous),'id':'1'*64}))
        with self.assertRaises(ValueError):
            self.actor.prepare_backend(*arguments)
        self.assertIsNone(self.provision.guard.read())
        self.write_private(path/'candidate.json',previous)
        self.fail_phase = 'backend-prepared'
        with self.assertRaisesRegex(OSError,'durable reply'):
            self.actor.prepare_backend(*arguments)
        outcome = self.actor.prepare_backend(*arguments)
        self.assertEqual(outcome['phase'],'backend-prepared')
        self.assertEqual(self.actor.prepare_backend(*arguments),outcome)
        self.assertIsNotNone(self.provision.guard.read())
        self.assertEqual(self.systemd_commands,[])
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.recovery.exists())
        with self.assertRaises(ValueError):
            self.actor.apply(*arguments[:-1])

    def paired_fixture(self):
        https = recovery_https_install
        edge = recovery_https_edge
        public = edge_fixtures.RecoveryEdgeTests()
        public.setUp()
        self.addCleanup(public.doCleanups)
        profile = {**public.config,'upstreamPort':self.port}
        self.origin = profile['origin']
        state_root = self.base/'edge-state'
        gen = '9'*64
        generation = state_root/'generations'/gen
        generation.mkdir(mode=0o700,parents=True)
        for path in (state_root,state_root/'generations'):
            path.chmod(0o700)
        (state_root/'active').symlink_to('generations/'+gen)
        profile_bytes = encoded(profile)
        chain = public.chain.read_bytes()
        certificate = edge._leaf_hash(chain)
        self.write_private(generation/'profile.json',profile_bytes)
        self.write_private(generation/'chain.pem',chain)
        certificate_bytes = encoded({'profileSha256':digest(profile_bytes),'certificateSha256':certificate,
                                     'chainSha256':digest(chain),'leafExpiresAtSec':int(time.time())+3600})
        operation = state_root/'operations'/gen
        operation.mkdir(mode=0o700,parents=True)
        operation.parent.chmod(0o700)
        self.write_private(operation/'complete.json',certificate_bytes)
        reference = {'generation':gen,'receiptSha256':digest(certificate_bytes),'profileSha256':digest(profile_bytes),
                     'certificateSha256':certificate}
        package = {'launcher':str(self.release/'bin/orbis-sentinel'),'binding':{'packageSha256':'0'*64}}

        @contextmanager
        def held(candidate,install,verify):
            if candidate != reference or install != self.provision.review['installationId']:
                raise ValueError('Crossed public fixture')
            def current():
                verify()
                if getattr(self,'edge_start_fault',None)=='expired' and not self.edge_state['ready']:
                    raise ValueError('Fixture retained public leaf expired')
            current()
            yield https.RetainedEdge(package,{'operationId':gen,'profile':profile},
                                  {'certificateSha256':certificate},chain,reference,current)

        self.provision.plan['main'].update(publicationSha256='b'*64,definitionSha256='4'*64,
                                          protocol='orbis.credentials.v1',storageRestartPolicy='no')
        self.provision.plan['runtime']['artifactSha256'] = '0'*64
        args = self.prepare_source()
        origin,_ = self.make_origin_terminal(reference)
        self.start(mock.patch.object(https,'STATE',state_root))
        self.start(mock.patch.object(https,'UNIT_ROOT',self.units))
        self.start(mock.patch.object(https,'held_public_edge',side_effect=held))
        self.start(mock.patch.object(recovery_backend_tls,'LISTENER_ROOT',self.base/'listener-pair'))
        self.start(mock.patch.object(recovery_backend_tls,'AUTHORITY_ROOT',self.base/'issuer-pair'))
        self.start(mock.patch.object(collector_execution,'_root'))
        self.start(mock.patch.object(listener,'_https_process',side_effect=lambda _:listener.https_child()))
        boot = self.start(mock.patch.object(https,'boot_identity',return_value='a'*64))
        def socket_facts(pid,address,port,*,inherited=None):
            return {'inode':port,'fd':3 if inherited is not None else 9,'address':address,'port':port}
        self.start(mock.patch.object(https,'socket_identity',side_effect=socket_facts))
        self.paired = True
        proc = self.base/'proc'
        self.start(mock.patch.object(listener,'PROC_ROOT',proc))
        record = proc/str(self.process['pid'])
        record.mkdir(parents=True)
        executable = record/'exe'
        executable.touch()
        stat_info = executable.stat()
        self.process['executableIdentity'] = [stat_info.st_dev,stat_info.st_ino]
        arguments = ('/usr/bin/python3','-I',self.release/'bin/orbis-sentinel','--recovery-profile',self.config)
        (record/'cmdline').write_bytes(b'\0'.join(os.fsencode(item) for item in arguments)+b'\0')
        (record/'environ').write_bytes(b'INVOCATION_ID='+self.process['invocationId'].encode('ascii')+b'\0')
        (record/'stat').write_bytes(b'1 (fixture) '+b'0 '*19+str(self.process['startTicks']).encode('ascii'))

        response = self.actor.review(*args,builtin=origin)
        journal = self.provision.namespace/listener.OPERATIONS/response['operationId']
        plan = decode((journal/'review.json').read_bytes())
        approval = encoded({'schema':listener.APPROVAL,'operationId':response['operationId'],
                            'installationId':self.provision.review['installationId'],'reviewSha256':response['reviewSha256'],
                            'approvalId':'6'*64})
        self.write_private(journal/'approval.json',approval)
        arguments = (*args,response['reviewSha256'],digest(approval),origin)
        self.actor.prepare_backend(*arguments)
        before = [711,'b'*32,110]
        after = [712,'c'*32,120]
        restored = [713,'d'*32,130]
        state = {'worker':before,'ready':True,'dropinLoaded':False}
        self.edge_state = state
        self.expected_attached_edge = after
        context = edge.server_context(str(public.chain),str(public.key),'recovery.test')
        actions = []
        active = []

        def stop_edge():
            if active:
                server,thread,resources = active.pop()
                server.shutdown()
                thread.join(3)
                server.server_close()
                resources.close()
                self.assertFalse(thread.is_alive())
        self.addCleanup(stop_edge)

        def start_edge(*, pairing):
            stop_edge()
            resources = ExitStack()
            backend = None
            if pairing:
                credentials = self.base/'loaded-edge-creds'
                credentials.mkdir(mode=0o700)
                packet_path = state_root/https.ATTACHMENTS/response['operationId']/'edge.json'
                packet = decode(packet_path.read_bytes())
                authority = recovery_backend_tls.AUTHORITY_ROOT/packet['pairId']
                values = (profile_bytes,chain,public.key.read_bytes(),packet_path.read_bytes(),
                          *((authority/name).read_bytes() for name in ('ca.pem','client.pem','client-key.pem')))
                for name,body in zip((*edge.TRUST_FILES,*edge.BACKEND_FILES),values):
                    self.write_private(credentials/name,body)
                    (credentials/name).chmod(0o400)
                fd = os.open(credentials,os.O_RDONLY|os.O_DIRECTORY)
                resources.callback(os.close,fd)
                base = []
                for name in edge.TRUST_FILES:
                    item = edge._credential(fd,name,65536)
                    resources.callback(os.close,item[0])
                    base.append(item)
                backend = edge._pending_backend(fd,base,resources,profile)
                self.assertIs(type(backend),edge.PendingBackendTLS)
            sock = edge_fixtures.FixtureListener(fileno=os.dup(public.sock.fileno()))
            sock.listening = True
            server = edge.EdgeServer(sock,config=profile,context=context,backend=backend)
            thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.02})
            thread.start()
            active.append((server,thread,resources))

        def loaded(_,request,*,socket_active,attachment=None):
            self.assertTrue(socket_active)
            self.assertEqual(request['profile'],profile)
            if state['dropinLoaded'] != (attachment is not None):
                raise ValueError('Fixture effective edge attachment changed')
            if attachment is not None:
                attachment.verify_files()
            pid,invocation,ticks = state['worker']
            return {'LoadState':'loaded','ActiveState':'active','MainPID':str(pid),
                    'InvocationID':invocation,'startTicks':ticks}

        original_command = https._command
        def command(program,*call,**options):
            if program != https.SYSTEMCTL:
                return original_command(program,*call,**options)
            if call[0] == 'show':
                self.assertEqual(call[-1],self.unit.name)
                value = self.paired_listener_profile()
                self.assertEqual({item.split('=',1)[1] for item in call[3:-1]},set(value))
                return ''.join(f'{key}={data}\n' for key,data in value.items()).encode('ascii')
            actions.append(call)
            active_dropin = self.units/(https.SERVICE+'.d')/https.ATTACH_DROPIN
            if call[0] == 'daemon-reload':
                state['dropinLoaded'] = active_dropin.exists()
                self.listener_status_reset = True
            if call[0] in ('restart','start'):
                self.assertEqual(call[1],https.SERVICE)
                state['worker'] = after if active_dropin.exists() else restored
                state['ready'] = False
                start_edge(pairing=active_dropin.exists())
                if getattr(self,'edge_restart_lost',False):
                    self.edge_restart_lost = False
                    raise OSError('Fixture lost the successful edge restart reply')
            return b''

        def show(unit,fields):
            self.assertEqual(unit,https.SERVICE)
            pid,invocation,_ = state['worker']
            dropin = self.units/(https.SERVICE+'.d')/https.ATTACH_DROPIN
            values = {'LoadState':'loaded','ActiveState':'active','MainPID':str(pid),'InvocationID':invocation,
                      'DropInPaths':str(dropin) if state['dropinLoaded'] else '',
                      'NeedDaemonReload':'no' if state['dropinLoaded']==dropin.exists() else 'yes'}
            if getattr(self,'foreign_edge_dropin',False):
                values['DropInPaths'] = '/foreign/override.conf'
            return {key:values[key] for key in fields}

        def verify_edge_base(candidate,current):
            self.assertEqual(candidate,package)
            self.assertEqual(current['profile'],profile)
            if getattr(self,'crossed_edge_base',False):
                raise ValueError('Fixture edge base bytes changed')

        def worker_identity(value,_):
            if not state['ready']:
                raise ValueError('Fixture PID 1 reported active before Python exec')
            return value['MainPID'],value['InvocationID'],str(value['startTicks'])

        original_fingerprint = https._wire_fingerprint
        def wire_fingerprint(settings,tls,deadline):
            fault = getattr(self,'edge_start_fault',None) if not state['ready'] else None
            if fault == 'timeout':
                raise TimeoutError('Fixture fixed TLS deadline elapsed')
            leaf = original_fingerprint(settings,tls,deadline)
            if fault == 'wrong-leaf':
                return '0'*64
            state['ready'] = True
            if fault == 'crossed-invocation':
                state['worker'] = [714,'e'*32,140]
            return leaf

        def loaded_credentials(pid,attachment):
            self.assertEqual(pid,state['worker'][0])
            self.assertEqual(attachment is not None,state['dropinLoaded'])
            if getattr(self,'edge_start_fault',None)=='missing-credentials':
                raise FileNotFoundError('Fixture PID 1 credential load absent')

        self.start(mock.patch.object(listener,'_edge_system',return_value=SimpleNamespace(
            loaded=loaded,show=show,verify_files=verify_edge_base,listener_profile=https.EdgeSystem().listener_profile,
            restart=lambda *_:command(https.SYSTEMCTL,'restart',https.SERVICE))))
        self.start(mock.patch.object(https,'_command',side_effect=command))
        self.start(mock.patch.object(https,'_worker_identity',side_effect=worker_identity))
        self.start(mock.patch.object(https,'_wire_fingerprint',side_effect=wire_fingerprint))
        self.start(mock.patch.object(https.EdgeAttachment,'loaded_credentials',side_effect=loaded_credentials))
        start_edge(pairing=False)
        return arguments,journal,plan,boot,actions

    def test_builtin_terminal_uses_both_tls_legs_and_same_owner_before_fence_retires(self):
        arguments,journal,plan,boot,actions = self.paired_fixture()
        def interrupt(phase):
            self.fail_phase = phase
            with self.assertRaisesRegex(OSError,'durable reply'):
                self.actor.apply_builtin(*arguments)
            self.assertEqual(decode((journal/'intent.json').read_bytes())['phase'],phase)
            self.assertIsNotNone(self.provision.guard.read())

        for phase in ('configured','starting'):
            interrupt(phase)
        self.start_lost = True
        with self.assertRaisesRegex(OSError,'lost the successful'):
            self.actor.apply_builtin(*arguments)
        self.assertTrue(self.started)
        self.assertFalse((self.recovery/listener.PAIRED_FILE).exists())
        self.assertIsNotNone(self.provision.guard.read())
        for phase in ('running','attaching'):
            interrupt(phase)
        self.crossed_edge_base = True
        with self.assertRaisesRegex(ValueError,'edge base bytes changed'):
            self.actor.apply_builtin(*arguments)
        self.crossed_edge_base = False
        self.foreign_edge_dropin = True
        with self.assertRaises(ValueError):
            self.actor.apply_builtin(*arguments)
        self.foreign_edge_dropin = False
        self.assertEqual(actions,[])
        self.edge_restart_lost = True
        with self.assertRaisesRegex(OSError,'successful edge restart'):
            self.actor.apply_builtin(*arguments)
        for phase in ('attached','paired','complete'):
            interrupt(phase)
        paired = decode((self.recovery/listener.PAIRED_FILE).read_bytes())
        self.assertEqual(paired['attempt'],1)
        self.assertIn('start_time=[n/a]',self.paired_listener_profile()['ExecStart'])
        self.assertNotEqual(paired['recovery']['process']['invocationId'],paired['edge']['invocationId'])
        self.assertEqual(actions,[('daemon-reload',),('restart',recovery_https_install.SERVICE)])
        review, expected = self.receipt_review()
        with self.assertRaises(ValueError):
            listener.read_setup_receipt(self.recovery,review)
        finish = self.provision.guard.finish
        attempt_path = journal/'proof-1'/'proof.json'
        attempt_body = attempt_path.read_bytes()

        def change_before_retirement(*args,**options):
            attempt_path.write_bytes(attempt_body+b' ')
            return finish(*args,**options)

        with mock.patch.object(self.provision.guard,'finish',side_effect=change_before_retirement):
            with self.assertRaises(ValueError):
                self.actor.apply_builtin(*arguments)
        self.assertIsNotNone(self.provision.guard.read())
        attempt_path.write_bytes(attempt_body)
        result = self.actor.apply_builtin(*arguments)
        self.assertIsNone(self.provision.guard.read())
        self.assertEqual(listener.read_setup_receipt(self.recovery,review),expected)
        self.assertEqual(self.actor.apply_builtin(*arguments),result)
        show = self.paired_listener_profile
        for key, item in (('ControlPID','66'), ('InvocationID','f'*32),
                          ('ExecStart',show()['ExecStart'].replace('pid=0',f"pid={self.process['pid']}")),
                          ('ExecStart',show()['ExecStart'].replace('stop_time=[n/a]','stop_time=[yesterday]'))):
            with self.subTest(property=key), mock.patch.object(
                    self,'paired_listener_profile',side_effect=lambda: {**show(),key:item}):
                with self.assertRaises(ValueError):
                    listener.read_setup_receipt(self.recovery,review)
        with recovery_config.RecoveryConfig(self.config) as config,listener.setup_profile(config,self.config) as setup:
            self.assertEqual(listener.read_setup_receipt(self.recovery,review,marker_sha=setup.sha256,setup=setup),expected)
            boot.return_value = 'd'*64
            with self.assertRaises(ValueError):
                listener.read_setup_receipt(self.recovery,review,marker_sha=setup.sha256,setup=setup)
            with self.assertRaises(ValueError):
                listener.read_setup_receipt(self.recovery,review)
        boot.return_value = 'a'*64
        before_host = (self.host/bootstrap_host_transition.CONFIG).read_bytes()
        generation = recovery_backend_tls.LISTENER_ROOT
        saved_marker = self.marker.with_name('retained-setup-marker')
        saved_generation = generation.with_name('retained-listener-generations')
        # Keep the tested process unchanged while withdrawing the Root-side
        # source files. The owner's separate runtime check would also refuse.
        with (mock.patch.object(self.owner_setup,'_check'),
              mock.patch.object(self.owner_setup.backend,'_check')):
            try:
                with self.assertRaises(FileNotFoundError), self.observed_host_transition(review) as recheck:
                    self.marker.rename(saved_marker)
                    generation.rename(saved_generation)
                    recheck()
                self.assertTrue(self.listener_thread.is_alive())
                self.assertEqual(review['recovery']['process'],self.process)
                with self.assertRaises(FileNotFoundError), self.observed_host_transition(review):
                    self.fail('Missing paired setup entered the Host writer')
            finally:
                if saved_generation.exists():
                    saved_generation.rename(generation)
                if saved_marker.exists():
                    saved_marker.rename(self.marker)
                self.stop_owner()
        self.assertEqual((self.host/bootstrap_host_transition.CONFIG).read_bytes(),before_host)

    def test_paired_receipt_allows_only_the_restricted_recovery_self_bind(self):
        arguments, _journal, _plan, _boot, _actions = self.paired_fixture()
        self.actor.apply_builtin(*arguments)
        review, expected_receipt = self.receipt_review()
        role = {'path': str(self.recovery), 'filesystem': 'ext4', 'uuid': '1' * 32, 'handle': '2' * 16,
                'owner': [os.getuid(), os.getgid(), self.recovery.stat().st_mode],
                'filesystemPath': str(self.recovery), 'mountPoint': '/', 'mountRoot': '/'}
        projected = {**role, 'mountPoint': role['path'], 'mountRoot': role['filesystemPath']}

        def verify(role_name, directory, expected, *, recovery=False):
            self.assertEqual(expected, ROLE)
            directory.verify()
            return VERIFY_STORAGE_ROLE(role_name, directory, role, recovery=recovery)

        with (recovery_config.RecoveryConfig(self.config) as config,
              listener.setup_profile(config, self.config) as setup,
              mock.patch.object(listener.storage, 'observe', return_value=projected) as observation,
              mock.patch.object(listener.storage, 'in_recovery_unit', return_value=True) as service,
              mock.patch.object(listener.storage, 'verify_role', side_effect=verify)):
            # The outside reader cannot adopt even the same-directory projection.
            with self.assertRaises(listener.storage.CredentialStorageError):
                listener.read_setup_receipt(self.recovery, review)
            self.assertEqual(listener.read_setup_receipt(
                self.recovery, review, marker_sha=setup.sha256, setup=setup), expected_receipt)
            service.return_value = False
            with self.assertRaises(listener.storage.CredentialStorageError):
                listener.read_setup_receipt(self.recovery, review, marker_sha=setup.sha256, setup=setup)
            service.return_value = True
            for field, value in (('uuid', '3' * 32), ('handle', '4' * 16), ('mountRoot', '/another-directory')):
                observation.return_value = {**projected, field: value}
                with self.subTest(field=field), self.assertRaises(listener.storage.CredentialStorageError):
                    listener.read_setup_receipt(self.recovery, review, marker_sha=setup.sha256, setup=setup)

    def test_exact_preterminal_rollback_restores_cookie_free_503_and_keeps_hold(self):
        arguments,journal,_plan,_boot,actions = self.paired_fixture()
        with mock.patch.object(listener,'_https_process',side_effect=OSError('fixture interrupted probe')):
            with self.assertRaisesRegex(OSError,'interrupted probe'):
                self.actor.apply_builtin(*arguments)
        with self.assertRaises(ValueError):
            self.actor.apply_builtin(*arguments)
        self.assertEqual(sorted(path.name for path in journal.glob('proof-*')),['proof-1'])
        self.assertTrue((journal/'proof-1'/'arm.json').exists())
        intent = decode((journal/'intent.json').read_bytes())
        self.assertEqual(intent['phase'],'attached')
        dropin = self.units/(recovery_https_install.SERVICE+'.d')/recovery_https_install.ATTACH_DROPIN
        settings = dropin.read_text().splitlines()
        self.assertEqual(settings[0],'[Service]')
        self.assertEqual([row.split('=',1)[0] for row in settings[1:]],['LoadCredential']*4)
        self.assertFalse((self.recovery/listener.PAIRED_FILE).exists())
        approval = {'schema':'orbis.sentinel-recovery-attachment-rollback-approval.v1','approvalId':'7'*64,
                    **{key:intent[key] for key in ('operationId','reviewSha256','pairSha256')},
                    'edgeSha256':intent['attachment']['edgeSha256']}
        self.write_private(journal/'rollback-approval.json',encoded(approval))
        write = listener._new_file
        def lose_reply(path,body,mode):
            write(path,body,mode)
            if path.name == 'rollback-intent.json':
                raise OSError('Fixture lost the durable rollback intent reply')
        with mock.patch.object(listener,'_new_file',side_effect=lose_reply):
            with self.assertRaisesRegex(OSError,'rollback intent reply'):
                self.actor.apply_builtin(*arguments)
        crossed = {**intent['edge'],'pid':799}
        with mock.patch.object(recovery_https_install.EdgeAttachment,'observe',return_value=crossed):
            with self.assertRaises(ValueError):
                self.actor.apply_builtin(*arguments)
        self.assertTrue(dropin.exists())
        original_command = recovery_https_install._command
        def lose_reload(program,*call,**options):
            if (program,*call) == (recovery_https_install.SYSTEMCTL,'daemon-reload'):
                raise OSError('Fixture lost control after removing the owned drop-in')
            return original_command(program,*call,**options)
        with mock.patch.object(recovery_https_install,'_command',side_effect=lose_reload):
            with self.assertRaisesRegex(OSError,'after removing'):
                self.actor.apply_builtin(*arguments)
        self.assertFalse(dropin.exists())
        baseline_actions = list(actions)
        self.crossed_edge_base = True
        with self.assertRaisesRegex(ValueError,'edge base bytes changed'):
            self.actor.apply_builtin(*arguments)
        self.crossed_edge_base = False
        self.foreign_edge_dropin = True
        with self.assertRaises(ValueError):
            self.actor.apply_builtin(*arguments)
        self.foreign_edge_dropin = False
        self.assertEqual(actions,baseline_actions)
        result = self.actor.apply_builtin(*arguments)
        self.assertEqual(result['phase'],'listener-edge-rolled-back')
        self.assertFalse(dropin.exists())
        self.assertTrue((journal/'rolled-back.json').exists())
        self.assertEqual(decode((journal/'rolled-back.json').read_bytes())['restoredEdge'],[713,'d'*32,130])
        self.assertIsNotNone(self.provision.guard.read())
        self.assertEqual(self.actor.apply_builtin(*arguments),result)
        self.assertEqual(actions.count(('restart',recovery_https_install.SERVICE)),2)

    def test_reported_active_waits_for_exact_tls_before_proc_and_credential_proof(self):
        arguments,journal,_plan,_boot,actions = self.paired_fixture()
        for fault,error in (('expired',ValueError),('timeout',TimeoutError),('wrong-leaf',ValueError),
                            ('crossed-invocation',ValueError),('missing-credentials',FileNotFoundError)):
            with self.subTest(fault=fault):
                self.edge_start_fault = fault
                with self.assertRaises(error):
                    self.actor.apply_builtin(*arguments)
                self.assertEqual(decode((journal/'intent.json').read_bytes())['phase'],'attaching')
                self.assertFalse((self.recovery/listener.PAIRED_FILE).exists())
                self.assertFalse((journal/'proof-1').exists())
                self.assertIsNotNone(self.provision.guard.read())
                self.edge_state['worker'] = self.expected_attached_edge
                self.edge_state['ready'] = False
        self.edge_start_fault = None
        self.assertEqual(self.actor.apply_builtin(*arguments)['phase'],'listener-verified')
        self.assertIsNone(self.provision.guard.read())
        self.assertEqual(actions.count(('restart',recovery_https_install.SERVICE)),1)

    def test_interrupted_observation_retries_after_expiry_without_replacing_attempt(self):
        arguments,journal,_plan,_boot,actions = self.paired_fixture()
        with mock.patch.object(listener,'_https_process',side_effect=OSError('fixture interrupted probe')):
            with self.assertRaisesRegex(OSError,'interrupted probe'):
                self.actor.apply_builtin(*arguments)
        first_arm = (journal/'proof-1'/'arm.json').read_bytes()
        with self.assertRaises(ValueError):
            self.actor.apply_builtin(*arguments)
        self.assertFalse((journal/'proof-2').exists())
        pause = listener.PROBE_TTL+4
        clock = self.owner_setup._clock
        self.owner_setup._clock = lambda: clock()+pause
        real_ns = time.monotonic_ns
        with mock.patch.object(listener.time,'monotonic_ns',side_effect=lambda:real_ns()+pause*1_000_000_000):
            result = self.actor.apply_builtin(*arguments)
            self.assertEqual(result['phase'],'listener-verified')
            self.assertEqual(decode((self.recovery/listener.PAIRED_FILE).read_bytes())['attempt'],2)
        self.assertEqual((journal/'proof-1'/'arm.json').read_bytes(),first_arm)
        self.assertFalse((journal/'proof-1'/'proof.json').exists())
        self.assertEqual(actions.count(('restart',recovery_https_install.SERVICE)),1)

    def test_review_refuses_crossed_worker_receipt_and_live_stock_ingress(self):
        params = self.prepare_source()
        with self.assertRaises(ValueError):
            self.actor.review(params[0], params[1], '0' * 64, params[3])
        self.proxy['State']['Running'] = True
        with self.assertRaises(ValueError):
            self.actor.review(*params)
        self.proxy['State']['Running'] = False
        self.responder = True
        with self.assertRaises(ValueError):
            self.actor.review(*params)
        self.assertFalse(self.recovery.exists())
        self.assertEqual(self.systemd_commands, [])

    def test_crossed_approval_has_no_effect(self):
        params = self.prepare_approval()
        with self.assertRaises(ValueError):
            self.actor.apply(*params[:-1], 'a' * 64)
        self.assertIsNone(self.provision.guard.read())
        self.assertFalse(self.recovery.exists())

    def test_exact_lost_systemd_start_reuses_same_owner(self):
        self.start_lost = True
        params = self.prepare_approval()
        with self.assertRaises(OSError):
            self.actor.apply(*params)
        self.assertIsNotNone(self.provision.guard.read())
        self.assertTrue(self.started)
        self.assertEqual(self.actor.apply(*params)['phase'], 'listener-verified')
        self.assertEqual(self.systemd_commands.count('start'), 1)

    def test_exact_interrupted_profile_write_can_reconcile_without_adopting_foreign_bytes(self):
        params = self.prepare_approval()
        original = listener._new_file
        interrupted = False

        def fail_environment(path, body, mode):
            nonlocal interrupted
            if path == self.environment and not interrupted:
                interrupted = True
                self.write_private(path.with_name('.recovery.env.pending'), body)
                raise OSError('Fixture power loss after exact environment stage')
            original(path, body, mode)

        with mock.patch.object(listener, '_new_file', side_effect=fail_environment), self.assertRaises(OSError):
            self.actor.apply(*params)
        pending = self.environment.with_name('.recovery.env.pending')
        target = pending.read_bytes()
        pending.write_bytes(target + b' ')
        with self.assertRaises(ValueError):
            self.actor.apply(*params)
        self.assertEqual(pending.read_bytes(), target + b' ')
        self.assertIsNotNone(self.provision.guard.read())
        self.assertEqual(self.systemd_commands, [])
        pending.write_bytes(target)
        self.assertEqual(self.actor.apply(*params)['phase'], 'listener-verified')
        self.assertEqual(self.systemd_commands, ['daemon-reload', 'start', 'enable'])

    def test_effective_unit_override_cannot_start_after_owned_config(self):
        params = self.prepare_approval()
        active = self.product._systemd
        self.product._systemd = lambda *args, **kwargs: {
            **active(*args, **kwargs), 'DropInPaths': '/unknown/extra.conf'}
        with self.assertRaises(ValueError):
            self.actor.apply(*params)
        self.assertEqual(self.systemd_commands, ['daemon-reload'])
        self.assertIsNotNone(self.provision.guard.read())
        self.assertFalse((self.recovery / 'recovery.sqlite3').exists())

    def test_unavailable_tls_keeps_owned_hold_without_disabling_same_listener(self):
        self.start(mock.patch.object(listener, 'PROBE_TTL', 0.2))
        self.disable_probe = True
        params = self.prepare_approval()
        with self.assertRaises(ssl.SSLError):
            self.actor.apply(*params)
        self.assertIsNotNone(self.provision.guard.read())
        self.assertFalse((self.recovery / listener.RECEIPT_FILE).exists())
        self.assertFalse(self.enabled)
        self.disable_probe = False
        threading.Event().wait(0.25)
        self.assertEqual(self.actor.apply(*params)['phase'], 'listener-verified')
        self.assertEqual(self.systemd_commands.count('start'), 1)

    def test_terminal_reply_loss_requires_exact_invocation_and_approval(self):
        self.fail_phase = 'complete'
        params = self.prepare_approval()
        with self.assertRaises(OSError):
            self.actor.apply(*params)
        self.assertIsNotNone(self.provision.guard.read())
        self.assertTrue(self.enabled)
        review, receipt = self.receipt_review()
        self.assertEqual(listener.read_setup_receipt(self.recovery, review), receipt)
        self.process['startTicks'] += 1
        with self.assertRaises(ValueError):
            self.actor.apply(*params)
        self.assertIsNotNone(self.provision.guard.read())
        self.process['startTicks'] -= 1
        self.assertEqual(self.actor.apply(*params)['phase'], 'listener-verified')
        self.assertIsNone(self.provision.guard.read())
        self.assertEqual(self.systemd_commands, ['daemon-reload', 'start', 'enable'])
        crossed = {**review, 'publisher': {**review['publisher'], 'receiptSha256': '0' * 64}}
        with self.assertRaises(ValueError):
            listener.read_setup_receipt(self.recovery, crossed)

    def test_trusted_tls_refuses_wrong_name_redirect_and_wrong_asset(self):
        self.start_tls()
        params = self.prepare_approval()
        self.actor.apply(*params)
        with self.assertRaises(ssl.SSLCertVerificationError):
            listener.signed_out_https(self.origin.replace('localhost', '127.0.0.1'), ASSETS, context=self.trusted_context)
        with self.assertRaises(ssl.SSLCertVerificationError):
            listener.signed_out_https(self.origin, ASSETS)
        self.alter_response = lambda path, status, headers, body: (302, [*headers, ('Location', self.origin)], body)
        with self.assertRaises(ValueError):
            self.tls_proof(None)
        self.alter_response = lambda path, status, headers, body: (status, headers,
            b'x' * len(body) if path.endswith('recovery.js') else body)
        with self.assertRaises(ValueError):
            self.tls_proof(None)

    def test_signed_out_proxy_replaying_old_cookie_cannot_finish_root_proof(self):
        self.start_tls()
        params = self.prepare_approval()
        self.alter_response = lambda path, status, headers, body: (status, [
            (key, value.replace(listener._binding_cookie(headers), 'A' * 43))
            if key.lower() == 'set-cookie' and value.startswith('__Host-orbis-sentinel-binding=') else (key, value)
            for key, value in headers], body)
        with self.assertRaises(bootstrap_control.RootBootstrapControlError):
            self.actor.apply(*params)
        self.assertIsNotNone(self.provision.guard.read())
        self.assertFalse((self.recovery / listener.RECEIPT_FILE).exists())

    def test_missing_terminal_or_crossed_receipt_refuses_C1_reader(self):
        params = self.prepare_approval()
        self.actor.apply(*params)
        review, receipt = self.receipt_review()
        path = self.journal / 'intent.json'
        original = path.read_bytes()
        value = decode(original)
        path.write_bytes(encoded({**value, 'phase': 'qualified'}))
        with self.assertRaises(ValueError):
            listener.read_setup_receipt(self.recovery, review)
        path.write_bytes(original)
        self.assertEqual(listener.read_setup_receipt(self.recovery, review), receipt)
        with self.assertRaises(ValueError):
            listener.read_setup_receipt(self.recovery, review, marker_sha='0' * 64)


class ListenerDispatchTests(unittest.TestCase):
    def test_only_explicit_fixed_operation_and_bounded_port_can_dispatch(self):
        args = ('--review-recovery-listener', '0' * 64, '--publisher-receipt-sha256', 'a' * 64,
                '--listener-worker-receipt-sha256', 'b' * 64, '--listener-loopback-port', '4443')
        with mock.patch.object(runtime, '_run_listener_install', return_value=0) as dispatch:
            self.assertEqual(runtime.main(args), 0)
            dispatch.assert_called_once_with('review', '0' * 64, 'a' * 64, 'b' * 64, 4443, None, None)
        for invalid in (args[:-1] + ('443',), args + ('--disk-path', '/'), args + ('--listener-review-sha256', 'd' * 64),
                        ('--listener-https-probe', '--listener-loopback-port', '4443')):
            with self.subTest(invalid=invalid), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                runtime.main(invalid)

    def test_backend_dispatch_requires_exact_origin_and_cannot_use_ordinary_apply(self):
        base = ('--prepare-recovery-listener-backend','0'*64,'--publisher-receipt-sha256','a'*64,
                '--listener-worker-receipt-sha256','b'*64,'--listener-loopback-port','4443',
                '--listener-review-sha256','c'*64,'--listener-approval-sha256','d'*64)
        origin = ('--listener-origin-operation','e'*64,'--listener-origin-receipt-sha256','f'*64)
        with mock.patch.object(runtime,'_run_listener_install',return_value=0) as fixed:
            self.assertEqual(runtime.main(base+origin),0)
            fixed.assert_called_once_with('prepare-backend','0'*64,'a'*64,'b'*64,4443,'c'*64,'d'*64,builtin=('e'*64,'f'*64))
        for args in (base,base+origin[:2],('--apply-recovery-listener',*base[1:],*origin),
                     ('--recovery-https-edge',*origin),('--listener-https-probe',*origin)):
            with self.subTest(args=args),redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
                runtime.main(args)

    def test_internal_https_probe_has_no_user_supplied_target(self):
        with mock.patch.object(listener, 'https_child', return_value={'known': 'fixture'}) as child, redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.main(('--listener-https-probe',)), 0)
            child.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
