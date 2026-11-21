"""Private pairing and TLS use the fixed installed recovery listener."""

from contextlib import ExitStack
import http.client
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_control, recovery_backend_tls as backend, recovery_config, recovery_control
from orbis_sentinel import recovery_gateway, recovery_listener_install as listener, recovery_runtime, recovery_sessions
from orbis_sentinel.bootstrap_source import decode, digest, encoded

SOURCE = Path(__file__).resolve().parents[1]
OP = '1' * 64
PAIR = '2' * 64
INSTALLATION = '3' * 64
ORIGIN = 'https://recovery.example.test:8443'
IMAGE = 'sha256:' + '7' * 64


class KeyEncodingTests(unittest.TestCase):
    def test_generated_key_round_trips_without_replacing_its_identity(self):
        from orbis_sentinel.recovery_https_install import _ssl

        body = backend._new_key()
        self.assertEqual(backend._inspect_key(body), _ssl('pkey','-pubout','-outform','DER',value=body))

    def test_noncanonical_or_additional_key_material_is_rejected(self):
        body = backend._new_key()
        variants = [b'ignored preamble\n'+body, body+body,
                    body.replace(b'\n',b'\n\n',1), body.rstrip()+b'\n\n']
        for value in variants:
            with self.subTest(bytes=len(value)), self.assertRaises(ValueError):
                backend._inspect_key(value)

    def test_legacy_or_encrypted_encoding_is_rejected(self):
        from orbis_sentinel.recovery_https_install import _ssl

        body = backend._new_key()
        legacy = _ssl('ec','-outform','PEM',value=body)
        encrypted = _ssl('pkcs8','-topk8','-v2','aes-256-cbc','-passout','pass:synthetic-fixture',value=body)
        for value in [legacy, encrypted]:
            with self.subTest(bytes=len(value)), self.assertRaises(ValueError):
                backend._inspect_key(value)


class Pairs(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix='p')
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name).resolve()
        self.private = self.root/'issuer'
        self.receiver = self.root/'receiver'
        self.patch(backend,'LISTENER_ROOT',self.receiver)
        self.patch(backend,'AUTHORITY_ROOT',self.private)
        self.patch(recovery_sessions,'_OWNER_UID',os.getuid())
        self.patch(recovery_control,'_OWNER_UID',os.getuid())
        self.patch(bootstrap_control,'_OWNER_UID',os.getuid())
        self.patch(recovery_config,'_OWNER_UID',os.getuid())
        self.patch(recovery_runtime,'_require_root')
        self.recovery = self.root/'r'
        self.recovery.mkdir(mode=0o700)
        self.config = self.recovery/'config.json'
        self.marker = self.root/'setup.json'
        self.patch(listener,'RECOVERY_CONFIG',self.config)
        self.patch(listener,'SETUP_CONFIG',self.marker)
        self.port = 4400
        self.config_body = {'schema':'orbis.sentinel-recovery-config.v1','origin':ORIGIN,
            'directory':str(self.recovery), 'imageId':IMAGE,'listenPort':self.port,'statusSocket':listener.STATUS_SOCKET}
        self.marker_body = {'schema':listener.BUILTIN_MARKER,'operationId':OP,'installationId':INSTALLATION,
            'origin':ORIGIN,'configSha256':digest(encoded(self.config_body)),
            'transport':{'mode':backend.MODE,'pairId':PAIR}}
        self.plan = {'operationId':OP,'scope':{'origin':ORIGIN,'installationId':INSTALLATION},
            'listenPort':self.port,'markerSha256':digest(encoded(self.marker_body)),
            'configSha256':digest(encoded(self.config_body)),
            'transport':{'mode':backend.MODE,'pairId':PAIR,'origin':{'operationId':'a'*64}}}
        self.intent = {'reviewSha256':'4'*64,'approvalSha256':'5'*64}

    def patch(self,obj,name,*args,**kwargs):
        patch = mock.patch.object(obj,name,*args,**kwargs)
        self.addCleanup(patch.stop)
        return patch.start()

    @staticmethod
    def write(path,value):
        path.write_bytes(value)
        path.chmod(0o600)

    def prepare(self, check=lambda:None):
        return backend.prepare_pair(self.plan,self.intent,check)

    def device(self, role='client', *, send=True):
        issuer = self.private/PAIR
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=issuer/'ca.pem')
        if send:
            folder = issuer if role == 'client' else self.receiver/PAIR
            context.load_cert_chain(folder/(role+'.pem'),folder/(role+'-key.pem'))
        return context

    def same_authority_different_client(self):
        from orbis_sentinel.recovery_https_install import _ssl

        issuer = self.private/PAIR
        extra = self.root/'other-leaf'
        extra.mkdir(mode=0o700)
        private = extra/'client-key.pem'
        self.write(private,backend._new_key())
        leaf = extra/'client.pem'
        request = _ssl('req','-new','-key',str(private),'-subj','/CN='+backend.CLIENT_NAME)
        self.write(leaf,_ssl('x509','-req','-sha256','-CA',str(issuer/'ca.pem'),'-CAkey',str(issuer/'ca-key.pem'),
            '-set_serial','0x1234567890','-days','3','-extfile',str(issuer/'client.cnf'),'-extensions','leaf',value=request))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=issuer/'ca.pem')
        context.load_cert_chain(leaf,private)
        return context

    def test_prepare_returns_stable_exact_role_separated_custody(self):
        bind = self.prepare()
        self.assertEqual(self.prepare(), bind)
        self.assertEqual(set(os.listdir(self.receiver/PAIR)),backend.LISTENER_FILES)
        self.assertEqual(set(os.listdir(self.private/PAIR)),backend.AUTHORITY_FILES)
        record = (self.receiver/PAIR/backend.MANIFEST).read_bytes()
        self.assertEqual(digest(record),bind)
        parts = decode(record)
        self.assertNotIn('clientKeySha256',parts)
        self.assertNotEqual(parts['server']['leafSha256'],parts['client']['leafSha256'])
        self.assertNotEqual(parts['server']['publicKeySha256'],parts['client']['publicKeySha256'])
        self.assertFalse((self.receiver/PAIR/'client-key.pem').exists())
        self.assertFalse((self.private/PAIR/'server-key.pem').exists())
        with self.assertRaises(ValueError):
            self.prepare(lambda: (_ for _ in ()).throw(ValueError('guard changed')))

    def test_exact_interrupted_manifest_publication_replays_same_keys(self):
        from orbis_sentinel import recovery_https_install
        publish = recovery_https_install._exact_component
        def interrupt(directory,name,body):
            if directory.path == self.receiver/PAIR and name == backend.MANIFEST:
                self.write(directory.path/('.'+name+'.pending'),body)
                raise OSError('lost publication reply')
            return publish(directory,name,body)
        with mock.patch.object(recovery_https_install,'_exact_component',side_effect=interrupt):
            with self.assertRaises(OSError):
                self.prepare()
        key = self.receiver/PAIR/'server-key.pem'
        before = key.read_bytes()
        self.prepare()
        self.assertEqual(key.read_bytes(),before)
        self.assertFalse((self.receiver/PAIR/('.'+backend.MANIFEST+'.pending')).exists())

    def test_partial_pending_key_stays_unpublished_and_prepared_keys_are_never_reissued(self):
        from orbis_sentinel import recovery_listener_install
        publish = recovery_listener_install._new_file
        def interrupt(path,body,mode):
            if path.name == 'server-key.pem':
                self.write(path.with_name('.server-key.pem.pending'),b'partial private key fixture')
                raise OSError('interrupted key')
            return publish(path,body,mode)
        with mock.patch.object(recovery_listener_install,'_new_file',side_effect=interrupt):
            with self.assertRaises(OSError):
                self.prepare()
        folder = self.receiver/PAIR
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual((folder/'.server-key.pem.pending').read_bytes(),b'partial private key fixture')
        self.assertFalse((folder/'server-key.pem').exists())
        (folder/'.server-key.pem.pending').unlink()
        digest_before = self.prepare()
        (folder/'server-key.pem').unlink()
        with self.assertRaises(ValueError):
            backend.prepare_pair(self.plan,self.intent,lambda:None,expected_sha=digest_before)
        self.assertFalse((folder/'server-key.pem').exists())

    def test_existing_ca_key_cannot_be_promoted_as_the_listener_key(self):
        from orbis_sentinel import recovery_listener_install
        publish = recovery_listener_install._new_file
        private = self.private/PAIR/'ca-key.pem'
        pending = self.receiver/PAIR/'.server-key.pem.pending'
        def crossed(path,body,mode):
            if path.name == 'server-key.pem':
                self.write(pending,private.read_bytes())
                raise OSError('fixture interrupted key')
            return publish(path,body,mode)
        with mock.patch.object(recovery_listener_install,'_new_file',side_effect=crossed):
            with self.assertRaises(OSError):
                self.prepare()
        with self.assertRaises(ValueError):
            self.prepare()
        self.assertEqual(pending.read_bytes(),private.read_bytes())
        self.assertFalse((self.receiver/PAIR/'server-key.pem').exists())
        self.assertFalse((self.receiver/PAIR/'server.pem').exists())

    def test_stale_pair_refuses_before_reservation_or_socket(self):
        self.prepare()
        self.write(self.config,encoded(self.config_body))
        self.write(self.marker,encoded(self.marker_body))
        material = decode((self.receiver/PAIR/backend.MANIFEST).read_bytes())
        for expires in (material['server']['notAfterSec'],material['caNotAfterSec']):
            with recovery_config.RecoveryConfig(self.config) as config, mock.patch.object(
                    backend.time,'time',return_value=expires), self.assertRaises(ValueError):
                with listener.setup_profile(config,self.config):
                    self.fail('Stale credentials reached listener setup')
        self.assertFalse((self.recovery/listener.STORE_BINDING).exists())
        self.assertFalse((self.recovery/'recovery.sqlite3').exists())

    def test_missing_or_crossed_marker_and_generation_refuse_before_store(self):
        self.write(self.config,encoded(self.config_body))
        self.prepare()
        with recovery_config.RecoveryConfig(self.config) as config:
            with self.assertRaises(ValueError):
                with listener.setup_profile(config,self.config):
                    pass
            self.write(self.marker,encoded({**self.marker_body,'installationId':'f'*64}))
            with self.assertRaises(ValueError):
                with listener.setup_profile(config,self.config):
                    pass
            self.write(self.marker,encoded(self.marker_body))
            (self.receiver/PAIR/'ca.pem').unlink()
            with self.assertRaises(ValueError):
                with listener.setup_profile(config,self.config):
                    pass
        self.assertFalse((self.recovery/'recovery.sqlite3').exists())

    def test_real_pair_reaches_single_sessions_handler_and_refuses_wrong_peer(self):
        self.prepare()
        self.write(self.config,encoded(self.config_body))
        self.write(self.marker,encoded(self.marker_body))
        stop, ready = threading.Event(), threading.Event()
        observations = []
        with recovery_config.RecoveryConfig(self.config) as config, listener.setup_profile(config,self.config) as setup:
            addresses, errors = [], []
            def known(address):
                addresses.append(address)
                ready.set()
            def run():
                try:
                    recovery_runtime.run_recovery(directory=str(self.recovery),image_id=IMAGE,origin=ORIGIN,
                        address=('127.0.0.1',0),status=lambda:None,stop=stop,ready=known,check=setup.verify,
                        control=True,setup=setup,installed_listener=True,backend=setup.backend)
                except BaseException as error:
                    errors.append(error)
                    ready.set()
            handle = recovery_gateway._Handler._handle
            def observed(handler):
                observations.append(handler.path)
                return handle(handler)
            with mock.patch.object(recovery_gateway._Handler,'_handle',new=observed), mock.patch.multiple(
                    recovery_gateway._Handler, do_GET=observed):
                thread = threading.Thread(target=run)
                thread.start()
                try:
                    self.assertTrue(ready.wait(3))
                    self.assertEqual(errors,[])
                    address = addresses[0]
                    with self.assertRaises(BlockingIOError):
                        recovery_sessions.RecoverySessions(self.recovery,setup=setup)
                    request = (b'GET /sentinel/recovery/ HTTP/1.1\r\nHost: recovery.example.test:8443\r\n'
                               b'Connection: close\r\n\r\n')
                    def attempt(context,name):
                        with socket.create_connection(address,timeout=2) as raw, context.wrap_socket(raw,server_hostname=name) as tls:
                            tls.sendall(request)
                            response = http.client.HTTPResponse(tls)
                            try:
                                response.begin()
                                return response.status, response.getheader('Set-Cookie')
                            finally:
                                response.close()
                    with socket.create_connection(address,timeout=2) as raw:
                        raw.sendall(request)
                        try:
                            self.assertEqual(raw.recv(1),b'')
                        except ConnectionResetError:
                            pass
                    for ctx,name in ((self.device(send=False),backend.SERVER_NAME),
                                     (self.device('server'),backend.SERVER_NAME),
                                     (self.same_authority_different_client(),backend.SERVER_NAME)):
                        with self.assertRaises((ssl.SSLError,ConnectionResetError,http.client.RemoteDisconnected)):
                            attempt(ctx,name)
                    wrong = self.device()
                    wrong.check_hostname = False
                    with self.assertRaises(ssl.SSLError):
                        attempt(wrong,'wrong.invalid')
                    self.assertEqual(observations,[])
                    status,cookie = attempt(self.device(),backend.SERVER_NAME)
                    self.assertEqual(status,200)
                    self.assertIn('__Host-orbis-sentinel-binding=',cookie)
                    self.assertEqual(observations,['/sentinel/recovery/'])
                    self.assertTrue((self.recovery/listener.STORE_BINDING).is_file())
                finally:
                    stop.set()
                    thread.join(4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors,[])

    def test_expired_budget_after_tls_step_does_not_wait_again(self):
        connection = mock.Mock()
        connection.do_handshake.side_effect = ssl.SSLWantReadError()
        context = mock.Mock()
        context.wrap_socket.return_value = connection
        peer = backend.ListenerPeer(context,'4'*64,lambda:None)
        with (mock.patch.object(backend.time,'monotonic',side_effect=[.1,1.1]),
              mock.patch.object(backend.select,'select') as waiting):
            with self.assertRaises(ValueError):
                peer.authenticate(mock.Mock(),1.,threading.Event())
        waiting.assert_not_called()
        connection.close.assert_called_once_with()

    def test_trickled_record_does_not_extend_original_handshake_deadline(self):
        self.prepare()
        with (backend.open_listener(self.marker_body,digest(encoded(self.marker_body)),self.config_body) as peer,
              mock.patch.object(recovery_gateway,'BACKEND_HANDSHAKE_TIMEOUT',.30)):
            server = recovery_gateway.RecoveryHTTPServer(('127.0.0.1',0),mock.Mock(),backend=peer)
            thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01})
            thread.start()
            try:
                with socket.create_connection(server.server_address,timeout=.5) as raw:
                    start = time.monotonic()
                    raw.sendall(b'\x16')
                    time.sleep(.18)
                    raw.sendall(b'\x03')
                    try:
                        self.assertEqual(raw.recv(1),b'')
                    except ConnectionResetError:
                        pass
                    elapsed = time.monotonic()-start
                    self.assertGreater(elapsed,.22)
                    self.assertLess(elapsed,.44)
                server.application.handle.assert_not_called()
            finally:
                server.shutdown()
                thread.join(2)
                server.server_close()

    def test_late_and_ninth_socket_never_reach_http_and_shutdown_drains(self):
        self.prepare()
        routed = self.config_body
        with backend.open_listener(self.marker_body,digest(encoded(self.marker_body)),routed) as peer:
            server = recovery_gateway.RecoveryHTTPServer(('127.0.0.1',0),mock.Mock(),backend=peer)
            thread = threading.Thread(target=server.serve_forever,kwargs={'poll_interval':0.02})
            thread.start()
            try:
                with ExitStack() as resources:
                    for occupied in range(1,9):
                        resources.enter_context(socket.create_connection(server.server_address,timeout=1))
                        expires = time.monotonic()+.3
                        while server._slots._value != 8-occupied and time.monotonic() < expires:
                            time.sleep(.005)
                        self.assertEqual(server._slots._value,8-occupied)
                    with socket.create_connection(server.server_address,timeout=1) as late:
                        try:
                            self.assertEqual(late.recv(1),b'')
                        except ConnectionResetError:
                            pass
                    start = time.monotonic()
                    server.shutdown()
                    server.server_close()
                    self.assertLess(time.monotonic()-start,1)
                    self.assertEqual(server._slots._value,8)
            finally:
                server.shutdown()
                thread.join(3)
                server.server_close()
            server.application.handle.assert_not_called()


class PackageTests(unittest.TestCase):
    def test_archive_advertising_pair_preparation_requires_full_private_contract(self):
        def load(name):
            spec = importlib.util.spec_from_file_location(name,SOURCE/'packaging'/(name+'.py'))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module

        build, stage = load('build_release'),load('stage_release')
        with tempfile.TemporaryDirectory(prefix='backend-package-') as root:
            package = build.build_release(SOURCE,Path(root))
            with Path(package['artifact']).open('rb') as file:
                inventory, manifest, initializer, commands = stage._scan(file)
            self.assertIn(build.RECOVERY_BACKEND_COMMAND,commands)
            self.assertLessEqual(len(manifest['files']),512)
            self.assertTrue(build.RECOVERY_BACKEND_MEMBERS <= set(manifest['files']))
            stage._manifest(inventory,manifest,initializer,package['version'],runtime_https=commands)
            missing = set(build.RECOVERY_BACKEND_MEMBERS) - build.RECOVERY_HTTPS_MEMBERS
            edited = {name:value for name,value in manifest['files'].items() if name not in missing}
            scanned = {name:value for name,value in inventory.items() if name not in missing}
            with self.assertRaises(stage.StageError):
                stage._manifest(scanned,{**manifest,'files':edited},initializer,package['version'],runtime_https=commands)
            self.assertFalse(any(name.endswith('.pem') or 'pair.json' in name for name in inventory))


if __name__=='__main__':
    unittest.main()
