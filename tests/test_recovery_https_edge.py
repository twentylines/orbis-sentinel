"""Local TLS exercises the actual edge, gateway and single Sessions owner."""

from contextlib import ExitStack, contextmanager
import errno
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from orbis_sentinel import recovery_gateway, recovery_https_edge as edge, recovery_listener_install as listener
from orbis_sentinel import bootstrap_control, recovery_backend_tls, recovery_config, recovery_control, recovery_runtime, recovery_sessions
from orbis_sentinel.bootstrap_source import decode, digest, encoded
import test_recovery_backend_tls as pair_fixture
from orbis_sentinel.status import ComponentStatus, build_status

HOST = 'recovery.test'


class FixtureListener(socket.socket):
    def listen(self, backlog):
        super().listen(backlog)
        self.listening = True

    def getsockopt(self, level, option, *args):
        try:
            return super().getsockopt(level, option, *args)
        except OSError as error:
            if (sys.platform == 'darwin' and error.errno == errno.ENOPROTOOPT and
                    (level, option) == (socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
                return int(getattr(self, 'listening', False))
            raise


class RecoveryEdgeTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix='https-edge-')
        self.addCleanup(root.cleanup)
        self.root = Path(root.name).resolve()
        self.tool = shutil.which('openssl')
        if self.tool is None:
            self.skipTest('OpenSSL is required for the local TLS fixture')
        self.chain, self.key = self.certificate('edge', HOST)
        self.backend_chain, self.backend_key = self.certificate('backend', edge.BACKEND_NAME)
        self.backend = edge.BackendTLS(self.backend_chain.read_text(),
                                     digest(ssl.PEM_cert_to_DER_cert(self.backend_chain.read_text())))
        self.context = ssl.create_default_context(cafile=str(self.chain))
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            self.upstream = reserve.getsockname()[1]
        self.sock = FixtureListener()
        self.addCleanup(self.sock.close)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.origin = f'https://{HOST}:{self.port}'
        self.config = {'schema': edge.PROFILE, 'origin': self.origin, 'bind': '127.0.0.1',
                       'allow': '127.0.0.0/8', 'upstreamPort': self.upstream}
        self.store = self.root / 'store'
        self.store.mkdir(mode=0o700)
        self.start_patch(mock.patch.object(recovery_sessions, '_OWNER_UID', os.getuid()))
        self.start_patch(mock.patch.object(recovery_runtime, '_require_root'))
        self.cookies = {}

    def start_patch(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def certificate(self, label, name):
        chain, key = self.root / (label + '-chain.pem'), self.root / (label + '-key.pem')
        subprocess.run([self.tool, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', f'/CN={name}/OU={label}', '-addext', 'subjectAltName=DNS:' + name,
                        '-keyout', str(key), '-out', str(chain)], stdin=subprocess.DEVNULL, capture_output=True,
                       timeout=10, check=True)
        return chain, key

    def start_edge(self, *, admit=True):
        config = edge.profile(encoded(self.config))
        context = edge.server_context(str(self.chain), str(self.key), HOST)
        self.server = edge.EdgeServer(self.sock, config=config, context=context, backend=self.backend if admit else None)
        thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.03))
        thread.start()

        def stop():
            self.server.shutdown()
            thread.join(5)
            self.server.server_close()
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop)

    def start_owner(self, *, enrolled=False, progress=None):
        if enrolled:
            manager = recovery_sessions.RecoverySessions(self.store)
            try:
                pending = manager.prepare_recovery_key(origin=self.origin, expected_revision=None)
                self.recovery_key = pending['recoveryKey']
                manager.activate_recovery_key(revision=pending['revision'], recovery_key=self.recovery_key, expected_revision=None)
            finally:
                manager.close()
        stop, ready = threading.Event(), threading.Event()
        errors = []
        status = build_status(ComponentStatus(None, None, 'unavailable'), ComponentStatus('0.1.0', None, 'healthy'))
        context = edge.server_context(str(self.backend_chain), str(self.backend_key), edge.BACKEND_NAME)

        class TLSGateway(recovery_gateway.RecoveryHTTPServer):
            def __init__(self, *args):
                super().__init__(*args)
                self.socket = context.wrap_socket(self.socket, server_side=True)

        self.start_patch(mock.patch.object(recovery_runtime, 'RecoveryHTTPServer', TLSGateway))

        def serve():
            try:
                recovery_runtime.run_recovery(directory=str(self.store), image_id='sha256:' + 'a' * 64,
                    origin=self.origin, address=('127.0.0.1', self.upstream), status=lambda: status,
                    stop=stop, ready=lambda _: ready.set(), progress=progress)
            except BaseException as error:
                errors.append(error)
                ready.set()

        worker = threading.Thread(target=serve)
        worker.start()

        def close():
            stop.set()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
        self.addCleanup(close)
        self.assertTrue(ready.wait(5))
        self.assertEqual(errors, [])

    @contextmanager
    def connect(self, *, origin_host=HOST, context=None):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as client:
            with (context or self.context).wrap_socket(client, server_hostname=origin_host) as peer:
                yield peer

    def request(self, route, *, method='GET', body=None, headers=(), cookies=True, request_line=None):
        host = f'{HOST}:{self.port}'
        pairs = [('Host', host), ('Connection', 'close')]
        if cookies and self.cookies:
            pairs.append(('Cookie', '; '.join(f'{key}={value}' for key, value in self.cookies.items())))
        if body is None:
            payload = b''
        else:
            payload = encoded(body)
            pairs.extend((('Origin', self.origin), ('Content-Type', 'application/json'), ('Content-Length', str(len(payload)))))
        pairs.extend(headers)
        line = f'{method} {route} HTTP/1.1' if request_line is None else request_line
        request = line + '\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in pairs) + '\r\n'
        with self.connect() as peer:
            peer.sendall(request.encode('ascii') + payload)
            result = bytearray()
            while part := peer.recv(8192):
                result.extend(part)
        head, _, content = bytes(result).partition(b'\r\n\r\n')
        status_line, *lines = head.decode('ascii').split('\r\n')
        result_headers = [tuple(line.split(': ', 1)) for line in lines]
        for header, value in result_headers:
            if header == 'Set-Cookie':
                for name, morsel in SimpleCookie(value).items():
                    if morsel['max-age'] == '0':
                        self.cookies.pop(name, None)
                    else:
                        self.cookies[name] = morsel.value
        return int(status_line.split(' ')[1]), result_headers, content

    def test_real_key_sign_in_action_and_logout_through_independent_edge(self):
        sample = {'schema': 'orbis-sentinel.progress.v1', 'available': True, 'ageMs': 0, 'sourceState': 'ready',
                  'progress': {'version': 1, 'job': {'id': '12345678-1234-4123-8123-123456789abc', 'state': 'running',
                                                 'targetTag': 'v0.8.8', 'phase': 'restarting'}}}
        self.start_owner(enrolled=True, progress=lambda: sample)
        self.start_edge()
        with self.assertRaises(BlockingIOError):
            recovery_sessions.RecoverySessions(self.store)
        base, api = recovery_gateway.BASE, recovery_gateway.API
        self.assertEqual(self.request(api + '/progress')[0], 401)
        code, headers, body = self.request(base + '/')
        self.assertEqual((code, body), (200, recovery_gateway._asset('recovery.html')))
        self.assertTrue(any('HttpOnly' in value for key, value in headers if key == 'Set-Cookie'))
        code, _, body = self.request(api + '/options')
        self.assertEqual(code, 200)
        self.assertTrue(json.loads(body)['recoveryKey'])
        code, _, body = self.request(api + '/challenge', method='POST', body={'method': 'recovery-key'})
        self.assertEqual(code, 200)
        code, _, body = self.request(api + '/login', method='POST', body={'challenge': json.loads(body)['challenge'],
            'credentials': {'method': 'recovery-key', 'recoveryKey': self.recovery_key}})
        self.assertEqual((code, json.loads(body)), (200, {'authenticated': True}))
        self.assertEqual(self.request(api + '/status')[0], 200)
        code, _, body = self.request(api + '/progress')
        self.assertEqual((code, json.loads(body)), (200, sample))
        self.assertEqual(self.request(api + '/progress', method='POST', body={})[0], 404)
        self.assertEqual(self.request(api + '/active', method='POST', body={})[0], 401)
        csrf = ('X-Orbis-Sentinel-Csrf', self.cookies[edge.COOKIE_NAMES[2]])
        self.assertEqual(self.request(api + '/active', method='POST', body={}, headers=(csrf,))[0], 200)
        self.assertEqual(self.request(api + '/logout', method='POST', body={}, headers=(csrf,))[0], 200)
        self.assertEqual(self.request(api + '/status')[0], 401)
        self.assertEqual(self.request(api + '/progress')[0], 401)

    def test_unavailable_then_complete_D2a_signed_out_probe_through_same_edge(self):
        self.start_edge()
        status, headers, _ = self.request(recovery_gateway.BASE + '/')
        self.assertEqual(status, 503)
        self.assertFalse(any(name == 'Set-Cookie' for name, _ in headers))
        self.start_owner()
        actual = socket.getaddrinfo

        def look_up(host, *args, **options):
            return actual('127.0.0.1' if host == HOST else host, *args, **options)

        assets = {name: digest(recovery_gateway._asset(name)) for name in listener.ASSETS}
        with mock.patch.object(socket, 'getaddrinfo', side_effect=look_up):
            observed = listener.signed_out_https(self.origin, assets, context=self.context)
        self.assertEqual(observed['certificateSha256'],
                         digest(ssl.PEM_cert_to_DER_cert(self.chain.read_text())))

    def test_no_redirect_query_encoded_path_unlisted_verb_or_spoof_headers(self):
        self.start_owner()
        self.start_edge()
        base, api = recovery_gateway.BASE, recovery_gateway.API
        attempts = (
            (base + '/?probe=1', {}),
            ('/sentinel/%72ecovery/', {}),
            ('/sentinel/capture/abcd', {}),
            (api + '/restart', {'method': 'POST', 'body': {}}),
            (base + '/', {'method': 'CONNECT'}),
            (base + '/', {'request_line': f'GET {self.origin}{base}/ HTTP/1.1'}),
            (base + '/', {'headers': (('Host', 'ordinary.test'),)}),
            (base + '/', {'headers': (('Origin', 'https://ordinary.test'),)}),
            (base + '/', {'headers': (('Forwarded', 'for=127.0.0.1'),)}),
            (base + '/', {'headers': (('X-Forwarded-Host', 'ordinary.test'),)}),
            (base + '/', {'headers': (('Upgrade', 'websocket'),)}),
            (base + '/', {'headers': (('Transfer-Encoding', 'chunked'),)}),
            (base + '/', {'headers': (('Content-Length', '2'), ('Content-Length', '0'))}),
        )
        for target, options in attempts:
            with self.subTest(target=target, options=options):
                code, headers, _ = self.request(target, **options)
                self.assertIn(code, (400, 404))
                self.assertFalse(any(name == 'Set-Cookie' for name, _ in headers))

    def test_requires_expected_sni_and_a_real_trust_chain(self):
        self.start_edge()
        with self.assertRaises(ssl.SSLError), self.connect(origin_host='ordinary.test'):
            self.fail('Foreign SNI accepted')
        with self.assertRaises(ssl.SSLCertVerificationError), self.connect(context=ssl.create_default_context()):
            self.fail('Unknown local test CA trusted by default')

    def test_queue_full_is_closed_until_one_bounded_worker_releases(self):
        self.start_owner()
        self.start_patch(mock.patch.object(edge, 'MAX_CONNECTIONS', 2))
        self.start_edge()
        stalled = [socket.create_connection(('127.0.0.1', self.port), timeout=1) for _ in range(2)]
        for client in stalled:
            self.addCleanup(client.close)
        end = time.monotonic() + 1
        while self.server._slots._value and time.monotonic() < end:
            time.sleep(0.01)
        self.assertEqual(self.server._slots._value, 0)
        with socket.create_connection(('127.0.0.1', self.port), timeout=1) as excess:
            self.assertEqual(excess.recv(1), b'')
        for client in stalled:
            client.close()
        end = time.monotonic() + 1
        while not self.server._slots._value and time.monotonic() < end:
            time.sleep(0.01)
        self.assertEqual(self.request(recovery_gateway.BASE + '/')[0], 200)

    def test_config_and_inherited_tuple_cannot_choose_a_different_host_or_socket(self):
        for changed in ({'origin': f'https://127.0.0.1:{self.port}'}, {'bind': '0.0.0.0'},
                        {'bind': '192.168.1.2', 'allow': '0.0.0.0/0'}, {'upstreamPort': self.port},
                        {'upstreamPort': 443}, {'origin': f'{self.origin}/'},
                        {'origin': f'https://user@{HOST}:{self.port}'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                edge.profile(encoded({**self.config, **changed}))
        context = edge.server_context(str(self.chain), str(self.key), HOST)
        with self.assertRaises(ValueError):
            edge.EdgeServer(self.sock, config={**self.config, 'origin': f'https://{HOST}:9443'}, context=context)

    def test_edge_rejects_upstream_cookie_and_never_forwards_unrelated_browser_cookie(self):
        chosen = 'B' * 43
        self.assertEqual(edge._request_cookie(f'x=ordinary; {edge.COOKIE_NAMES[0]}={chosen}'), f'{edge.COOKIE_NAMES[0]}={chosen}')
        with self.assertRaises(ValueError):
            edge._response_cookies([f'{edge.COOKIE_NAMES[0]}={chosen}; Path=/; HttpOnly; Secure; SameSite=Strict; '
                                    'Max-Age=3600; Domain=recovery.test'])
        with self.assertRaises(ValueError):
            edge._response_cookies([f'ordinary={chosen}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600'])

    def stand_in(self, operation):
        gateway = socket.socket()
        self.addCleanup(gateway.close)
        gateway.bind(('127.0.0.1', self.upstream))
        gateway.listen(1)
        gateway.settimeout(0.5)
        received, errors = [], []

        def run():
            try:
                with gateway.accept()[0] as peer:
                    peer.settimeout(2)
                    received.append(operation(peer))
            except TimeoutError:
                pass
            except Exception as error:
                errors.append(error)
        peer = threading.Thread(target=run)
        peer.start()
        self.addCleanup(lambda: peer.join(3))
        return peer, received, errors

    def login_canary(self):
        return self.request(recovery_gateway.API + '/login', method='POST', body={'fixture': 'credential-canary'},
            headers=(('Cookie', edge.COOKIE_NAMES[0] + '=' + 'A' * 43),))

    def test_production_transport_has_no_outbound_connection_before_backend_admission(self):
        self.start_edge(admit=False)
        peer, received, errors = self.stand_in(lambda connection: connection.recv(4096))
        status, headers, _ = self.login_canary()
        self.assertEqual(status, 503)
        self.assertFalse(any(name == 'Set-Cookie' for name, _ in headers))
        peer.join(2)
        self.assertEqual((received, errors), ([], []))

    def test_unencrypted_impostor_gets_only_tls_handshake_and_no_HTTP_or_credential(self):
        self.start_edge()

        def clear(connection):
            hello = connection.recv(4096)
            connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
            return hello
        peer, received, errors = self.stand_in(clear)
        self.assertEqual(self.login_canary()[0], 503)
        peer.join(2)
        self.assertEqual(errors, [])
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0][0], 0x16)
        self.assertNotIn(b'credential-canary', received[0])
        self.assertNotIn(b'Cookie:', received[0])

    def start_pending_owner(self):
        fixture = pair_fixture.Pairs()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.config_body.update(origin=self.origin,listenPort=self.upstream)
        fixture.marker_body.update(origin=self.origin,configSha256=digest(encoded(fixture.config_body)))
        fixture.plan['scope']['origin'] = self.origin
        fixture.plan.update(listenPort=self.upstream,configSha256=fixture.marker_body['configSha256'],
                            markerSha256=digest(encoded(fixture.marker_body)))
        pair_sha = fixture.prepare()
        fixture.write(fixture.config,encoded(fixture.config_body))
        fixture.write(fixture.marker,encoded(fixture.marker_body))
        profile = encoded(self.config)
        resources = ExitStack()
        self.addCleanup(resources.close)
        pair = resources.enter_context(recovery_backend_tls.held_prepared_pair(
            fixture.plan,{**fixture.intent,'pairSha256':pair_sha}))
        self.assertEqual(pair.manifest['binding']['operationId'],pair_fixture.OP)
        settings = resources.enter_context(recovery_config.RecoveryConfig(fixture.config))
        setup = resources.enter_context(listener.setup_profile(settings,fixture.config))
        credentials = self.root/'credential-copy'
        credentials.mkdir(mode=0o700)
        envelope = pair.envelope(digest(profile),edge._leaf_hash(self.chain.read_bytes()))
        mapping = dict(zip(edge.TRUST_FILES,(profile,self.chain.read_bytes(),self.key.read_bytes())))
        mapping.update(zip(edge.BACKEND_FILES,(encoded(envelope),*( (pair.authority/name).read_bytes()
                       for name in ('ca.pem','client.pem','client-key.pem')))))
        for name,body in mapping.items():
            fixture.write(credentials/name,body)
            (credentials/name).chmod(0o400)
        descriptor = os.open(credentials,os.O_RDONLY|os.O_DIRECTORY)
        resources.callback(os.close,descriptor)
        base = []
        for name in edge.TRUST_FILES:
            held = edge._credential(descriptor,name,65536)
            resources.callback(os.close,held[0])
            base.append(held)
        self.backend = edge._pending_backend(descriptor,base,resources,self.config)
        self.assertIs(type(self.backend),edge.PendingBackendTLS)

        stop, ready, errors = threading.Event(), threading.Event(), []
        self.start_patch(mock.patch.object(bootstrap_control,'_OWNER_UID',os.getuid()))
        self.start_patch(mock.patch.object(recovery_control,'_OWNER_UID',os.getuid()))
        def serve():
            try:
                recovery_runtime.run_recovery(directory=str(fixture.recovery),image_id=pair_fixture.IMAGE,
                    origin=self.origin,address=('127.0.0.1',self.upstream),status=lambda:{},stop=stop,
                    ready=lambda _:ready.set(),control=True,installed_listener=True,setup=setup,backend=setup.backend)
            except BaseException as error:
                errors.append(error)
                ready.set()
        thread = threading.Thread(target=serve)
        thread.start()
        def drain():
            stop.set()
            thread.join(4)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors,[])
        self.addCleanup(drain)
        self.assertTrue(ready.wait(4))
        self.assertEqual(errors,[])
        return fixture,setup,credentials

    def test_production_pending_mtls_routes_and_exact_peer_before_http(self):
        fixture,setup,credentials = self.start_pending_owner()
        self.start_edge()
        with self.assertRaises(BlockingIOError):
            recovery_sessions.RecoverySessions(fixture.recovery,setup=setup)
        with mock.patch.object(self.backend,'authenticate',wraps=self.backend.authenticate) as connect:
            self.assertEqual(self.request(recovery_gateway.API+'/status')[0],503)
            self.assertEqual(self.login_canary()[0],503)
            self.assertEqual(self.request(recovery_gateway.BASE+'/',headers=(('Cookie',edge.COOKIE_NAMES[1]+'='+'a'*43),))[0],503)
            connect.assert_not_called()
            status,headers,_ = self.request(recovery_gateway.BASE+'/')
            self.assertEqual(status,200)
            self.assertIn(edge.COOKIE_NAMES[0],self.cookies)
            self.assertTrue(all(value.startswith(edge.COOKIE_NAMES[0]+'=') for name,value in headers if name=='Set-Cookie'))
            self.assertEqual(self.request(recovery_gateway.API+'/session')[0],200)
            self.assertEqual(self.request(recovery_gateway.API+'/options')[0],401)
            self.assertEqual(connect.call_count,3)
            (credentials/'backend-client').rename(credentials/'foreign-copy')
            self.assertEqual(self.request(recovery_gateway.BASE+'/')[0],503)
            self.assertEqual(connect.call_count,3)

    def test_trusted_name_terminating_relay_still_needs_exact_backend_leaf_before_HTTP(self):
        relay_chain, relay_key = self.certificate('relay', edge.BACKEND_NAME)
        known = self.backend_chain.read_text()
        self.backend = edge.BackendTLS(known + relay_chain.read_text(), digest(ssl.PEM_cert_to_DER_cert(known)))
        self.start_edge()
        context = edge.server_context(str(relay_chain), str(relay_key), edge.BACKEND_NAME)
        # The stand-in must finish its handshake before testing that no HTTP was sent.
        # TLS 1.3 can still be writing a session ticket when the edge closes the socket.
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.options |= ssl.OP_NO_TICKET
        established = []

        def relay(connection):
            with context.wrap_socket(connection, server_side=True) as secured:
                established.append(True)
                # A terminating proxy cannot forward plaintext it never receives.
                try:
                    return secured.recv(4096)
                except ConnectionResetError:
                    # The client can reject the leaf while a TLS ticket is in flight.
                    return b''
        peer, received, errors = self.stand_in(relay)
        self.assertEqual(self.login_canary()[0], 503)
        peer.join(2)
        self.assertEqual(errors, [])
        self.assertEqual(established, [True])
        self.assertEqual(received, [b''])


if __name__ == '__main__':
    unittest.main()
