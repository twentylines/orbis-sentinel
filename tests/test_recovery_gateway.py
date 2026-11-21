import http.client
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
import json
import os
import secrets
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

from orbis_sentinel import recovery_gateway as gateway
from orbis_sentinel import recovery_sessions as recovery
from orbis_sentinel.status import ComponentStatus, build_status


class RecoveryGatewayTests(unittest.TestCase):
    def test_configuration_refusal_precedes_session_or_authentication_work(self):
        self.app.check = mock.Mock(side_effect=ValueError('private-configuration-detail'))
        with mock.patch.object(self.store, 'authentication_options') as options:
            reply = self.call(gateway.API + '/options')
        self.assertEqual(reply.status, 503)
        self.assertNotIn(b'private-configuration-detail', reply.body)
        options.assert_not_called()
        self.verifier.assert_not_called()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        patch = mock.patch.object(recovery, '_OWNER_UID', os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.now = 1_800_000_000_000
        self.store = recovery.RecoverySessions(self.temp.name, clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.profile = {'identitySha256': 'a' * 64, 'revision': 'b' * 64, 'accountId': 1,
                        'origin': 'https://recovery.example', 'totpEnabled': False,
                        'requireTotpAfterPasskey': False, 'credentials': {'credential': 3}}
        self.store.enroll(self.profile)
        self.observed = build_status(ComponentStatus(None, None, 'unavailable'), ComponentStatus('0.1.0-dev.12', None, 'healthy'))
        self.verifier = mock.Mock(side_effect=self.proof)
        self.app = gateway.RecoveryApplication(origin=self.profile['origin'], sessions=self.store,
                                              verify=self.verifier, status=lambda: self.observed)
        self.cookies = {}

    def proof(self, digest, nonce, request):
        if request.get('password') != 'synthetic-password':
            return {'schema': 'orbis.sentinel-authentication.v1', 'verified': False}
        return {'schema': 'orbis.sentinel-authentication.v1', 'verified': True, 'accountId': 1,
                'revision': self.profile['revision'], 'identitySha256': digest, 'challenge': nonce,
                'method': 'password', 'verifiedAtMs': self.now, 'totpStep': None, 'credential': None}

    def call(self, path, body=None, *, extra=None, method=None):
        headers = {'host': 'recovery.example', 'cookie': '; '.join(k + '=' + v for k, v in self.cookies.items())}
        if body is not None:
            headers.update(origin=self.profile['origin'], **{'content-type': 'application/json'})
        headers.update(extra or {})
        reply = self.app.handle(method or ('POST' if body is not None else 'GET'), path, headers,
                                b'' if body is None else json.dumps(body).encode())
        for value in reply.cookies:
            parsed = SimpleCookie(value)
            for name, morsel in parsed.items():
                if morsel['max-age'] == '0':
                    self.cookies.pop(name, None)
                else:
                    self.cookies[name] = morsel.value
        return reply

    def begin(self):
        self.assertEqual(self.call(gateway.BASE + '/').status, 200)
        self.assertEqual(self.call(gateway.API + '/options').status, 200)
        reply = self.call(gateway.API + '/challenge', {'method': 'password'})
        self.assertEqual(reply.status, 200)
        return json.loads(reply.body)['challenge']

    def login(self):
        nonce = self.begin()
        reply = self.call(gateway.API + '/login', {'challenge': nonce, 'credentials': {'method': 'password', 'username': 'operator', 'password': 'synthetic-password'}})
        self.assertEqual(reply.status, 200)
        return reply

    def csrf(self):
        return {'x-orbis-sentinel-csrf': self.cookies[self.app.prefix + 'csrf']}

    def test_actual_session_store_login_status_reload_logout_and_second_login(self):
        reply = self.login()
        self.assertEqual(json.loads(reply.body), {'authenticated': True})
        self.assertNotIn(b'token', reply.body)
        self.assertEqual(self.call(gateway.API + '/status').body, gateway._json(200, self.observed).body)
        self.call(gateway.BASE + '/')
        self.assertTrue(json.loads(self.call(gateway.API + '/session').body)['authenticated'])
        self.assertEqual(self.call(gateway.API + '/logout', {}, extra=self.csrf()).status, 200)
        self.assertEqual(self.call(gateway.API + '/status').status, 401)
        self.login()

    def enroll_key(self):
        pending = self.store.prepare_recovery_key(origin=self.profile['origin'], expected_revision=None)
        self.store.activate_recovery_key(revision=pending['revision'], recovery_key=pending['recoveryKey'], expected_revision=None)
        return pending

    def key_login(self, key):
        self.assertEqual(self.call(gateway.BASE + '/').status, 200)
        issued = self.call(gateway.API + '/challenge', {'method': 'recovery-key'})
        self.assertEqual(issued.status, 200)
        return self.call(gateway.API + '/login', {'challenge': json.loads(issued.body)['challenge'],
                                                'credentials': {'method': 'recovery-key', 'recoveryKey': key}})

    def test_emergency_sign_in_remains_available_with_main_identity_and_worker_unavailable(self):
        key = self.enroll_key()
        self.store.revoke()
        self.verifier.side_effect = RuntimeError('Main Orbis runtime is unavailable')
        options = json.loads(self.call(gateway.API + '/options').body)
        self.assertEqual(options, {'password': False, 'passkey': False, 'recoveryKey': True,
                                   'totp': {'password': False, 'passkey': False}})
        self.assertEqual(self.key_login(key['recoveryKey']).status, 200)
        self.verifier.assert_not_called()
        session = json.loads(self.call(gateway.API + '/session').body)
        self.assertTrue(session['authenticated'])
        self.assertEqual(session['method'], 'recovery-key')
        self.assertEqual(self.call(gateway.API + '/status').status, 200)
        self.assertEqual(self.call(gateway.API + '/logout', {}, extra=self.csrf()).status, 200)
        self.assertEqual(self.call(gateway.API + '/status').status, 401)

    def test_emergency_key_has_independent_admission_while_operator_crypto_is_busy(self):
        key = self.enroll_key()
        nonce = self.begin()
        headers = {'host': 'recovery.example', 'origin': self.profile['origin'], 'content-type': 'application/json',
                   'cookie': '; '.join(k + '=' + v for k, v in self.cookies.items())}
        body = json.dumps({'challenge': nonce, 'credentials': {'method': 'password', 'password': 'synthetic-password'}}).encode()
        entered, release = threading.Event(), threading.Event()
        def blocked(*args):
            entered.set()
            if not release.wait(timeout=5):
                raise RuntimeError('Synthetic verifier did not release')
            return self.proof(*args)
        self.verifier.side_effect = blocked
        with ThreadPoolExecutor(max_workers=2) as pool:
            operator = pool.submit(self.app.handle, 'POST', gateway.API + '/login', headers, body)
            try:
                self.assertTrue(entered.wait(timeout=2))
                emergency = pool.submit(self.key_login, key['recoveryKey']).result(timeout=2)
                self.assertEqual(emergency.status, 200)
                self.assertFalse(operator.done())
                self.assertEqual(self.app.handle('POST', gateway.API + '/login', headers, body).status, 429)
            finally:
                release.set()
            self.assertEqual(operator.result(timeout=2).status, 200)

    def test_emergency_key_never_appears_in_responses_and_cannot_grant_host_actions(self):
        key = self.enroll_key()
        reply = self.key_login(key['recoveryKey'])
        self.assertEqual(reply.status, 200)
        self.assertNotIn(key['recoveryKey'].encode(), reply.body)
        self.assertNotIn(key['recoveryKey'], str(reply.cookies))
        for route in ('/restart', '/restore', '/enroll', '/recovery-key', '/recovery-key/rotate'):
            self.assertEqual(self.call(gateway.API + route, {}, extra=self.csrf()).status, 404)
        self.verifier.assert_not_called()

    def test_key_challenge_cannot_use_an_orbis_proof_or_browser_supplied_authority(self):
        key = self.enroll_key()
        self.call(gateway.BASE + '/')
        nonce = json.loads(self.call(gateway.API + '/challenge', {'method': 'recovery-key'}).body)['challenge']
        body = {'challenge': nonce, 'credentials': {'method': 'recovery-key', 'recoveryKey': key['recoveryKey'], 'verified': True}}
        self.assertEqual(self.call(gateway.API + '/login', body).status, 400)
        body['credentials'] = {'method': 'password', 'username': 'operator', 'password': 'synthetic-password'}
        self.assertEqual(self.call(gateway.API + '/login', body).status, 401)
        self.verifier.assert_not_called()
        body['credentials'] = {'method': 'recovery-key', 'recoveryKey': key['recoveryKey']}
        self.assertEqual(self.call(gateway.API + '/login', body).status, 200)

    def test_host_origin_csrf_and_json_type_enforcement(self):
        self.login()
        for extra in [{'host': 'other.example'}, {'origin': 'https://other.example'}, {'origin': 'null'}, {'content-type': 'text/plain'}]:
            with self.subTest(extra=extra):
                self.assertIn(self.call(gateway.API + '/logout', {}, extra=extra).status, (400, 403))
        for extra in [{}, {'x-orbis-sentinel-csrf': secrets.token_urlsafe(32)}]:
            self.assertEqual(self.call(gateway.API + '/logout', {}, extra=extra).status, 401)
        self.assertEqual(self.call(gateway.API + '/status').status, 200)

    def test_failures_do_not_echo_credentials_and_consume_nonce(self):
        nonce = self.begin()
        body = {'challenge': nonce, 'credentials': {'method': 'password', 'password': 'secret-synthetic-wrong-value'}}
        first = self.call(gateway.API + '/login', body)
        self.assertEqual(first.status, 401)
        self.assertNotIn(b'secret-synthetic-wrong-value', first.body)
        self.assertEqual(self.call(gateway.API + '/login', body).status, 401)
        self.assertEqual(self.verifier.call_count, 1)

    def test_profile_digest_and_proof_cannot_be_supplied_by_the_browser(self):
        nonce = self.begin()
        for extra in [{'identitySha256': 'f' * 64}, {'verified': True}, {'profile': self.profile}]:
            body = {'challenge': nonce, 'credentials': {'method': 'password'}, **extra}
            self.assertEqual(self.call(gateway.API + '/login', body).status, 400)
        self.verifier.assert_not_called()

    def test_unknown_and_duplicate_json_fields_are_rejected_before_verification(self):
        self.begin()
        headers = {'host': 'recovery.example', 'origin': self.profile['origin'], 'content-type': 'application/json'}
        reply = self.app.handle('POST', gateway.API + '/challenge', headers, b'{"method":"password","method":"passkey"}')
        self.assertEqual(reply.status, 400)
        self.assertEqual(self.call(gateway.API + '/challenge', {'method': 'password', 'path': '/another/profile'}).status, 400)
        self.verifier.assert_not_called()

    def test_public_options_are_filtered_and_passkey_options_are_root_bound(self):
        self.begin()
        reply = self.call(gateway.API + '/options')
        self.assertEqual(json.loads(reply.body), {'password': True, 'recoveryKey': False,
                                                'passkey': True, 'totp': {'password': False, 'passkey': False}})
        issued = json.loads(self.call(gateway.API + '/challenge', {'method': 'passkey'}).body)
        self.assertEqual(issued['publicKey']['rpId'], 'recovery.example')
        self.assertEqual(issued['publicKey']['userVerification'], 'required')
        self.assertEqual(issued['publicKey']['challenge'], issued['challenge'])
        self.assertNotIn('identitySha256', issued)

    def test_automatic_status_checks_never_extend_idle_session_lifetime(self):
        self.login()
        for _ in range(4):
            self.now += 200_000
            self.assertEqual(self.call(gateway.API + '/status').status, 200)
        self.now += 100_001
        self.assertEqual(json.loads(self.call(gateway.API + '/session').body), {'authenticated': False})
        self.assertEqual(self.call(gateway.API + '/status').status, 401)

    def progress(self):
        return {'schema': 'orbis-sentinel.progress.v1', 'available': True, 'ageMs': 20, 'sourceState': 'ready',
                'progress': {'version': 1, 'job': {'id': '12345678-1234-4123-8123-123456789abc', 'state': 'running',
                                               'targetTag': 'v0.8.8', 'phase': 'restarting'}}}

    def test_progress_is_authenticated_read_only_and_independent_of_main(self):
        provider = mock.Mock(return_value=self.progress())
        self.app.progress = provider
        self.assertEqual(self.call(gateway.API + '/progress').status, 401)
        provider.assert_not_called()
        self.login()
        result = self.call(gateway.API + '/progress')
        self.assertEqual(result.status, 200)
        self.assertEqual(json.loads(result.body), self.progress())
        self.assertEqual(self.call(gateway.API + '/progress', {}, extra=self.csrf()).status, 404)
        self.assertEqual(self.call(gateway.API + '/progress?restart=1').status, 404)
        provider.assert_called_once()

    def test_missing_progress_provider_reports_unavailable_without_disabling_sign_in(self):
        self.login()
        result = self.call(gateway.API + '/progress')
        self.assertEqual(result.status, 200)
        self.assertEqual(json.loads(result.body), {'schema': 'orbis-sentinel.progress.v1', 'available': False,
                                                  'progress': None, 'ageMs': None, 'sourceState': 'unavailable'})
        self.assertEqual(self.call(gateway.API + '/status').status, 200)

    def test_observer_startup_is_a_valid_unavailable_observation(self):
        self.login()
        starting = {'schema': 'orbis-sentinel.progress.v1', 'available': False, 'progress': None, 'ageMs': None, 'sourceState': 'starting'}
        self.app.progress = lambda: starting
        reply = self.call(gateway.API + '/progress')
        self.assertEqual(reply.status, 200)
        self.assertEqual(json.loads(reply.body), starting)
        self.app.progress = lambda: {**starting, 'ageMs': 0}
        self.assertEqual(self.call(gateway.API + '/progress').status, 503)

    def test_malformed_stale_or_private_progress_never_reaches_the_browser(self):
        self.login()
        for field, bad in (('available', 1), ('ageMs', True), ('ageMs', 5001), ('ageMs', None),
                           ('sourceState', 'stale'), ('privatePath', self.temp.name)):
            self.app.progress = lambda field=field, bad=bad: {**self.progress(), field: bad}
            with self.subTest(field=field):
                reply = self.call(gateway.API + '/progress')
                self.assertEqual(reply.status, 503)
                self.assertNotIn(self.temp.name.encode(), reply.body)
        invalid = self.progress()
        invalid['progress']['job']['phase'] = 'private'
        self.app.progress = lambda: invalid
        self.assertEqual(self.call(gateway.API + '/progress').status, 503)
        self.app.progress = mock.Mock(side_effect=RuntimeError(self.temp.name))
        self.assertNotIn(self.temp.name.encode(), self.call(gateway.API + '/progress').body)

    def test_progress_polling_never_touches_session_and_revocation_blocks_the_result(self):
        self.login()
        self.app.progress = mock.Mock(return_value=self.progress())
        for _ in range(4):
            self.now += 200_000
            self.assertEqual(self.call(gateway.API + '/progress').status, 200)
        self.now += 100_001
        self.assertEqual(self.call(gateway.API + '/progress').status, 401)
        self.assertEqual(self.app.progress.call_count, 4)
        self.login()
        def revoked():
            self.store.logout(token=self.cookies[self.app.prefix + 'session'], origin=self.profile['origin'],
                              csrf=self.cookies[self.app.prefix + 'csrf'])
            return self.progress()
        self.app.progress = revoked
        reply = self.call(gateway.API + '/progress')
        self.assertEqual(reply.status, 401)
        self.assertNotIn(b'targetTag', reply.body)

    def test_explicit_user_activity_requires_csrf_and_refreshes_idle_deadline(self):
        self.login()
        self.now += 800_000
        self.assertEqual(self.call(gateway.API + '/active', {}).status, 401)
        self.assertEqual(self.call(gateway.API + '/active', {}, extra=self.csrf()).status, 200)
        self.now += 800_000
        self.assertEqual(self.call(gateway.API + '/status').status, 200)

    def test_logout_after_idle_expiry_and_repeated_anonymous_logout_remain_usable(self):
        self.login()
        csrf = self.csrf()
        self.now += 900_001
        self.assertEqual(self.call(gateway.API + '/logout', {}, extra=csrf).status, 200)
        self.assertEqual(self.call(gateway.API + '/logout', {}).status, 200)
        self.assertEqual(self.call(gateway.API + '/status').status, 401)
        self.login()

    def test_unavailable_or_malformed_status_never_becomes_a_successful_observation(self):
        self.login()
        self.observed = {'schema': 'other', 'components': {}}
        self.assertEqual(self.call(gateway.API + '/status').status, 503)

    def test_worker_or_cleanup_failure_never_issues_browser_authority(self):
        nonce = self.begin()
        self.verifier.side_effect = RuntimeError('Synthetic cleanup uncertainty with private diagnostics')
        reply = self.call(gateway.API + '/login', {'challenge': nonce, 'credentials': {'method': 'password'}})
        self.assertEqual(reply.status, 503)
        self.assertEqual(reply.cookies, ())
        self.assertNotIn(b'private diagnostics', reply.body)
        self.assertEqual(json.loads(self.call(gateway.API + '/session').body), {'authenticated': False})
        self.assertEqual(self.call(gateway.API + '/status').status, 401)

    def test_anonymous_session_discovery_has_no_authority_and_no_error_response(self):
        self.call(gateway.BASE + '/')
        reply = self.call(gateway.API + '/session')
        self.assertEqual(reply.status, 200)
        self.assertEqual(json.loads(reply.body), {'authenticated': False})
        self.assertEqual(self.call(gateway.API + '/status').status, 401)
        self.verifier.assert_not_called()

    def test_parallel_credential_work_is_rejected_before_a_second_worker(self):
        nonce = self.begin()
        self.app._verification.acquire()
        try:
            self.assertEqual(self.call(gateway.API + '/login', {'challenge': nonce, 'credentials': {}}).status, 429)
        finally:
            self.app._verification.release()
        self.verifier.assert_not_called()

    def test_secure_cookie_policy_and_tampered_cookie_recovery(self):
        reply = self.login()
        for value in reply.cookies:
            self.assertIn('__Host-orbis-sentinel-', value)
            self.assertIn('; Secure', value)
            self.assertIn('; SameSite=Strict', value)
            self.assertIn('; Path=/', value)
            self.assertEqual('HttpOnly' in value, '-csrf=' not in value)
        reply = self.call(gateway.BASE + '/', extra={'cookie': self.app.prefix + 'session=malformed'})
        self.assertEqual(reply.status, 200)
        self.assertTrue(any('Max-Age=0' in value for value in reply.cookies))

    def test_fixed_assets_and_no_lifecycle_or_unsafe_origin_listener(self):
        for path in ['recovery.css', 'recovery.js']:
            self.assertEqual(self.call(gateway.ASSETS + path).status, 200)
        self.assertNotEqual(self.call(gateway.ASSETS + '../recovery_sessions.py').status, 200)
        self.login()
        for path in ['/restart', '/restore', '/enroll']:
            self.assertEqual(self.call(gateway.API + path, {}, extra=self.csrf()).status, 404)
        for origin in ['http://192.0.2.1', 'https://user@recovery.example', 'https://@recovery.example', 'https://recovery.example/path']:
            with self.assertRaises(ValueError):
                gateway.RecoveryApplication(origin=origin, sessions=self.store, verify=self.verifier, status=lambda: self.observed)
        with self.assertRaises(ValueError):
            gateway.RecoveryHTTPServer(('0.0.0.0', 0), self.app)

    def test_real_http_headers_body_bounds_and_ambiguous_headers(self):
        server = gateway.RecoveryHTTPServer(('127.0.0.1', 0), self.app)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
            connection.request('GET', gateway.BASE + '/', headers={'Host': 'recovery.example'})
            reply = connection.getresponse()
            self.assertEqual(reply.status, 200)
            self.assertEqual(reply.getheader('Cache-Control'), 'no-store')
            self.assertEqual(reply.getheader('Content-Security-Policy'), gateway.CSP)
            self.assertEqual(reply.getheader('X-Content-Type-Options'), 'nosniff')
            self.assertEqual(int(reply.getheader('Content-Length')), len(reply.read()))
            connection.close()
            for headers in [b'Host: recovery.example\r\nHost: other.example', b'Host: recovery.example\r\nContent-Length: 32769',
                            b'Host: recovery.example\r\nTransfer-Encoding: chunked']:
                with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as connection:
                    connection.sendall(b'GET ' + gateway.BASE.encode() + b'/ HTTP/1.1\r\n' + headers + b'\r\n\r\n')
                    self.assertIn(b'400', connection.recv(1024).split(b'\r\n')[0])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_slow_header_bytes_cannot_extend_the_whole_request_read_deadline(self):
        server = gateway.RecoveryHTTPServer(('127.0.0.1', 0), self.app)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as connection:
                connection.settimeout(0.1)
                connection.sendall(b'GET /sentinel/recovery/ HTTP/1.1\r\nHost: ')
                end = time.monotonic() + 5
                closed = False
                while time.monotonic() < end:
                    try:
                        connection.sendall(b'a')
                        if connection.recv(1024) == b'':
                            closed = True
                            break
                    except (BrokenPipeError, ConnectionResetError):
                        closed = True
                        break
                    except socket.timeout:
                        pass
                self.assertTrue(closed, 'Slow bytes must not keep a request slot indefinitely')
            self.verifier.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
