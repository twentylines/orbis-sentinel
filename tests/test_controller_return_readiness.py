"""Socket-free production Gateway and listener readiness regressions."""

from contextlib import ExitStack, contextmanager
import json
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from orbis_sentinel import recovery_gateway as gateway
from orbis_sentinel import recovery_https_edge as edge
from orbis_sentinel import recovery_listener_install as listener
from orbis_sentinel import recovery_runtime as runtime
from orbis_sentinel.bootstrap_control import RootBootstrapControl, _SCHEMA
from orbis_sentinel.controller_return_readiness import (
    APPROVAL, ARM, READINESS, RETURN, ControllerReturnGateway, readiness_reply,
)
from orbis_sentinel.controller_return_transport import READINESS_PATH, RETURN_PATH
from orbis_sentinel.observer import HANDOFF_SCHEMA, unavailable_handoff
from orbis_sentinel.recovery_backend_tls import ListenerPeer
from orbis_sentinel.recovery_bootstrap import RecoveryBootstrap
import test_recovery_sessions as session_fixture


SCOPE = {'planId': '11111111-2222-4333-8444-555555555555',
         'installationId': 'a' * 64, 'handoffSha256': 'b' * 64}
CHALLENGE = {'challenge': 'c' * 64, 'installationId': SCOPE['installationId'],
             'invocationId': 'd' * 32, 'markerSha256': 'e' * 64}
CERT = 'f' * 64


class ControllerReturnReadinessTests(unittest.TestCase):
    def setUp(self):
        self.fixture = session_fixture.RecoverySessionsTests('runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.sessions, self.origin = self.fixture.store, self.fixture.origin
        self.login = self.fixture.complete()
        self.setup = SimpleNamespace(installation=SCOPE['installationId'],
                                     sha256=CHALLENGE['markerSha256'], verify=Mock(), observe=Mock())
        self.status = Mock(return_value=self.envelope(None))
        self.controller = ControllerReturnGateway(
            self.sessions, origin=self.origin, setup=self.setup, invocation_id=CHALLENGE['invocationId'],
            handoff_status=self.status)
        self.app = gateway.RecoveryApplication(
            origin=self.origin, sessions=self.sessions, verify=Mock(), status=Mock(),
            handoff_status=self.status, controller_return=self.controller)
        bootstrap = RecoveryBootstrap.__new__(RecoveryBootstrap)
        bootstrap.store, bootstrap.origin = self.sessions, self.origin
        self.bootstrap = RootBootstrapControl(bootstrap, controller_return=self.controller)
        self.host = Mock(side_effect=self.host_reply)
        exchange = patch.object(self.controller.transport, '_exchange', self.host)
        exchange.start()
        self.addCleanup(exchange.stop)
        self.edge = SimpleNamespace(reference={'generation': 'a' * 64}, facts={'certificateSha256': CERT},
                                    context=lambda: self)
        self.https_calls = []

    @staticmethod
    def envelope(handoff):
        return {'schema': HANDOFF_SCHEMA, 'status': {'version': 1, 'handoff': handoff}, 'ageMs': 0}

    def host_reply(self, path, request, timeout, decode):
        if path == READINESS_PATH:
            value = readiness_reply(request)
            status = '200 OK'
        else:
            self.assertEqual(path, RETURN_PATH)
            value = {'version': 1, 'planId': request['planId'], 'state': 'return-accepted', 'phase': 'return-accepted',
                     'portalUrl': self.origin + gateway.BASE + '/', 'expiresAtMs': 1800000000000}
            status = '202 Accepted'
        body = json.dumps(value).encode()
        wire = f'HTTP/1.0 {status}\r\nContent-Length: {len(body)}\r\n\r\n'.encode() + body
        return decode(wire)

    def arm(self, value=CHALLENGE):
        return self.bootstrap.handle({'schema': _SCHEMA, 'operation': ARM, 'arguments': value})

    def call(self, route, document, *, login=None, csrf=None):
        headers = {'host': urlsplit(self.origin).netloc, 'origin': self.origin, 'content-type': 'application/json'}
        if login is not None:
            headers['cookie'] = self.app.prefix + 'session=' + login['token']
            headers['x-orbis-sentinel-csrf'] = login['csrfToken'] if csrf is None else csrf
        return self.app.handle('POST', gateway.API + '/' + route, headers, json.dumps(document).encode())

    @contextmanager
    def probe_edge(self, config, marker, *, live):
        self.assertTrue(live)
        yield self.edge, {'invocationId': '1' * 32}, Mock()

    def https(self, origin, context, path, kind, *, retained, document, probe=None):
        self.assertIs(context, self)
        self.assertIs(retained, self.edge)
        self.assertEqual(kind, edge.JSON)
        self.https_calls.append((path, document))
        host = urlsplit(origin).netloc
        headers = f'Host: {host}\r\nConnection: close\r\n'
        if probe is not None:
            headers += 'X-Orbis-Sentinel-Return-Probe: ' + listener.encoded(probe).hex() + '\r\n'
        payload = b'' if document is None else json.dumps(document).encode()
        if document is not None:
            headers += f'Origin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\n'
        method = 'GET' if document is None else 'POST'
        connection = Mock()
        connection.recv.return_value = f'{method} {path} HTTP/1.1\r\n{headers}\r\n'.encode() + payload
        verb, target, forwarded, body = edge._request(connection, {'origin': origin}, time.monotonic() + 2)
        reply = self.app.handle(verb, target, {key.lower(): value for key, value in forwarded.items()}, body)
        return reply.status, reply.body, reply.cookies, CERT

    def test_held_https_observation_through_deployed_routes_uses_shared_read_only_authority(self):
        self.fixture.activate_key(self.fixture.prepare_key())
        before, clock = self.sessions._db.total_changes, self.sessions._return_clock_state
        config = SimpleNamespace(data={'origin': self.origin})
        proof = {'attachment': self.edge.reference, 'invocationId': '1' * 32, 'certificateSha256': CERT}

        def arm():
            self.assertEqual(self.arm(), {'schema': _SCHEMA, 'ok': True, 'result': CHALLENGE})

        with (patch.object(listener, '_probe_edge', self.probe_edge),
              patch.object(listener, '_tls_get', self.https)):
            listener.verify_controller_return_portal(config, b'fixture marker', proof, CHALLENGE, arm)
        self.assertEqual(self.https_calls, [(gateway.API + '/' + name, document) for name, document in (
            ('handoff-status', None), (APPROVAL, {}), (RETURN, {}), (READINESS, CHALLENGE))])
        self.status.assert_called_once_with()
        self.assertEqual(self.host.call_args.args[:3], (READINESS_PATH, CHALLENGE, 3))
        self.assertEqual(self.sessions._db.total_changes, before)
        self.assertEqual(self.sessions._return_clock_state, clock)
        self.assertEqual(self.call(READINESS, CHALLENGE).status, 400)

    def test_missing_approval_authority_or_status_cannot_reach_host(self):
        for missing in ('credentials', 'observation'):
            with self.subTest(missing=missing):
                if missing == 'observation':
                    self.fixture.activate_key(self.fixture.prepare_key())
                    self.status.return_value = unavailable_handoff()
                self.assertTrue(self.arm()['ok'])
                self.assertNotEqual(self.call(READINESS, CHALLENGE).status, 200)
        self.host.assert_not_called()

    def test_missing_or_rebound_deployed_handlers_cannot_echo_readiness(self):
        self.fixture.activate_key(self.fixture.prepare_key())
        proof = {'attachment': self.edge.reference, 'invocationId': '1' * 32, 'certificateSha256': CERT}
        handle = self.app.handle
        for route in ('handoff-status', APPROVAL, RETURN):
            def missing(method, path, headers, body):
                if path == gateway.API + '/' + route:
                    path = gateway.API + '/absent-handler'
                return handle(method, path, headers, body)
            with (self.subTest(route=route), patch.object(self.app, 'handle', side_effect=missing),
                  patch.object(listener, '_probe_edge', self.probe_edge), patch.object(listener, '_tls_get', self.https),
                  self.assertRaises(Exception)):
                listener.verify_controller_return_portal(SimpleNamespace(data={'origin': self.origin}),
                    b'marker', proof, CHALLENGE, lambda: self.assertTrue(self.arm()['ok']))
        self.host.assert_not_called()
        self.assertTrue(self.arm()['ok'])
        self.app._controller_routes[('POST', gateway.API + '/' + RETURN)] = Mock()
        self.assertEqual(self.call(READINESS, CHALLENGE).status, 503)
        self.host.assert_not_called()

    def test_probe_header_needs_current_armed_nonce_and_never_creates_a_session(self):
        route = gateway.API + '/' + APPROVAL
        headers = {'host': self.app.host, 'origin': self.origin, 'content-type': 'application/json',
                   'x-orbis-sentinel-return-probe': listener.encoded(CHALLENGE).hex()}
        self.assertEqual(self.app.handle('POST', route, headers, b'{}').status, 400)
        before = self.sessions._db.total_changes
        self.assertTrue(self.arm()['ok'])
        self.assertEqual(self.app.handle('POST', route, headers, b'{}').status, 200)
        self.assertEqual(self.sessions._db.total_changes, before)
        self.assertEqual(self.app.handle('POST', route, {**headers, 'cookie': 'invalid'}, b'{}').status, 404)
        self.host.assert_not_called()

    def test_session_queue_expiry_blocks_approval_and_dispatch_before_effect(self):
        from orbis_sentinel import controller_return_readiness as binding
        self.status.return_value = {**self.envelope({'planId': SCOPE['planId'], 'state': 'held', 'returnScope': SCOPE}),
                                    'ageMs': 4000}
        grant = json.loads(self.call(APPROVAL, {'scope': SCOPE}, login=self.login).body)
        original = self.sessions._transaction
        for route, request in ((APPROVAL, {'scope': SCOPE}), (RETURN, {key: grant[key] for key in ('scope', 'approvalId')})):
            elapsed = [0.0]
            before = self.sessions._db.total_changes
            def queued(action):
                if action.__name__ in ('issue', 'read'):
                    elapsed[0] += 2
                return original(action)
            with (self.subTest(route=route), patch.object(binding, 'time', SimpleNamespace(monotonic=lambda: elapsed[0])),
                  patch.object(self.sessions, '_transaction', queued)):
                self.assertEqual(self.call(route, request, login=self.login).status, 503)
            self.assertEqual(self.sessions._db.total_changes, before)
        self.host.assert_not_called()

    def test_installed_prepublication_fence_cannot_be_mistaken_for_usable_return(self):
        self.fixture.activate_key(self.fixture.prepare_key())
        with patch.object(self.sessions, '_setup', self.setup):
            self.assertTrue(self.arm()['ok'])
            self.assertNotEqual(self.call(READINESS, CHALLENGE).status, 200)
        self.host.assert_not_called()

    def test_runtime_shares_one_controller_return_binding_only_with_paired_installed_gateway(self):
        stop = threading.Event()
        stop.set()
        backend = ListenerPeer.__new__(ListenerPeer)
        self.setup.backend = backend
        worker = Mock()
        profiles = Mock(_store=self.sessions)
        with ExitStack() as patches:
            patches.enter_context(patch.object(runtime, '_require_root'))
            patches.enter_context(patch.object(runtime, 'RecoverySessions', return_value=self.sessions))
            patches.enter_context(patch.object(runtime, 'RecoveryWorker', return_value=worker))
            patches.enter_context(patch.object(runtime, 'RecoveryProfiles', return_value=profiles))
            patches.enter_context(patch.object(ListenerPeer, 'verify'))
            patches.enter_context(patch.object(runtime.threading, 'Thread'))
            patches.enter_context(patch.dict(runtime.os.environ, {'INVOCATION_ID': CHALLENGE['invocationId']}))
            patches.enter_context(patch.object(runtime, 'RecoveryControlServer'))
            bootstrap = patches.enter_context(patch.object(runtime, 'RootBootstrapControlServer'))
            server = patches.enter_context(patch.object(runtime, 'RecoveryHTTPServer'))
            patches.enter_context(patch.object(self.sessions, 'close'))
            runtime.run_recovery(
                directory='/fixture', image_id='fixture-image', origin=self.origin, address=('127.0.0.1', 9443),
                status=Mock(), stop=stop, control=True, setup=self.setup, backend=backend,
                handoff_status=self.status, installed_listener=True)
            application = server.call_args.args[1]
            root = bootstrap.call_args.args[1]
            self.assertIs(application.controller_return, root.controller_return)
            self.assertIs(self.sessions, root.controller_return.approvals.sessions)
            self.assertEqual(root.controller_return.invocation_id, CHALLENGE['invocationId'])
            self.assertIs(root.controller_return.handoff_status, self.status)
            runtime.run_recovery(
                directory='/fixture', image_id='fixture-image', origin=self.origin, address=('127.0.0.1', 9443),
                status=Mock(), stop=stop, control=True, handoff_status=self.status, installed_listener=True)
            self.assertIsNone(server.call_args.args[1].controller_return)
            self.assertIsNone(bootstrap.call_args.args[1].controller_return)

    def test_wrong_invocation_expired_challenge_and_wrong_host_echo_are_refused(self):
        self.fixture.activate_key(self.fixture.prepare_key())
        self.assertFalse(self.arm({**CHALLENGE, 'invocationId': '2' * 32})['ok'])
        self.assertTrue(self.arm()['ok'])
        self.assertEqual(self.call(READINESS, {**CHALLENGE, 'challenge': '0' * 64}).status, 400)
        with patch('orbis_sentinel.controller_return_readiness.time.monotonic', return_value=time.monotonic() + 9):
            self.assertEqual(self.call(READINESS, CHALLENGE).status, 400)
        self.host.assert_not_called()
        self.assertTrue(self.arm()['ok'])
        self.host.return_value = readiness_reply({**CHALLENGE, 'markerSha256': '2' * 64})
        self.host.side_effect = None
        self.assertEqual(self.call(READINESS, CHALLENGE).status, 503)

    def test_fixed_browser_approval_is_session_bound_and_dispatch_projects_only_the_result(self):
        self.status.return_value = self.envelope({'planId': SCOPE['planId'], 'state': 'held', 'returnScope': SCOPE})
        self.assertEqual(self.call(APPROVAL, {'scope': SCOPE}).status, 401)
        self.assertEqual(self.call(APPROVAL, {'scope': SCOPE}, login=self.login, csrf=self.fixture.binding).status, 401)
        response = self.call(APPROVAL, {'scope': SCOPE}, login=self.login)
        self.assertEqual(response.status, 200)
        approval = json.loads(response.body)
        self.assertEqual(set(approval), {'scope', 'approvalId', 'expiresAtMs'})
        self.assertEqual(approval['scope'], SCOPE)
        self.assertLessEqual(approval['expiresAtMs'] - self.fixture.now, 60000)
        request = {key: approval[key] for key in ('scope', 'approvalId')}
        other = self.fixture.complete()
        self.assertEqual(self.call(RETURN, request, login=other).status, 401)
        self.status.return_value = unavailable_handoff()
        self.assertEqual(self.call(RETURN, request, login=self.login).status, 503)
        self.host.assert_not_called()
        self.status.return_value = self.envelope({'planId': SCOPE['planId'], 'state': 'held', 'returnScope': SCOPE})
        response = self.call(RETURN, request, login=self.login)
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.body), {'planId': SCOPE['planId'], 'phase': 'return-accepted', 'state': 'return-accepted'})
        self.assertEqual(self.host.call_args.args[:3],
                         (RETURN_PATH, {'planId': SCOPE['planId'], 'approvalId': approval['approvalId']}, 45))
        self.assertIsNone(self.sessions._db.execute('SELECT claim FROM controller_return_approvals').fetchone()[0])
        reply = self.bootstrap.handle({'schema': _SCHEMA, 'operation': 'controller-return-claim',
            'arguments': {'approvalId': approval['approvalId'], 'scope': SCOPE, 'claimId': '7' * 64}})
        self.assertTrue(reply['result']['approved'])


if __name__ == '__main__':
    unittest.main()
