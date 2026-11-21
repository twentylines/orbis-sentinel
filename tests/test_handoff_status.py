"""Socket-free observer, cache, gateway and HTTPS route contract checks."""

import json
import threading
import time
import unittest
from unittest.mock import Mock, patch

from orbis_sentinel import observer, recovery_cli, recovery_https_edge, recovery_runtime, runtime, server
import test_recovery_gateway as gateway_tests

PLAN = '12345678-1234-4123-8123-123456789abc'
SCOPE = {'planId': PLAN, 'installationId': 'a' * 64, 'handoffSha256': 'b' * 64}
PATH = '/sentinel/recovery/api/v1/handoff-status'
STATUS_PATH = '/sentinel/api/v1/handoff-status'


def envelope(state='held'):
    handoff = {'planId': PLAN, 'state': state}
    if state == 'held':
        handoff['returnScope'] = dict(SCOPE)
    return {'schema': observer.HANDOFF_SCHEMA, 'status': {'version': 1, 'handoff': handoff}, 'ageMs': 20}


class HandoffCacheTests(unittest.TestCase):
    def test_observer_uses_one_fixed_read_and_old_helper_refuses(self):
        client = observer.ObserverClient('/run/observer/status.sock')
        with patch.object(client, '_exchange', return_value=envelope()['status']) as exchange:
            self.assertEqual(client.read_handoff(deadline=42), envelope()['status'])
            exchange.assert_called_once_with('/v4/controller-handoff/status', 42)
        with patch.object(client, '_exchange', side_effect=ValueError), self.assertRaises(ValueError):
            client.read_handoff()

    def test_cache_returns_only_fresh_exact_samples_and_clears_prior_success(self):
        collector = observer.ObserverCollector('/run/observer/status.sock')
        value = envelope()
        getter = Mock()
        collector.handoffs.snapshot = getter

        def sample(status, *, age=20, state='ready', **extras):
            getter.return_value = {'state': state, 'ageMs': age, 'sample': {
                'schema': collector.handoffs.schema, 'status': status, **extras}}
            return collector.handoff_snapshot()

        self.assertEqual(sample(value['status']), value)
        idle = {'version': 1, 'handoff': None}
        self.assertEqual(sample(idle)['status'], idle)
        for result in (sample(None), sample(value['status'], age=5001),
                       sample(value['status'], state='stale'), sample(value['status'], leaked='private')):
            self.assertEqual(result, observer.unavailable_handoff())
        collector.close()

    def test_handoff_worker_failure_clears_sample_without_touching_other_reads(self):
        output = Mock()
        client = Mock()
        client.read_handoff.side_effect = [envelope()['status'], ValueError('old observer')]
        with patch.object(observer, 'ObserverClient', return_value=client),                 patch.object(observer.time, 'sleep', side_effect=[None, InterruptedError]),                 self.assertRaises(InterruptedError):
            observer._handoff_worker(output, ('/fixed',), 2)
        samples = [json.loads(call.args[0])['sample']['status'] for call in output.send.call_args_list]
        self.assertEqual(samples, [envelope()['status'], None])
        self.assertEqual(client.read_handoff.call_count, 2)
        output.close.assert_called_once()

    def test_failed_handoff_worker_start_closes_all_three_owners(self):
        collector = observer.ObserverCollector('/run/observer/status.sock')
        collector.components = Mock()
        collector.handoffs = Mock()
        collector.handoffs.start.side_effect = RuntimeError
        with patch.object(observer.TelemetryCollector, 'start'), patch.object(observer.TelemetryCollector, 'close') as close:
            with self.assertRaises(RuntimeError):
                collector.start()
        collector.components.close.assert_called_once()
        collector.handoffs.close.assert_called_once()
        close.assert_called_once()

    def test_runtime_supplies_a_cached_reader_even_without_host_observer(self):
        for configured in (False, True):
            with self.subTest(configured=configured),                     patch.object(runtime, 'TelemetryCollector'), patch.object(runtime, 'ObserverCollector') as collector,                     patch.object(runtime, 'SentinelServer') as api, patch.object(runtime.threading, 'Event') as stop,                     patch.object(runtime.threading, 'Thread'), patch.object(runtime.signal, 'signal'):
                stop.return_value.wait.return_value = True
                collector.return_value.handoff_snapshot.return_value = envelope()
                args = ['--socket', '/run/api.sock']
                if configured:
                    args += ['--observer-socket', '/run/observer.sock']
                self.assertEqual(runtime.main(args), 0)
                read = api.call_args.args[1][STATUS_PATH]
                self.assertEqual(read(), envelope() if configured else observer.unavailable_handoff())

    def test_status_socket_route_and_cli_get_have_fixed_framing(self):
        self.assertIn(STATUS_PATH, server._ROUTES)
        api = object.__new__(server.SentinelServer)
        callback = Mock(return_value=envelope())
        api.providers = {STATUS_PATH: callback}
        api.capture_provider = None

        def request(method, target):
            conn = Mock()
            conn.recv.return_value = f'{method} {target} HTTP/1.1\r\nHost: sentinel\r\n\r\n'.encode()
            return api._request(conn, time.monotonic() + 2)

        self.assertEqual(request('GET', STATUS_PATH + '?planId=' + PLAN)[0], '404 Not Found')
        self.assertEqual(request('POST', STATUS_PATH)[0], '405 Method Not Allowed')
        callback.assert_not_called()
        status, value = request('GET', STATUS_PATH)
        self.assertEqual(status, '200 OK')
        self.assertEqual(json.loads(value), envelope())
        with patch.object(recovery_cli, '_read_observation', return_value=envelope()) as read:
            self.assertEqual(recovery_cli.read_handoff_status('/run/api.sock'), envelope())
            read.assert_called_once_with('/run/api.sock', STATUS_PATH)
            read.side_effect = ValueError('older status socket')
            self.assertEqual(recovery_cli.read_handoff_status('/run/api.sock'), observer.unavailable_handoff())
        with self.assertRaises(ValueError):
            recovery_cli._read_observation('/run/api.sock', STATUS_PATH + '?planId=' + PLAN)

    def test_recovery_runtime_passes_the_optional_provider_to_the_sole_gateway(self):
        stop = threading.Event()
        stop.set()
        read = Mock(return_value=envelope())
        with patch.object(recovery_runtime, '_require_root'), patch.object(recovery_runtime, 'RecoverySessions'),                 patch.object(recovery_runtime, 'RecoveryWorker'), patch.object(recovery_runtime, 'RecoveryProfiles'),                 patch.object(recovery_runtime, 'RecoveryApplication') as app,                 patch.object(recovery_runtime, 'RecoveryHTTPServer'), patch.object(recovery_runtime.threading, 'Thread'):
            recovery_runtime.run_recovery(directory='/configured', image_id='fixture', origin='https://recovery.example',
                                          address=('127.0.0.1', 9443), status=Mock(), stop=stop, handoff_status=read)
        self.assertIs(app.call_args.kwargs['handoff_status'], read)
        read.assert_not_called()

    def test_https_edge_allows_only_the_exact_read(self):
        def request(method, path):
            conn = Mock()
            conn.recv.return_value = f'{method} {path} HTTP/1.1\r\nHost: recovery.example\r\n\r\n'.encode()
            return recovery_https_edge._request(conn, {'origin': 'https://recovery.example'}, time.monotonic() + 2)

        self.assertEqual(request('GET', PATH), ('GET', PATH, {'Host': 'recovery.example', 'Connection': 'close'}, b''))
        for method, path in (('POST', PATH), ('GET', PATH + '/'), ('GET', PATH + '?planId=' + PLAN)):
            with self.subTest(method=method, path=path), self.assertRaises(LookupError):
                request(method, path)


class HandoffGatewayTests(unittest.TestCase):
    setUp = gateway_tests.RecoveryGatewayTests.setUp
    call = gateway_tests.RecoveryGatewayTests.call
    proof = gateway_tests.RecoveryGatewayTests.proof
    begin = gateway_tests.RecoveryGatewayTests.begin
    login = gateway_tests.RecoveryGatewayTests.login
    csrf = gateway_tests.RecoveryGatewayTests.csrf

    def test_authenticated_get_does_not_consult_component_health_or_accept_input(self):
        self.app.handoff_status = Mock(return_value=envelope())
        self.app.status = Mock(side_effect=AssertionError)
        self.assertEqual(self.call(PATH).status, 401)
        self.app.handoff_status.assert_not_called()
        self.login()
        reply = self.call(PATH)
        self.assertEqual(reply.status, 200)
        self.assertEqual(json.loads(reply.body), envelope())
        self.assertFalse(reply.cookies)
        self.assertEqual(self.call(PATH + '?planId=' + PLAN).status, 404)
        self.assertEqual(self.call(PATH, {}, extra=self.csrf()).status, 404)
        self.app.handoff_status.assert_called_once()
        self.app.status.assert_not_called()

    def test_missing_provider_and_idle_have_different_meanings(self):
        self.login()
        self.assertEqual(json.loads(self.call(PATH).body), observer.unavailable_handoff())
        idle = {'schema': observer.HANDOFF_SCHEMA, 'status': {'version': 1, 'handoff': None}, 'ageMs': 0}
        self.app.handoff_status = lambda: idle
        self.assertEqual(json.loads(self.call(PATH).body), idle)

    def test_malformed_stale_cross_plan_or_private_observations_never_reach_browser(self):
        self.login()
        missing_scope = envelope()
        del missing_scope['status']['handoff']['returnScope']
        wrong_plan = envelope()
        wrong_plan['status']['handoff']['returnScope']['planId'] = '12345678-1234-4123-8123-123456789abd'
        bad_hash = envelope()
        bad_hash['status']['handoff']['returnScope']['handoffSha256'] = 'F' * 64
        unhealthy_scope = envelope('complete')
        unhealthy_scope['status']['handoff']['returnScope'] = dict(SCOPE)
        leaked = envelope()
        leaked['status']['handoff']['source'] = 'private source'
        for value in (missing_scope, wrong_plan, bad_hash, unhealthy_scope, leaked,
                      {**envelope(), 'ageMs': 5001}, {**envelope(), 'ageMs': True}):
            self.app.handoff_status = lambda: value
            reply = self.call(PATH)
            self.assertEqual(reply.status, 503)
            self.assertNotIn(b'private source', reply.body)
            self.assertNotIn(PLAN.encode(), reply.body)

    def test_idle_session_expiry_and_mid_read_revocation_do_not_disclose_status(self):
        self.login()
        self.app.handoff_status = Mock(return_value=envelope())
        for _ in range(4):
            self.now += 200_000
            self.assertEqual(self.call(PATH).status, 200)
        self.now += 100_001
        self.assertEqual(self.call(PATH).status, 401)
        self.assertEqual(self.app.handoff_status.call_count, 4)
        self.login()

        def revoke():
            self.store.logout(token=self.cookies[self.app.prefix + 'session'], origin=self.profile['origin'],
                              csrf=self.cookies[self.app.prefix + 'csrf'])
            return envelope()

        self.app.handoff_status = revoke
        reply = self.call(PATH)
        self.assertEqual(reply.status, 401)
        self.assertNotIn(PLAN.encode(), reply.body)
