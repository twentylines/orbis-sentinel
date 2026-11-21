import http.client
from http.cookies import SimpleCookie
import json
import os
import socket
import tempfile
import threading
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

from test_recovery_worker import CAPABILITY
from orbis_sentinel import recovery_runtime as runtime
from orbis_sentinel import recovery_sessions as sessions
from orbis_sentinel import recovery_control as control
from orbis_sentinel.status import ComponentStatus, build_status


class RecoveryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='r')
        self.addCleanup(self.temp.cleanup)
        owner = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        owner.start()
        self.addCleanup(owner.stop)
        root = mock.patch.object(runtime, '_require_root')
        root.start()
        self.addCleanup(root.stop)
        store = sessions.RecoverySessions(self.temp.name)
        try:
            pending = store.prepare_recovery_key(origin='https://recovery.example', expected_revision=None)
            store.activate_recovery_key(revision=pending['revision'], recovery_key=pending['recoveryKey'], expected_revision=None)
            self.key = pending['recoveryKey']
        finally:
            store.close()
        self.stop = threading.Event()
        self.status = lambda: build_status(ComponentStatus(None, None, 'unavailable'), ComponentStatus('0.1.0-dev.19', None, 'healthy'))
        self.args = dict(directory=self.temp.name, image_id='sha256:' + 'a' * 64,
                         origin='https://recovery.example', address=('127.0.0.1', 0),
                         status=lambda: self.status(), stop=self.stop)
        self.cookies = {}

    def start(self):
        ready = threading.Event()
        self.failures = []

        def observed(address):
            self.address = address
            ready.set()

        def run():
            try:
                runtime.run_recovery(**self.args, ready=observed)
            except BaseException as error:
                self.failures.append(error)
                ready.set()

        self.thread = threading.Thread(target=run)
        self.thread.start()
        self.addCleanup(self.close)
        self.assertTrue(ready.wait(5))
        self.assertEqual(self.failures, [])

    def close(self):
        self.stop.set()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(self.failures, [])

    def request(self, route, body=None):
        connection = http.client.HTTPConnection(*self.address, timeout=5)
        headers = {'Host': 'recovery.example', 'Cookie': '; '.join(k + '=' + v for k, v in self.cookies.items())}
        if body is not None:
            headers.update({'Origin': self.args['origin'], 'Content-Type': 'application/json'})
        try:
            target = route.replace('api/', 'api/v1/', 1) if route.startswith('api/') else route
            connection.request('GET' if body is None else 'POST', '/sentinel/recovery/' + target,
                               body=None if body is None else json.dumps(body), headers=headers)
            reply = connection.getresponse()
            for name, value in reply.getheaders():
                if name.lower() == 'set-cookie':
                    for key, morsel in SimpleCookie(value).items():
                        if morsel['max-age'] == '0':
                            self.cookies.pop(key, None)
                        else:
                            self.cookies[key] = morsel.value
            return reply.status, json.loads(reply.read()) if route.startswith('api/') else reply.read()
        finally:
            connection.close()

    def login(self):
        self.assertEqual(self.request('')[0], 200)
        code, options = self.request('api/options')
        self.assertEqual(code, 200)
        self.assertFalse(options['password'])
        self.assertTrue(options['recoveryKey'])
        code, challenge = self.request('api/challenge', {'method': 'recovery-key'})
        self.assertEqual(code, 200)
        code, result = self.request('api/login', {'challenge': challenge['challenge'],
                                                'credentials': {'method': 'recovery-key', 'recoveryKey': self.key}})
        self.assertEqual((code, result), (200, {'authenticated': True}))

    def test_real_key_login_without_main_profile_or_worker_image(self):
        self.start()
        with mock.patch.object(runtime.RecoveryWorker, 'verify', side_effect=AssertionError('Key login must not use Main')):
            self.login()
            code, result = self.request('api/status')
        self.assertEqual(code, 200)
        self.assertEqual(result['components']['orbis']['state'], 'unavailable')
        self.assertEqual(self.request('api/restart', {})[0], 404)

    def test_progress_remains_available_without_main_and_never_adds_actions(self):
        sample = {'schema': 'orbis-sentinel.progress.v1', 'available': True, 'ageMs': 0, 'sourceState': 'ready',
                  'progress': {'version': 1, 'job': {'id': '12345678-1234-4123-8123-123456789abc', 'state': 'running',
                                                 'targetTag': 'v0.8.8', 'phase': 'restarting'}}}
        self.args['progress'] = lambda: sample
        self.start()
        self.assertEqual(self.request('api/progress')[0], 401)
        with mock.patch.object(runtime.RecoveryWorker, 'verify', side_effect=AssertionError('Progress must not call Main')):
            self.login()
            self.assertEqual(self.request('api/progress'), (200, sample))
        self.assertEqual(self.request('api/restart', {})[0], 404)

    def test_shutdown_drains_active_status_before_releasing_store_ownership(self):
        self.start()
        self.login()
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        observed = self.status()

        def blocked():
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Test did not release status provider')
            return observed

        self.status = blocked
        replies = []
        request = threading.Thread(target=lambda: replies.append(self.request('api/status')))
        request.start()
        try:
            self.assertTrue(entered.wait(5))
            self.stop.set()
            self.thread.join(0.3)
            self.assertTrue(self.thread.is_alive(), 'Root resources must stay owned until requests drain')
            with self.assertRaises(BlockingIOError):
                sessions.RecoverySessions(self.temp.name)
        finally:
            release.set()
            request.join(5)
        self.close()
        self.assertFalse(request.is_alive())
        self.assertEqual(replies, [(200, observed)])
        reopened = sessions.RecoverySessions(self.temp.name)
        try:
            self.assertTrue(reopened.authentication_options()['recoveryKey'])
        finally:
            reopened.close()

    def test_listener_bind_failure_releases_store_without_revoking_key(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            self.args['address'] = occupied.getsockname()
            with self.assertRaises(OSError):
                runtime.run_recovery(**self.args)
        reopened = sessions.RecoverySessions(self.temp.name)
        try:
            self.assertTrue(reopened.authentication_options()['recoveryKey'])
        finally:
            reopened.close()

    def test_readiness_failure_closes_listener_and_store(self):
        def fail(address):
            self.address = address
            raise RuntimeError('Readiness was refused')

        with self.assertRaisesRegex(RuntimeError, 'Readiness was refused'):
            runtime.run_recovery(**self.args, ready=fail)
        with socket.socket() as listener:
            self.assertNotEqual(listener.connect_ex(self.address), 0)
        reopened = sessions.RecoverySessions(self.temp.name)
        reopened.close()

    def test_configuration_refusal_prevents_start_and_releases_running_listener(self):
        with mock.patch.object(runtime, 'RecoverySessions') as store:
            with self.assertRaisesRegex(ValueError, 'Changed configuration'):
                runtime.run_recovery(**self.args, check=mock.Mock(side_effect=ValueError('Changed configuration')))
            store.assert_not_called()
        changed = threading.Event()

        def verify():
            if changed.is_set():
                raise ValueError('Changed configuration')

        self.args['check'] = verify
        self.start()
        changed.set()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())
        self.assertEqual(len(self.failures), 1)
        self.assertIsInstance(self.failures.pop(), ValueError)
        reopened = sessions.RecoverySessions(self.temp.name)
        reopened.close()

    def test_non_linux_root_cannot_start_the_listener(self):
        with mock.patch.object(runtime, '_require_root', wraps=root_requirement):
            with mock.patch.object(runtime.sys, 'platform', 'darwin'):
                with self.assertRaises(RuntimeError):
                    runtime.run_recovery(**self.args)

    def test_root_control_capability_uses_live_worker_callback_without_signin(self):
        self.args['control']=True
        with mock.patch.object(control,'_OWNER_UID',os.getuid()), \
                mock.patch.object(control.RecoveryControlServer,'_peer_uid',return_value=os.getuid()), \
                mock.patch.object(runtime.RecoveryWorker,'capability',return_value=CAPABILITY) as probe:
            self.start()
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(5);connection.connect(os.path.join(self.temp.name,'control.sock'))
                body=json.dumps({'schema':control._SCHEMA,'operation':'operator-capability','arguments':{}}).encode()
                connection.sendall(struct.pack('!I',len(body))+body);connection.shutdown(socket.SHUT_WR)
                chunks=bytearray()
                while True:
                    block=connection.recv(8192)
                    if not block:break
                    chunks.extend(block)
            value=json.loads(chunks[4:]);self.assertTrue(value['ok']);self.assertEqual(value['result'],CAPABILITY)
            probe.assert_called_once_with();self.close()

    def test_busy_control_does_not_block_key_login_and_shutdown_drains_both_listeners(self):
        self.args['control'] = True
        entered, release = threading.Event(), threading.Event()
        replies = []
        self.addCleanup(release.set)

        def prepare(identity):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Test did not release control work')
            return SimpleNamespace(origin=self.args['origin'], digest='a' * 64)

        def send():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect(os.path.join(self.temp.name, 'control.sock'))
                body = json.dumps({'schema': control._SCHEMA, 'operation': 'operator-stage',
                                   'arguments': {'identityBase64': 'e30='}}).encode()
                connection.sendall(struct.pack('!I', len(body)) + body)
                connection.shutdown(socket.SHUT_WR)
                chunks = bytearray()
                while True:
                    block = connection.recv(8192)
                    if not block:
                        break
                    chunks.extend(block)
                replies.append(json.loads(chunks[4:]))

        with mock.patch.object(control, '_OWNER_UID', os.getuid()), \
                mock.patch.object(control.RecoveryControlServer, '_peer_uid', return_value=os.getuid()), \
                mock.patch.object(runtime.RecoveryProfiles, 'prepare', side_effect=prepare):
            self.start()
            sender = threading.Thread(target=send)
            sender.start()
            try:
                self.assertTrue(entered.wait(5))
                self.login()
                self.stop.set()
                self.thread.join(0.3)
                self.assertTrue(self.thread.is_alive())
            finally:
                release.set()
                sender.join(5)
            self.close()
        self.assertFalse(sender.is_alive())
        self.assertTrue(replies[0]['ok'])
        self.assertFalse(os.path.exists(os.path.join(self.temp.name, 'control.sock')))


root_requirement = runtime._require_root
