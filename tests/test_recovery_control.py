import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import secrets
import unittest
from unittest import mock

from test_recovery_worker import CAPABILITY
from orbis_sentinel import recovery_control as control
from orbis_sentinel import recovery_profiles as profiles
from orbis_sentinel import recovery_sessions as sessions


class RecoveryControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='c')
        self.addCleanup(self.temp.cleanup)
        for module in (sessions, control):
            patch = mock.patch.object(module, '_OWNER_UID', os.getuid())
            patch.start()
            self.addCleanup(patch.stop)
        self.store = sessions.RecoverySessions(self.temp.name)
        self.addCleanup(self.store.close)
        self.origin = 'https://recovery.example'
        self.metadata = {'revision': 'b' * 64, 'accountId': 1, 'origin': self.origin,
                         'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {}}
        self.inspect = mock.Mock(side_effect=lambda directory, digest: {
            'schema': 'orbis.sentinel-identity-description.v1', 'identitySha256': digest, **self.metadata})
        self.profiles = profiles.RecoveryProfiles(self.store, inspect=self.inspect, verify=mock.Mock())
        self.addCleanup(self.profiles.close)
        self.app = control.RecoveryControl(sessions=self.store, profiles=self.profiles, origin=self.origin)
        self.body = b'{"syntheticProtectedIdentity":true}'
        self.digest = hashlib.sha256(self.body).hexdigest()

    def request(self, operation, **arguments):
        return {'schema': control._SCHEMA, 'operation': operation, 'arguments': arguments}

    def call(self, operation, **arguments):
        result = self.app.handle(self.request(operation, **arguments))
        self.assertTrue(result['ok'])
        return result['result']

    def test_capability_is_fixed_root_callback_and_never_fakes_missing_support(self):
        before=self.store.operator_status()
        self.assertFalse(self.app.handle(self.request('operator-capability'))['ok'])
        callback=mock.Mock(return_value=CAPABILITY);self.app.capability=callback
        self.assertEqual(self.call('operator-capability'),CAPABILITY);callback.assert_called_once_with()
        self.assertEqual(self.store.operator_status(),before)
        callback.reset_mock()
        self.assertFalse(self.app.handle(self.request('operator-capability',workerOperation='arbitrary'))['ok'])
        callback.assert_not_called()
        for value in (True,{},dict(CAPABILITY,passkeyCounterProof='old')):
            callback.return_value=value
            self.assertFalse(self.app.handle(self.request('operator-capability'))['ok'])
        callback.side_effect=RuntimeError('private probe detail')
        result=self.app.handle(self.request('operator-capability'))
        self.assertFalse(result['ok']);self.assertNotIn('private probe detail',json.dumps(result))

    def test_stage_begin_complete_and_conditional_revoke_preserve_emergency_key(self):
        pending = self.store.prepare_recovery_key(origin=self.origin, expected_revision=None)
        self.store.activate_recovery_key(revision=pending['revision'], recovery_key=pending['recoveryKey'], expected_revision=None)
        binding = secrets.token_urlsafe(32)
        challenge = self.store.challenge(method='recovery-key', origin=self.origin, browser_binding=binding)
        key_session = self.store.complete_recovery_key(challenge=challenge['challenge'], browser_binding=binding,
                                                      origin=self.origin, recovery_key=pending['recoveryKey'])
        self.assertEqual(self.call('operator-status'), {'generation': 0, 'revision': None, 'state': 'never-enrolled'})
        self.assertEqual(self.call('operator-stage', identityBase64=base64.b64encode(self.body).decode()), {'identitySha256': self.digest})
        begun = self.call('operator-begin', identitySha256=self.digest, expectedGeneration=0, expectedRevision=None)
        self.assertEqual(begun['generation'], 1)
        self.assertEqual(self.call('operator-status')['state'], 'pending')
        completed = self.call('operator-complete', identitySha256=self.digest, expectedGeneration=1, changeToken=begun['changeToken'])
        self.assertEqual(completed, {'generation': 2, 'revision': 'b' * 64, 'state': 'enrolled'})
        stale = self.app.handle(self.request('operator-revoke', expectedGeneration=1, expectedRevision='b' * 64))
        self.assertFalse(stale['ok'])
        self.assertEqual(self.store.operator_status(), completed)
        self.assertEqual(self.call('operator-revoke', expectedGeneration=2, expectedRevision='b' * 64)['state'], 'revoked')
        self.assertTrue(self.store.authentication_options()['recoveryKey'])
        self.assertEqual(self.store.session(token=key_session['token'], origin=self.origin, touch=False)['method'], 'recovery-key')

    def test_cross_realm_profile_never_begins_operator_authority(self):
        self.metadata['origin'] = 'https://other.example'
        result = self.app.handle(self.request('operator-stage', identityBase64=base64.b64encode(self.body).decode()))
        self.assertFalse(result['ok'])
        self.assertEqual(self.store.operator_status()['generation'], 0)
        self.assertEqual(self.store.operator_status()['state'], 'never-enrolled')

    def test_writer_eligibility_is_read_only_and_legacy_only(self):
        schema = 'orbis.sentinel-operator-writer-eligibility.v1'
        self.assertEqual(self.call('operator-writer-eligibility'), {
            'schema': schema, 'generation': 0, 'revision': None, 'eligible': False})
        self.store.enroll({'identitySha256': self.digest, **self.metadata})
        before = self.store.operator_status()
        self.assertEqual(self.call('operator-writer-eligibility'), {
            'schema': schema, 'generation': before['generation'], 'revision': before['revision'], 'eligible': True})
        self.assertEqual(self.store.operator_status(), before)
        self.assertFalse(self.app.handle(self.request('operator-writer-eligibility', eligible=True))['ok'])

    def test_browser_fields_paths_and_host_operations_are_rejected(self):
        for request in (self.request('restart'), self.request('operator-stage', path='/private/identity'),
                        self.request('operator-status', extra=True), self.request('operator-stage', identityBase64='%%%'),
                        {**self.request('operator-status'), 'session': 'browser-token'}):
            with self.subTest(request=request):
                self.assertFalse(self.app.handle(request)['ok'])
        self.inspect.assert_not_called()
        self.assertEqual(self.store.operator_status()['generation'], 0)

    def test_configuration_failure_precedes_any_control_work_and_is_redacted(self):
        self.app.check = mock.Mock(side_effect=ValueError('synthetic-private-detail'))
        with mock.patch.object(self.store, 'operator_status') as status:
            result = self.app.handle(self.request('operator-status'))
        self.assertFalse(result['ok'])
        self.assertNotIn('synthetic-private-detail', json.dumps(result))
        status.assert_not_called()

    def start(self):
        self.path = os.path.join(self.temp.name, 'c.sock')
        self.server = control.RecoveryControlServer(self.path, self.app)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.thread.join(5)
        self.assertFalse(self.thread.is_alive())
        self.server.close()

    def exchange(self, body, *, declared=None, trailing=b''):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(self.path)
            try:
                connection.sendall(struct.pack('!I', len(body) if declared is None else declared) + body + trailing)
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                return b''
            chunks = bytearray()
            while True:
                try:
                    block = connection.recv(8192)
                except ConnectionResetError:
                    break
                if not block:
                    break
                chunks.extend(block)
            return bytes(chunks)

    @unittest.skipUnless(hasattr(socket, 'SO_PEERCRED') or hasattr(socket.socket, 'getpeereid'), 'requires Unix peer credentials')
    def test_real_unix_peer_frame_and_socket_permissions(self):
        self.start()
        self.assertEqual(Path(self.path).stat().st_mode & 0o777, 0o600)
        reply = self.exchange(json.dumps(self.request('operator-status')).encode())
        length = struct.unpack('!I', reply[:4])[0]
        self.assertEqual(length, len(reply) - 4)
        self.assertTrue(json.loads(reply[4:])['ok'])
        self.close()
        self.assertFalse(Path(self.path).exists())

    def test_wrong_peer_trailing_duplicate_and_oversized_frames_do_no_work(self):
        self.start()
        body = json.dumps(self.request('operator-status')).encode()
        with mock.patch.object(self.server, '_peer_uid', return_value=os.getuid() + 1):
            self.assertEqual(self.exchange(body), b'')
        with mock.patch.object(self.server, '_peer_uid', return_value=os.getuid()):
            self.assertTrue(json.loads(self.exchange(body)[4:])['ok'])
            with mock.patch.object(self.app, 'handle') as handle:
                for data, declared, trailing in ((body, None, b'extra'), (body, 98305, b''),
                                                 (b'{"schema":1,"schema":2}', None, b'')):
                    self.assertEqual(self.exchange(data, declared=declared, trailing=trailing), b'')
                handle.assert_not_called()

    def test_existing_socket_is_a_hold_and_close_preserves_replaced_path(self):
        self.start()
        original = Path(self.path)
        with self.assertRaises(OSError):
            control.RecoveryControlServer(self.path, self.app)
        self.assertTrue(original.is_socket())
        original.unlink()
        original.write_text('replacement must survive')
        self.close()
        self.assertEqual(original.read_text(), 'replacement must survive')
