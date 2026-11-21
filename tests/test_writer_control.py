import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest import mock

from orbis_sentinel import writer_control as control


class WriterControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='client-')
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name, 'c.sock'))
        patch = mock.patch.object(control, '_OWNER_UID', os.getuid())
        patch.start()
        self.addCleanup(patch.stop)
        self.requests = []
        self.payload = json.dumps({'schema': control._SCHEMA, 'ok': True,
                                   'result': {'generation': 1, 'revision': 'a' * 64, 'state': 'enrolled'}}).encode()
        self.trailing = b''
        self.advertised = None
        self.before_reply = lambda: None
        self.stop = threading.Event()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        os.chmod(self.path, 0o600)
        self.server.listen(2)
        self.server.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        self.addCleanup(self.close)
        # The local unprivileged transport fixture does not claim genuine root
        # credentials; joined Linux proof exercises SO_PEERCRED without this seam.
        peer = mock.patch.object(control.WriterControlClient, '_peer', return_value=True)
        peer.start()
        self.addCleanup(peer.stop)

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(1)
                try:
                    body = bytearray()
                    while True:
                        chunk = connection.recv(8192)
                        if not chunk:
                            break
                        body.extend(chunk)
                    if len(body) < 4:
                        continue
                    size = struct.unpack('!I', body[:4])[0]
                    assert len(body) == size + 4
                    self.requests.append(json.loads(body[4:]))
                    self.before_reply()
                    connection.sendall(struct.pack('!I', self.advertised if self.advertised is not None else len(self.payload)) + self.payload + self.trailing)
                except (OSError, ValueError):
                    pass

    def close(self):
        self.stop.set()
        self.server.close()
        self.thread.join(2)
        self.assertFalse(self.thread.is_alive())

    def call(self, operation='operator-status', arguments=None):
        return control.WriterControlClient(self.path, timeout=1).call(operation, arguments or {})

    def test_exact_bounded_root_control_frame_and_no_arbitrary_operations(self):
        value = self.call()
        self.assertEqual(value['state'], 'enrolled')
        self.assertEqual(self.requests, [{'schema': control._SCHEMA, 'operation': 'operator-status', 'arguments': {}}])
        for operation in ('operator-revoke', 'operator-begin', 'arbitrary', '../another/socket'):
            with self.assertRaises(control.WriterControlError):
                self.call(operation)
        self.assertEqual(len(self.requests), 1)

    def test_capability_is_one_fixed_operation_without_initial_enrollment_or_key_commands(self):
        self.call('operator-capability')
        self.assertEqual(self.requests[-1],{'schema':control._SCHEMA,'operation':'operator-capability','arguments':{}})
        before=len(self.requests)
        for operation in ('worker','worker-capability','operator-stage','operator-begin','operator-complete','key-prepare','key-activate'):
            with self.subTest(operation=operation),self.assertRaises(control.WriterControlError):self.call(operation)
        self.assertEqual(len(self.requests),before)

    def test_counter_operations_are_fixed_control_messages_without_authentication_session_operations(self):
        for operation in ('main-passkey-challenge', 'main-passkey-complete', 'main-passkey-floors'):
            with self.subTest(operation=operation):
                arguments={'syntheticBinding':'b'*64}
                self.call(operation,arguments)
                self.assertEqual(self.requests[-1], {'schema':control._SCHEMA,'operation':operation,'arguments':arguments})
        before=len(self.requests)
        for operation in ('main-passkey-login', 'recovery-session', 'operator-stage', 'operator-complete', 'key-activate'):
            with self.subTest(operation=operation),self.assertRaises(control.WriterControlError): self.call(operation)
        self.assertEqual(len(self.requests),before)

    def test_generic_errors_reject_invalid_duplicate_extra_and_trailing_response_without_exposing_values(self):
        secret = 'synthetic-secret-never-in-exception'
        for payload in (b'{"schema":1,"schema":2}', b'[]', b'not JSON',
                        json.dumps({'schema': control._SCHEMA, 'ok': False, 'error': secret}).encode(),
                        json.dumps({'schema': control._SCHEMA, 'ok': True, 'result': {}, 'private': secret}).encode()):
            self.payload = payload
            with self.assertRaises(control.WriterControlError) as caught:
                self.call()
            self.assertNotIn(secret, str(caught.exception))
        self.payload = json.dumps({'schema': control._SCHEMA, 'ok': True, 'result': {}}).encode()
        self.trailing = b'x'
        with self.assertRaises(control.WriterControlError):
            self.call()

    def test_partial_oversize_and_slow_response_are_ambiguous_failures_not_empty_status(self):
        self.advertised = 98305
        with self.assertRaises(control.WriterControlError):
            self.call()
        self.advertised = len(self.payload) + 2
        with self.assertRaises(control.WriterControlError):
            self.call()

    def test_permissive_aliased_and_changed_socket_custody_refuses(self):
        os.chmod(self.path, 0o660)
        with self.assertRaises(control.WriterControlError):
            self.call()
        self.assertEqual(self.requests, [])
        os.chmod(self.path, 0o600)
        alias = Path(self.temp.name, 'alias')
        alias.symlink_to(self.temp.name, target_is_directory=True)
        with self.assertRaises(control.WriterControlError):
            control.WriterControlClient(str(alias / 'c.sock'))
        self.before_reply = lambda: os.chmod(self.path, 0o640)
        with self.assertRaises(control.WriterControlError):
            self.call()

    def test_wrong_server_peer_refuses_before_sending_private_frame(self):
        with mock.patch.object(control.WriterControlClient, '_peer', return_value=False):
            with self.assertRaises(control.WriterControlError):
                self.call('operator-prepare-writer', {'syntheticPrivateValue': 'never-sent'})
        self.assertEqual(self.requests, [])

    def test_missing_socket_and_oversize_request_never_mean_unmanaged(self):
        self.assertRaises(control.WriterControlError, control.WriterControlClient(str(Path(self.temp.name, 'absent.sock'))).call, 'operator-status', {})
        with self.assertRaises(control.WriterControlError):
            self.call('operator-prepare-writer', {'identity': 'x' * 196608})
        self.assertEqual(self.requests, [])


if __name__ == '__main__':
    unittest.main()
