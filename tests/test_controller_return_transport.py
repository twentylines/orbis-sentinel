"""Fixed HTTP request and reply checks with a socket-free transport seam."""

from contextlib import contextmanager
import json
import stat
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from orbis_sentinel import controller_return_transport as transport
from orbis_sentinel.controller_return_readiness import readiness_reply

PLAN = '11111111-2222-4333-8444-555555555555'
ORIGIN = 'https://independent.example:8443'
VALUE = {'version': 1, 'planId': PLAN, 'state': 'return-accepted', 'phase': 'return-accepted',
         'portalUrl': ORIGIN + '/sentinel/recovery/', 'expiresAtMs': 1800000300000}


def response(value=VALUE, status='HTTP/1.0 202 Accepted', extra=b''):
    body = json.dumps(value).encode()
    return status.encode() + b'\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'\r\n' + body


class Connection:
    def __init__(self, data):
        self.data, self.sent = data, []

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, maximum):
        part, self.data = self.data[:maximum], self.data[maximum:]
        return part


class ReturnTransportTests(unittest.TestCase):
    def setUp(self):
        self.client = transport.ControllerReturnTransport(origin=ORIGIN)
        self.connection = Connection(response())
        self.calls, self.closed = 0, False

    @contextmanager
    def connection_scope(self):
        self.calls += 1
        try:
            yield self.connection, time.monotonic() + 1
        finally:
            self.closed = True

    def apply(self):
        with patch.object(self.client, '_connection', self.connection_scope), patch.object(transport.select, 'select', return_value=([self.connection], [], [])):
            return self.client.apply(plan_id=PLAN, approval_id='a' * 64)

    def test_only_fixed_socket_route_and_identifiers_are_sent(self):
        self.assertEqual(self.apply(), VALUE)
        self.assertEqual(transport.HOST_SOCKET, '/run/orbis/host.sock')
        header, body = self.connection.sent[0].split(b'\r\n\r\n')
        self.assertTrue(header.startswith(b'POST /v1/sentinel/controller-handoff/return-approved HTTP/1.1\r\n'))
        self.assertIn(b'Host: orbis', header)
        self.assertEqual(json.loads(body), {'planId': PLAN, 'approvalId': 'a' * 64})
        self.assertEqual(self.calls, 1)
        self.assertTrue(self.closed)

    def test_readiness_uses_same_fixed_socket_with_exact_challenge_and_only_200_echo(self):
        challenge = {'challenge': 'a' * 64, 'installationId': 'b' * 64,
                     'invocationId': 'c' * 32, 'markerSha256': 'd' * 64}
        echo = readiness_reply(challenge)
        with (patch.object(self.client, '_connection', self.connection_scope),
              patch.object(transport.select, 'select', return_value=([self.connection], [], []))):
            self.connection.data = response(echo, 'HTTP/1.0 200 OK')
            self.assertEqual(self.client.readiness(challenge), echo)
            header, body = self.connection.sent[0].split(b'\r\n\r\n')
            self.assertTrue(header.startswith(b'POST /v1/sentinel/controller-handoff/return-readiness HTTP/1.1\r\n'))
            self.assertEqual(json.loads(body), challenge)
            for data in (response(echo), response({**echo, 'invocationId': '0' * 32}, 'HTTP/1.0 200 OK')):
                self.connection.data = data
                with self.assertRaises(transport.ReturnTransportError):
                    self.client.readiness(challenge)
            self.assertEqual(self.calls, 3)
            with self.assertRaises(ValueError):
                self.client.readiness({**challenge, 'planId': PLAN})
            self.assertEqual(self.calls, 3)

    def test_wrong_id_destination_and_extra_authority_fields_are_refused(self):
        for update in ({'planId': '21111111-2222-4333-8444-555555555555'}, {'portalUrl': 'https://other.example/'},
                       {'command': 'start'}, {'version': True}, {'state': 'healthy'}, {'expiresAtMs': True}):
            with self.subTest(update=update), self.assertRaises(transport.ReturnTransportError):
                transport._reply(response({**VALUE, **update}), plan_id=PLAN, origin=ORIGIN)

    def test_http11_and_attention_do_not_claim_completion(self):
        value = {**VALUE, 'state': 'attention'}
        self.assertEqual(transport._reply(response(value, 'HTTP/1.1 200 OK'), plan_id=PLAN, origin=ORIGIN), value)

    def test_redirect_error_encoding_duplicate_or_wrong_length_is_refused(self):
        good = response()
        for data in (response(status='HTTP/1.1 307 Temporary Redirect'), response(status='HTTP/1.1 403 Forbidden'),
                     response(extra=b'Transfer-Encoding: chunked\r\n'), response(extra=b'Content-Encoding: gzip\r\n'),
                     response(extra=b'Content-Length: 1\r\n'), good[:-1], good + b'x'):
            with self.subTest(data=data[:40]), self.assertRaises(transport.ReturnTransportError):
                transport._reply(data, plan_id=PLAN, origin=ORIGIN)

    def test_invalid_identifiers_never_reach_connection(self):
        for identifier in (PLAN + '/other', '../start', '', None):
            with self.subTest(identifier=identifier), patch.object(self.client, '_connection') as connection, self.assertRaises(ValueError):
                self.client.apply(plan_id=identifier, approval_id='a' * 64)
            connection.assert_not_called()

    def test_uncertain_write_is_never_retried(self):
        with patch.object(self.connection, 'sendall', side_effect=OSError('lost reply')), self.assertRaises(transport.ReturnTransportError):
            self.apply()
        self.assertEqual(self.calls, 1)
        self.assertTrue(self.closed)

    def test_oversize_and_timeout_are_bounded_and_release_connection(self):
        self.connection.data = b'x' * 20481
        with self.assertRaises(transport.ReturnTransportError):
            self.apply()
        self.assertTrue(self.closed)
        self.closed = False
        with patch.object(self.client, '_connection', self.connection_scope), patch.object(transport.select, 'select', return_value=([], [], [])), self.assertRaises(transport.ReturnTransportError):
            self.client.apply(plan_id=PLAN, approval_id='a' * 64)
        self.assertTrue(self.closed)

    def test_origin_and_nonroot_platform_requirements_fail_closed(self):
        for origin in ('http://independent.example', ORIGIN + '/', ORIGIN + '?x=1', 'https://user@independent.example'):
            with self.assertRaises(ValueError):
                transport.ControllerReturnTransport(origin=origin)
        with patch.object(transport.sys, 'platform', 'other'), self.assertRaises(transport.ReturnTransportError):
            with self.client._connection():
                self.fail('Unsupported platform connected')

    def test_connection_pins_protected_path_and_root_peer_and_closes_descriptors(self):
        def info(inode, mode):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_uid=0, st_gid=0, st_mode=mode,
                                   st_nlink=1, st_size=0, st_mtime_ns=1, st_ctime_ns=1)

        for fault in (None, 'peer', 'mode', 'replacement'):
            with self.subTest(fault=fault):
                directories = {3: info(1, stat.S_IFDIR | 0o755), 4: info(2, stat.S_IFDIR | 0o755),
                               5: info(3, stat.S_IFDIR | 0o755)}
                endpoint = info(4, stat.S_IFSOCK | (0o666 if fault == 'mode' else 0o600))
                changed = info(5, stat.S_IFSOCK | 0o600) if fault == 'replacement' else endpoint
                peer = struct.pack('3i', 123, 1000 if fault == 'peer' else 0, 0)
                connection = SimpleNamespace(settimeout=lambda _: None, connect=lambda _: None,
                                             getsockopt=lambda *_: peer)

                @contextmanager
                def owned_socket(*_):
                    yield connection

                with (patch.object(transport.sys, 'platform', 'linux'),
                      patch.object(transport.os, 'geteuid', return_value=0),
                      patch.object(transport.os, 'open', side_effect=[3, 4, 5]),
                      patch.object(transport.os, 'close') as close,
                      patch.object(transport.os, 'fstat', side_effect=directories.__getitem__),
                      patch.object(transport.os, 'stat', side_effect=[endpoint, changed]),
                      patch.object(transport.os, 'lstat', side_effect=lambda path: directories[{'/': 3, '/run': 4, '/run/orbis': 5}[path]]),
                      patch.object(transport.socket, 'socket', owned_socket),
                      patch.object(transport.socket, 'SO_PEERCRED', 17, create=True)):
                    if fault is None:
                        with self.client._connection() as (actual, deadline):
                            self.assertIs(actual, connection)
                            self.assertGreater(deadline, time.monotonic())
                    else:
                        with self.assertRaises(transport.ReturnTransportError):
                            with self.client._connection():
                                pass
                    self.assertEqual([call.args[0] for call in close.call_args_list], [5, 4, 3])


if __name__ == '__main__':
    unittest.main()
