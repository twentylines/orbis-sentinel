"""Supervisor-only credential synchronization; no browser or lifecycle routes."""

import base64
import json
import os
import select
import socket
import stat
import struct
import threading
import time

from .recovery_config import _absolute, _pairs
from .recovery_worker import validate_capability

_OWNER_UID = 0
_MAX_REQUEST = 196608
_SCHEMA = 'orbis.sentinel-recovery-control.v1'


class RecoveryControl:
    def __init__(self, *, sessions, profiles, origin, check=None, incarnations=None, main_passkeys=None, capability=None):
        self.sessions, self.profiles, self.origin, self.check = sessions, profiles, origin, check
        self.incarnations = incarnations
        self.main_passkeys = main_passkeys
        if capability is not None and not callable(capability):
            raise ValueError('Recovery capability must use an actual worker callback.')
        self.capability = capability

    @staticmethod
    def _fields(arguments, names):
        if type(arguments) is not dict or set(arguments) != set(names):
            raise ValueError('Invalid control arguments.')

    @staticmethod
    def _identity(value):
        if type(value) is not str or len(value) > 87384:
            raise ValueError('Invalid protected identity.')
        identity = base64.b64decode(value, validate=True)
        if not 1 <= len(identity) <= 65536 or base64.b64encode(identity).decode('ascii') != value:
            raise ValueError('Invalid protected identity encoding.')
        return identity

    def handle(self, request):
        try:
            if self.check is not None:
                self.check()
            if (type(request) is not dict or set(request) != {'schema', 'operation', 'arguments'}
                    or request['schema'] != _SCHEMA or type(request['operation']) is not str):
                raise ValueError('Invalid control request.')
            operation, arguments = request['operation'], request['arguments']
            if operation != 'operator-capability':
                self.sessions._transaction(self.sessions._publication_idle)
            if operation == 'operator-status':
                self._fields(arguments, ())
                result = self.sessions.operator_status()
            elif operation == 'operator-writer-eligibility':
                self._fields(arguments, ())
                result = self.sessions.operator_writer_eligibility()
            elif operation == 'operator-capability':
                self._fields(arguments, ())
                if self.capability is None:
                    raise ValueError('Recovery worker qualification is unavailable.')
                result = validate_capability(self.capability())
            elif operation in ('main-passkey-challenge', 'main-passkey-complete'):
                if self.main_passkeys is None:
                    raise ValueError('Main passkey support is unavailable.')
                if operation == 'main-passkey-challenge':
                    self._fields(arguments, ('admissionBinding', 'purpose', 'ceremonyBinding'))
                    result = self.main_passkeys.challenge(admission_binding=arguments['admissionBinding'],
                        purpose=arguments['purpose'], ceremony_binding=arguments['ceremonyBinding'])
                else:
                    self._fields(arguments, ('challenge', 'admissionBinding', 'purpose', 'ceremonyBinding', 'response'))
                    result = self.main_passkeys.complete(challenge=arguments['challenge'],
                        admission_binding=arguments['admissionBinding'], purpose=arguments['purpose'],
                        ceremony_binding=arguments['ceremonyBinding'], response=arguments['response'])
            elif operation == 'main-passkey-floors':
                if self.incarnations is None:
                    raise ValueError('Main passkey floor support is unavailable.')
                self._fields(arguments, ('identityBase64', 'expectedGeneration', 'expectedRevision'))
                result = self.incarnations.counter_floors(self._identity(arguments['identityBase64']),
                    expected_generation=arguments['expectedGeneration'], expected_revision=arguments['expectedRevision'])
            elif operation == 'operator-stage':
                self._fields(arguments, ('identityBase64',))
                identity = self._identity(arguments['identityBase64'])
                with self.profiles._operation():
                    self.sessions._transaction(self.sessions._publication_idle)
                    prepared = self.profiles.prepare(identity)
                if prepared.origin != self.origin:
                    raise ValueError('Protected identity realm differs.')
                result = {'identitySha256': prepared.digest}
            elif operation in ('operator-check-source', 'operator-prepare-writer', 'operator-stage-incarnation', 'operator-begin-incarnation', 'operator-complete-incarnation'):
                if self.incarnations is None:
                    raise ValueError('Protected incarnation support is unavailable.')
                if operation == 'operator-prepare-writer':
                    self._fields(arguments, ('baselineIdentityBase64', 'identityBase64', 'expectedGeneration', 'expectedRevision', 'changeToken'))
                    result = self.incarnations.prepare_writer(self._identity(arguments['baselineIdentityBase64']),
                        self._identity(arguments['identityBase64']), expected_generation=arguments['expectedGeneration'],
                        expected_revision=arguments['expectedRevision'], change_token=arguments['changeToken'])
                elif operation == 'operator-check-source':
                    self._fields(arguments, ('identityBase64', 'expectedGeneration', 'expectedRevision'))
                    result = self.incarnations.check_source(self._identity(arguments['identityBase64']),
                        expected_generation=arguments['expectedGeneration'], expected_revision=arguments['expectedRevision'])
                elif operation == 'operator-stage-incarnation':
                    self._fields(arguments, ('identityBase64', 'expectedGeneration', 'expectedRevision', 'changeToken'))
                    result = self.incarnations.stage(self._identity(arguments['identityBase64']),
                        expected_generation=arguments['expectedGeneration'], expected_revision=arguments['expectedRevision'],
                        change_token=arguments['changeToken'])
                elif operation == 'operator-begin-incarnation':
                    self._fields(arguments, ('changeToken',))
                    result = self.incarnations.begin(change_token=arguments['changeToken'])
                else:
                    self._fields(arguments, ('identityBase64', 'expectedGeneration', 'changeToken'))
                    result = self.incarnations.complete(self._identity(arguments['identityBase64']),
                        expected_generation=arguments['expectedGeneration'], change_token=arguments['changeToken'])
            elif operation in ('operator-begin', 'operator-begin-prepared', 'operator-complete'):
                names = (('identitySha256', 'expectedGeneration', 'expectedRevision', 'changeToken')
                         if operation == 'operator-begin-prepared' else
                         ('identitySha256', 'expectedGeneration', 'expectedRevision') if operation == 'operator-begin' else
                         ('identitySha256', 'expectedGeneration', 'changeToken'))
                self._fields(arguments, names)
                prepared = self.profiles.inspect_retained(arguments['identitySha256'])
                if prepared.origin != self.origin:
                    raise ValueError('Protected identity realm differs.')
                if operation == 'operator-begin-prepared':
                    if arguments['changeToken'] is None:
                        raise ValueError('A prepared change token is required.')
                    result = self.profiles.begin(prepared, expected_generation=arguments['expectedGeneration'],
                                                 expected_revision=arguments['expectedRevision'], change_token=arguments['changeToken'])
                elif operation == 'operator-begin':
                    result = self.profiles.begin(prepared, expected_generation=arguments['expectedGeneration'],
                                                 expected_revision=arguments['expectedRevision'])
                else:
                    result = self.profiles.complete(prepared, change_token=arguments['changeToken'],
                                                    expected_generation=arguments['expectedGeneration'])
            elif operation == 'operator-revoke':
                self._fields(arguments, ('expectedGeneration', 'expectedRevision'))
                result = self.sessions.revoke_operator(expected_generation=arguments['expectedGeneration'],
                                                       expected_revision=arguments['expectedRevision'])
            else:
                raise ValueError('Unsupported control operation.')
            return {'schema': _SCHEMA, 'ok': True, 'result': result}
        except Exception:
            return {'schema': _SCHEMA, 'ok': False, 'error': 'Recovery control request could not be completed.'}


class RecoveryControlServer:
    """One length-prefixed JSON request per root-authenticated Unix connection.

    The sender must half-close its write side after the frame. Requests are
    serialized separately from browser authentication. An existing socket is a
    reconciliation hold, never automatically removed or taken over at startup.
    """

    def __init__(self, path, application):
        if not _absolute(path) or len(os.fsencode(path)) > 107:
            raise ValueError('Control socket must use a canonical path.')
        self.path, self.application = path, application
        self._stop = threading.Event()
        self._created = None
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            current = '/'
            for part in os.path.dirname(path).strip('/').split('/'):
                current = os.path.join(current, part)
                info = os.lstat(current)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, _OWNER_UID}
                        or info.st_mode & 0o022):
                    raise ValueError('Control socket directory is not protected.')
            parent = os.lstat(os.path.dirname(path))
            if parent.st_uid != _OWNER_UID or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError('Control socket parent must be private.')
            self._socket.bind(path)
            info = os.lstat(path)
            self._created = (info.st_dev, info.st_ino)
            os.chmod(path, 0o600)
            self._socket.listen(4)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _peer_uid(connection):
        if hasattr(socket, 'SO_PEERCRED'):
            return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
        if hasattr(connection, 'getpeereid'):
            return connection.getpeereid()[0]
        raise OSError('Control peer credentials unavailable.')

    @staticmethod
    def _read(connection, count, deadline):
        body = bytearray()
        while len(body) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
                raise TimeoutError('Control request expired.')
            block = connection.recv(count - len(body))
            if not block:
                raise ValueError('Incomplete control frame.')
            body.extend(block)
        return bytes(body)

    def serve_forever(self):
        while not self._stop.is_set():
            if not select.select([self._socket], [], [], 0.1)[0]:
                continue
            with self._socket.accept()[0] as connection:
                try:
                    if self._peer_uid(connection) != _OWNER_UID:
                        continue
                    self._handle_connection(connection)
                except (OSError, ValueError):
                    continue

    def _handle_connection(self, connection):
        deadline = time.monotonic() + 2
        size = struct.unpack('!I', self._read(connection, 4, deadline))[0]
        if not 0 < size <= _MAX_REQUEST:
            return
        body = self._read(connection, size, deadline)
        if self._read_end(connection, deadline) or self._stop.is_set():
            return
        request = json.loads(body, object_pairs_hook=_pairs)
        response = json.dumps(self.application.handle(request), separators=(',', ':')).encode('utf8')
        connection.settimeout(2)
        connection.sendall(struct.pack('!I', len(response)) + response)

    @staticmethod
    def _read_end(connection, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([connection], [], [], remaining)[0]:
            raise TimeoutError('Control frame was not closed.')
        return connection.recv(1)

    def shutdown(self):
        self._stop.set()

    def close(self):
        self.shutdown()
        self._socket.close()
        if self._created is not None:
            try:
                info = os.lstat(self.path)
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == self._created:
                    os.unlink(self.path)
            except FileNotFoundError:
                pass
            self._created = None
