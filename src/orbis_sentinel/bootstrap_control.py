"""Distinct Root bootstrap transport; never a Main credential-broker capability."""
from contextlib import contextmanager
import os
import socket
import stat
import struct
import time

from .writer_journal import _OWNER_UID, decoded, encoded, mount_id, directory_seal, seal

_OPERATIONS = {'bootstrap-source-challenge', 'bootstrap-stage', 'bootstrap-key-prepare', 'bootstrap-status', 'bootstrap-enrollment-state',
               'bootstrap-ack', 'bootstrap-activate', 'bootstrap-held-review', 'bootstrap-held-key-status',
               'bootstrap-held-activation-challenge', 'bootstrap-held-activation-receipt',
               'bootstrap-held-activation-projection', 'bootstrap-held-activation-reconcile',
               'bootstrap-paired-publication-ready', 'bootstrap-paired-publication-publish',
               'bootstrap-listener-probe-arm', 'bootstrap-listener-probe-confirm'}
_BROWSER_OPERATIONS = {f'bootstrap-browser-{action}': action for action in ('authorize', 'revoke', 'deliver', 'confirm')}
_OPERATIONS.update(_BROWSER_OPERATIONS)
_OPERATIONS.add('controller-return-claim')
_OPERATIONS.add('controller-return-readiness-arm')
_SCHEMA = 'orbis.sentinel-root-bootstrap-control.v1'



class RootBootstrapControlError(RuntimeError):
    def __init__(self):
        super().__init__('Root bootstrap control is unavailable; preserve its pending operation.')


class RootBootstrapControlClient:
    def __init__(self, path, *, timeout=180, expected_pid=None):
        if (type(path) is not str or not os.path.isabs(path) or os.path.normpath(path) != path
                or os.path.realpath(os.path.dirname(path)) != os.path.dirname(path) or len(os.fsencode(path)) > 107
                or type(timeout) not in (int, float) or not 1 <= timeout <= 300
                or expected_pid is not None and (type(expected_pid) is not int or expected_pid <= 0)):
            raise RootBootstrapControlError()
        self.path, self.timeout = path, timeout
        self.expected_pid = expected_pid

    @staticmethod
    def _peer(connection):
        if hasattr(socket, 'SO_PEERCRED'):
            pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return pid > 0 and uid == _OWNER_UID
        if hasattr(connection, 'getpeereid'):
            return connection.getpeereid()[0] == _OWNER_UID
        return False

    @staticmethod
    def _peer_pid(connection):
        if not hasattr(socket, 'SO_PEERCRED'):
            raise RootBootstrapControlError()
        pid, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != _OWNER_UID or pid <= 0:
            raise RootBootstrapControlError()
        return pid

    @contextmanager
    def _connection(self):
        directories = []
        try:
            current = '/'
            for part in ('', *os.path.dirname(self.path).strip('/').split('/')):
                if part:
                    current = os.path.join(current, part)
                fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                directories.append((current, fd, directory_seal(info), mount_id(fd)))
                if info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022:
                    raise RootBootstrapControlError()
            if stat.S_IMODE(os.fstat(directories[-1][1]).st_mode) != 0o700:
                raise RootBootstrapControlError()
            name = os.path.basename(self.path)
            before = os.stat(name, dir_fd=directories[-1][1], follow_symlinks=False)
            if not stat.S_ISSOCK(before.st_mode) or before.st_uid != _OWNER_UID or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
                raise RootBootstrapControlError()
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(min(3, self.timeout))
                connection.connect(self.path)
                if (not self._peer(connection)
                        or self.expected_pid is not None and self._peer_pid(connection) != self.expected_pid):
                    raise RootBootstrapControlError()
                yield connection, deadline
            if seal(before) != seal(os.stat(name, dir_fd=directories[-1][1], follow_symlinks=False)):
                raise RootBootstrapControlError()
            for path, fd, expected, mounted in directories:
                fresh = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if (directory_seal(os.fstat(fd)) != expected or directory_seal(os.fstat(fresh)) != expected
                            or mount_id(fd) != mounted or mount_id(fresh) != mounted):
                        raise RootBootstrapControlError()
                finally:
                    os.close(fresh)
        except Exception:
            raise RootBootstrapControlError() from None
        finally:
            for _, fd, _, _ in reversed(directories):
                os.close(fd)

    def call(self, operation, arguments):
        try:
            if operation not in _OPERATIONS or type(arguments) is not dict:
                raise RootBootstrapControlError()
            body = encoded({'schema': _SCHEMA, 'operation': operation, 'arguments': arguments})
            if not 1 <= len(body) <= 196608:
                raise RootBootstrapControlError()
            with self._connection() as (connection, deadline):
                connection.settimeout(max(0.001, deadline - time.monotonic()))
                connection.sendall(struct.pack('!I', len(body)) + body)
                connection.shutdown(socket.SHUT_WR)
                def read(count):
                    output = bytearray()
                    while len(output) < count:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise RootBootstrapControlError()
                        connection.settimeout(remaining)
                        chunk = connection.recv(count - len(output))
                        if not chunk:
                            raise RootBootstrapControlError()
                        output.extend(chunk)
                    return bytes(output)
                size = struct.unpack('!I', read(4))[0]
                if not 0 < size <= 98304:
                    raise RootBootstrapControlError()
                value = decoded(read(size))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RootBootstrapControlError()
                connection.settimeout(remaining)
                if connection.recv(1):
                    raise RootBootstrapControlError()
            if (type(value) is not dict or set(value) != {'schema', 'ok', 'result'} or value['schema'] != _SCHEMA
                    or value['ok'] is not True or type(value['result']) is not dict):
                raise RootBootstrapControlError()
            return value['result']
        except Exception:
            raise RootBootstrapControlError() from None

    def stage_held(self, lease, operation_directory, *, review_sha256, request_id):
        return self._held_collection(lease, operation_directory, review_sha256, request_id, extra={})

    def activate_held(self, lease, operation_directory, *, review_sha256, request_id, packet_sha256, intent_sha256):
        return self._held_collection(lease, operation_directory, review_sha256, request_id,
                                     extra={'packetSha256': packet_sha256, 'intentSha256': intent_sha256})

    def _held_collection(self, lease, operation_directory, review_sha256, request_id, *, extra):
        from .bootstrap_source import ACTIVATION_TERMINAL, PrivateDirectory, create_file, digest, hash_value
        from .collector_execution import (ExecutionLease, held_schema, _challenge, receive_frame,
                                         require_eof, send_frame)
        if (type(lease) is not ExecutionLease or type(operation_directory) is not PrivateDirectory
                or not hash_value(review_sha256) or not hash_value(request_id)):
            raise RootBootstrapControlError()
        value = lease.observation
        request = value['request']
        activating = request['phase'] == 'activation'
        if (operation_directory.path.name != request['operationId'] or activating != bool(extra)
                or any(not hash_value(item) for item in extra.values())):
            raise RootBootstrapControlError()
        common = {'schema': held_schema(request['phase']), 'operationId': request['operationId'],
                  'planSha256': request['planSha256'], 'requestId': request_id}
        offer = {**common, 'step': 'offer', 'reviewSha256': review_sha256, 'collectionNonce': request['collectionNonce'],
                 **{key: value[key] for key in ('holdBinding', 'capsuleSha256', 'inventorySha256', 'descriptorSha256', 'sourceSha256')},
                 **extra}
        with self._connection() as (connection, deadline):
            deadline = min(deadline, lease._channel.deadline)
            descriptors = lease.open_held_proof(request_id)
            try:
                send_frame(connection, offer, deadline, rights=descriptors)
            finally:
                for fd in descriptors:
                    os.close(fd)
            response, _ = receive_frame(connection, deadline)
            terminal_challenge = _challenge(response.get('terminalChallenge'))
            terminal_binding = {}
            if activating:
                if not hash_value(response.get('commitSha256')):
                    raise RootBootstrapControlError()
                terminal_binding['commitSha256'] = response['commitSha256']
            if response != {**common, 'step': 'finish-required', 'terminalChallenge': terminal_challenge, **terminal_binding}:
                raise RootBootstrapControlError()
            event = lease.finish()
            terminal_schema = ACTIVATION_TERMINAL if activating else 'orbis.sentinel-bootstrap-held-terminal.v1'
            data = encoded({'schema': terminal_schema, 'offerSha256': digest(encoded(offer)),
                            'terminalChallenge': terminal_challenge, 'receipt': event, **terminal_binding})
            name = 'held-activation-terminal.json' if activating else 'held-stage-terminal.json'
            create_file(operation_directory, name, data)
            send_frame(connection, {**common, 'step': 'finished', 'terminalChallenge': terminal_challenge,
                                    'terminalReceiptSha256': digest(data), **terminal_binding}, deadline)
            connection.shutdown(socket.SHUT_WR)
            complete, _ = receive_frame(connection, deadline)
            if activating:
                receipt = complete.get('receipt')
                if (type(receipt) is not dict or receipt.get('phase') != 'activation-committed'
                        or {key: receipt.get(key) for key in ('operationId', 'planSha256', 'requestId')}
                        != {key: common[key] for key in ('operationId', 'planSha256', 'requestId')}
                        or receipt.get('packetSha256') != extra['packetSha256']
                        or receipt.get('commitSha256') != terminal_binding['commitSha256']
                        or receipt.get('terminalReceiptSha256') != digest(data)
                        or complete != {**common, 'step': 'activation-committed', 'receipt': receipt}):
                    raise RootBootstrapControlError()
            elif complete != {**common, 'step': 'stage-complete',
                             'stageBindingSha256': digest(encoded([request['operationId'], request['planSha256'],
                                                                  request_id, request['collectionNonce']]))}:
                raise RootBootstrapControlError()
            require_eof(connection, deadline)
            return complete


class RootBootstrapControl:
    def __init__(self, bootstrap, *, check=None, controller_return=None):
        from .recovery_bootstrap import RecoveryBootstrap
        from .controller_return_readiness import ControllerReturnGateway
        if type(bootstrap) is not RecoveryBootstrap or check is not None and not callable(check):
            raise ValueError('A concrete Root bootstrap engine is required.')
        if controller_return is not None and (type(controller_return) is not ControllerReturnGateway
                or controller_return.approvals.sessions is not bootstrap.store
                or controller_return.approvals.origin != bootstrap.origin):
            raise ValueError('Controller return must share the Root bootstrap Sessions owner.')
        self.bootstrap, self.check = bootstrap, check
        self.controller_return = controller_return

    def handle(self, request):
        try:
            if self.check is not None:
                self.check()
            if (type(request) is not dict or set(request) != {'schema', 'operation', 'arguments'}
                    or request['schema'] != _SCHEMA or request['operation'] not in _OPERATIONS
                    or type(request['arguments']) is not dict):
                raise ValueError('Invalid Root bootstrap operation.')
            operation, args = request['operation'], request['arguments']
            if operation == 'controller-return-readiness-arm':
                if self.controller_return is None:
                    raise ValueError('Controller return readiness is unavailable.')
                return {'schema': _SCHEMA, 'ok': True, 'result': self.controller_return.arm(args)}
            if operation == 'controller-return-claim':
                from .controller_return import ControllerReturnApprovals
                if set(args) != {'approvalId', 'scope', 'claimId'}:
                    raise ValueError('Invalid controller return approval fields.')
                approvals = (self.controller_return.approvals if self.controller_return is not None else
                             ControllerReturnApprovals(self.bootstrap.store, origin=self.bootstrap.origin))
                result = approvals.claim(approval_id=args['approvalId'], scope=args['scope'], claim_id=args['claimId'])
                return {'schema': _SCHEMA, 'ok': True, 'result': result}
            if operation in _BROWSER_OPERATIONS:
                action = _BROWSER_OPERATIONS[operation]
                fields = {'operationId', 'reviewSha256', 'planSha256', 'keyRevision', 'deliveryEpoch'}
                if action in ('deliver', 'confirm'):
                    fields.add('handoff')
                if action == 'confirm':
                    fields.add('recoveryKey')
                if set(args) != fields:
                    raise ValueError('Invalid browser handoff fields.')
                result = self.bootstrap.browser_key_handoff(action, operation_id=args['operationId'],
                    review_sha256=args['reviewSha256'], plan_sha256=args['planSha256'], key_revision=args['keyRevision'],
                    delivery_epoch=args['deliveryEpoch'], handoff=args.get('handoff'), recovery_key=args.get('recoveryKey'))
                return {'schema': _SCHEMA, 'ok': True, 'result': result}
            if operation == 'bootstrap-enrollment-state':
                if args:
                    raise ValueError('Enrollment state does not accept arguments.')
                return {'schema': _SCHEMA, 'ok': True, 'result': self.bootstrap.enrollment_state()}
            if operation in ('bootstrap-listener-probe-arm', 'bootstrap-listener-probe-confirm'):
                arm = operation == 'bootstrap-listener-probe-arm'
                fields = {'operationId', 'markerSha256'}
                if not arm:
                    fields.update(('nonce', 'bindingSha256'))
                if set(args) != fields:
                    raise ValueError('Invalid recovery listener setup fields.')
                result = self.bootstrap.listener_probe(action='arm' if arm else 'confirm', operation_id=args['operationId'],
                    marker_sha256=args['markerSha256'], nonce=args.get('nonce'), binding_sha256=args.get('bindingSha256'))
                return {'schema': _SCHEMA, 'ok': True, 'result': result}
            names = {
                'bootstrap-source-challenge': ('operationId', 'planSha256', 'phase', 'requestId'),
                'bootstrap-stage': ('operationId', 'planSha256', 'requestId', 'collectionNonce'),
                'bootstrap-key-prepare': ('operationId', 'planSha256'),
                'bootstrap-status': ('operationId',),
                'bootstrap-ack': ('operationId', 'planSha256', 'deliveryEpoch', 'recoveryKey'),
                'bootstrap-activate': ('operationId', 'planSha256', 'requestId', 'collectionNonce', 'ackReceiptId'),
                'bootstrap-held-review': ('operationId', 'reviewSha256'),
                'bootstrap-held-key-status': ('operationId', 'planSha256'),
                'bootstrap-held-activation-challenge': ('operationId', 'planSha256', 'packetSha256', 'requestId'),
                'bootstrap-held-activation-receipt': ('operationId', 'planSha256', 'packetSha256'),
                'bootstrap-held-activation-projection': ('operationId', 'planSha256', 'requestId'),
                'bootstrap-held-activation-reconcile': ('operationId', 'planSha256', 'packetSha256'),
                'bootstrap-paired-publication-ready': ('operationId', 'planSha256', 'packetSha256'),
                'bootstrap-paired-publication-publish': ('operationId', 'planSha256', 'packetSha256'),
            }[operation]
            if set(args) != set(names):
                raise ValueError('Invalid Root bootstrap fields.')
            translated = {'operation_id': args['operationId']}
            for wire, local in (('planSha256','plan_sha256'),('requestId','request_id'),('collectionNonce','collection_nonce'),
                                ('deliveryEpoch','delivery_epoch'),('recoveryKey','recovery_key'),('ackReceiptId','ack_receipt_id'),
                                ('phase','phase'),('reviewSha256','review_sha256'),('packetSha256','packet_sha256')):
                if wire in args:
                    translated[local] = args[wire]
            method = {'bootstrap-source-challenge': self.bootstrap.source_challenge, 'bootstrap-stage': self.bootstrap.stage,
                      'bootstrap-key-prepare': self.bootstrap.prepare_key, 'bootstrap-status': self.bootstrap.status,
                      'bootstrap-ack': self.bootstrap.acknowledge, 'bootstrap-activate': self.bootstrap.activate,
                      'bootstrap-held-review': self.bootstrap.held_review_status,
                      'bootstrap-held-key-status': self.bootstrap.held_key_status,
                      'bootstrap-held-activation-challenge': self.bootstrap.held_activation_challenge,
                      'bootstrap-held-activation-receipt': self.bootstrap.held_activation_receipt,
                      'bootstrap-held-activation-projection': self.bootstrap.held_activation_projection,
                      'bootstrap-held-activation-reconcile': self.bootstrap.held_activation_reconcile,
                      'bootstrap-paired-publication-ready': self.bootstrap.paired_publication_ready,
                      'bootstrap-paired-publication-publish': self.bootstrap.paired_publication_publish}[operation]
            result = method(**translated)
            return {'schema': _SCHEMA, 'ok': True, 'result': result}
        except Exception:
            return {'schema': _SCHEMA, 'ok': False, 'error': 'Root bootstrap requires reconciliation.'}

    def handle_held(self, connection, offer, descriptors, deadline):
        from .bootstrap_source import hash_value
        from .collector_execution import HELD_ACTIVATION, HELD_STAGE, _challenge, receive_frame, require_eof, send_frame
        activating = offer.get('schema') == HELD_ACTIVATION
        fields = ('operationId', 'planSha256', 'requestId', 'reviewSha256', 'holdBinding',
                  'capsuleSha256', 'inventorySha256', 'descriptorSha256', 'sourceSha256')
        if activating:
            fields += ('packetSha256', 'intentSha256')
        if (set(offer) != {'schema', 'step', 'collectionNonce', *fields}
                or offer['schema'] not in (HELD_STAGE, HELD_ACTIVATION) or offer['step'] != 'offer'
                or not all(hash_value(offer[key]) for key in fields)):
            raise ValueError('Invalid held Root stage offer')
        _challenge(offer['collectionNonce'])
        if self.check is not None:
            self.check()
        open_proof = self.bootstrap.open_held_activation if activating else self.bootstrap.open_held_stage
        with open_proof(offer, descriptors, deadline) as proof:
            extra = {}
            if activating:
                challenge, commit = self.bootstrap.activate_held(proof)
                extra['commitSha256'] = commit
            else:
                challenge = self.bootstrap.stage_held(proof)
            common = {key: offer[key] for key in ('schema', 'operationId', 'planSha256', 'requestId')}
            send_frame(connection, {**common, 'step': 'finish-required', 'terminalChallenge': challenge, **extra}, deadline)
            finished, _ = receive_frame(connection, deadline)
            receipt = finished.get('terminalReceiptSha256')
            if (not hash_value(receipt) or finished != {**common, 'step': 'finished',
                                       'terminalChallenge': challenge, 'terminalReceiptSha256': receipt, **extra}):
                raise ValueError('Invalid held Root terminal proof')
            require_eof(connection, deadline)
            if activating:
                result = self.bootstrap.finish_held_activation(proof, terminal_challenge=challenge,
                    receipt_sha256=receipt, commit_sha256=commit)
                send_frame(connection, {**common, 'step': 'activation-committed', 'receipt': result}, deadline)
                return
            binding = self.bootstrap.finish_held(proof, terminal_challenge=challenge, receipt_sha256=receipt)
            send_frame(connection, {**common, 'step': 'stage-complete', 'stageBindingSha256': binding}, deadline)


# Reuse the bounded Root-peer framing/server custody, with a DIFFERENT socket
# and application schema. Ordinary WriterControlClient cannot send these ops.
class RootBootstrapControlServer:
    def __new__(cls, path, application):
        # The separately pinned host client does not load server/worker code.
        from .recovery_control import RecoveryControlServer

        class BootstrapSocket(RecoveryControlServer):
            def _handle_connection(self, connection):
                from .collector_execution import DEADLINE, HELD_ACTIVATION, HELD_STAGE, receive_frame, require_eof, send_frame
                now = time.monotonic()
                request, descriptors = receive_frame(connection, now + 2, maximum=196608, rights=3)
                try:
                    if self._stop.is_set():
                        return
                    if request.get('schema') in (HELD_STAGE, HELD_ACTIVATION):
                        self.application.handle_held(connection, request, descriptors, now + DEADLINE)
                        return
                    if descriptors:
                        return
                    require_eof(connection, now + 2)
                    send_frame(connection, self.application.handle(request), now + 4, maximum=98304)
                except Exception:
                    return
                finally:
                    for fd in descriptors:
                        os.close(fd)

        return BootstrapSocket(path, application)
