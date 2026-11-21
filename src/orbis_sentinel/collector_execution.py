"""Held-byte collector execution custody, distinct from publisher/admission authority.

The inventory executor never issues a SourceBundleReceipt, opens a managed gate,
or retires a bootstrap hold. Its isolated fixed child owns the actual Host guard
and CaptureLease; only its parent-owned opaque process lease proves live custody.
"""
import array
import base64
import builtins
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import select
import selectors
import socket
import stat
import struct
import subprocess
import sys
import time
from types import MappingProxyType, ModuleType

HOST_SOURCE = Path('/opt/orbis/host-service')
SNAPSHOTS = Path('/var/lib/orbis/snapshots')
HOST_STATE = Path('/var/lib/orbis/state')
PYTHON = Path('/usr/bin/python3')
SCHEMA = 'orbis.collector-execution-custody.v1'
HELD_STAGE = 'orbis.sentinel-bootstrap-held-stage.v1'
HELD_ACTIVATION = 'orbis.sentinel-held-activation.v1'


def held_schema(phase):
    if phase == 'proposal':
        return HELD_STAGE
    if phase == 'activation':
        return HELD_ACTIVATION
    raise unavailable()
HELD_FRAME = 4096
MAX_FILES = 128
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
FRAME = 32768
DEADLINE = 120
_REQUIRED = frozenset({'orbis-host-credential-service.py', 'orbis-host-service.py',
    'orbis-host-recovery-source.py', 'orbis-host-recovery-admission.py',
    'orbis-host-core-pg-profiles.py'})
_NAME = re.compile(r'(?:orbis-[a-z-]+|migration-preflight|install-orbis)\.(?:py|mjs)\Z')
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_KEY = object()


class ExecutionUnavailable(ValueError):
    pass


class UncertainExecution(ExecutionUnavailable):
    def __init__(self, pending):
        super().__init__('Owned collector termination is uncertain; retain its pinned inputs and operation hold.')
        self.pending = pending


def unavailable():
    return ExecutionUnavailable('Protected collector execution custody is unavailable; preserve its operation hold.')


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def _hash(body):
    return hashlib.sha256(body).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise unavailable()
        result[key] = value
    return result


def _decoded(body):
    def invalid(_):
        raise unavailable()
    value = json.loads(body, object_pairs_hook=_pairs, parse_float=invalid, parse_constant=invalid)
    if type(value) is not dict:
        raise unavailable()
    return value


def _hash_value(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def _challenge(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        raise unavailable()
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + '=')).decode().rstrip('=') != value:
        raise unavailable()
    return value


def _inventory_mapping(expected):
    if (type(expected) is not dict or not _REQUIRED <= set(expected) or not len(expected) <= MAX_FILES
            or any(type(name) is not str or not _NAME.fullmatch(name) or not _hash_value(digest)
                   for name, digest in expected.items())):
        raise unavailable()
    return dict(expected)


def _root():
    if sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0:
        raise unavailable()


class _SourceLoader:
    def __init__(self, owner, name, filename):
        self.owner, self.name, self.filename = owner, name, filename
        self.module = None

    def create_module(self, spec):
        if spec.loader is not self:
            raise unavailable()
        return None

    def exec_module(self, module):
        if self.module is not module or module.__spec__.loader is not self:
            raise unavailable()
        self.owner._execute(module, self.filename)


class _ByteModules:
    """Local importlib substitution only; real global imports/hooks are untouched."""
    def __init__(self, inventory):
        self.inventory = inventory
        self._codes = {}
        self.executions = list(getattr(inventory, 'bootstrap_executions', ()))
        self.util = ModuleType('importlib.util')
        self.util.spec_from_file_location = self._spec
        self.util.module_from_spec = self._module
        self.util.spec_from_loader = self._metadata_spec
        self.proxy = ModuleType('importlib')
        self.proxy.util = self.util
        self.proxy.import_module = self._closed_import

    @staticmethod
    def _closed_import(*_args, **_kwargs):
        raise unavailable()

    @staticmethod
    def _metadata_spec(name, loader=None, *, origin=None, is_package=None):
        if loader is not None:
            raise unavailable()
        return importlib.util.spec_from_loader(name, loader=None, origin=origin, is_package=is_package)

    def _import(self, name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in ('importlib', 'importlib.util'):
            return self.util if name == 'importlib.util' and fromlist else self.proxy
        return builtins.__import__(name, globals, locals, fromlist, level)

    def _spec(self, name, location, *, loader=None, submodule_search_locations=None):
        self.inventory.verify()
        path = Path(location)
        if (type(name) is not str or not name or len(name) > 256 or loader is not None
                or submodule_search_locations is not None or path.parent != self.inventory.directory
                or path.name not in self.inventory.bodies or not path.name.endswith('.py')
                or str(path) != os.path.realpath(path)):
            raise unavailable()
        source_loader = _SourceLoader(self, name, path.name)
        return importlib.util.spec_from_loader(name, source_loader, origin=str(path))

    def _module(self, spec):
        if not isinstance(spec.loader, _SourceLoader) or spec.loader.owner is not self or spec.loader.module is not None:
            raise unavailable()
        module = importlib.util.module_from_spec(spec)
        module.__file__ = str(self.inventory.directory / spec.loader.filename)
        spec.loader.module = module
        return module

    def _execute(self, module, filename):
        self.inventory.verify()
        if filename not in self._codes:
            self._codes[filename] = compile(self.inventory.bodies[filename],
                str(self.inventory.directory / filename), 'exec', dont_inherit=True)
        module.__dict__['__builtins__'] = {**vars(builtins), '__import__': self._import}
        exec(self._codes[filename], module.__dict__)
        self.inventory.verify()
        self.executions.append({'alias': module.__name__, 'filename': filename,
                                'sha256': _hash(self.inventory.bodies[filename])})

    def load(self, filename, alias):
        spec = self._spec(alias, self.inventory.directory / filename)
        module = self._module(spec)
        spec.loader.exec_module(module)
        return module


class CollectorExecutionInventory:
    """Exact installed file custody only. Expected hashes are NOT publisher proof."""
    def __init__(self, key, directory, pins, resources):
        if key is not _KEY:
            raise unavailable()
        self.directory, self._pins, self._resources = directory, pins, resources
        self.bodies = MappingProxyType({name: pin.body for name, pin in pins.items()})
        self._sha256 = _hash(_encoded({name: _hash(body) for name, body in self.bodies.items()}))
        self.closed = False
        self._leases = set()

    @classmethod
    def open_installed(cls, expected):
        # These are existing Root custody primitives, not a receipt issuer.
        from .bootstrap_source import PrivateDirectory, PrivateFile
        expected = _inventory_mapping(expected)
        resources = ExitStack()
        try:
            directory = resources.enter_context(PrivateDirectory(HOST_SOURCE))
            if set(os.listdir(directory.fd)) != set(expected):
                raise unavailable()
            pins = {}
            total = 0
            for name, digest in sorted(expected.items()):
                pin = resources.enter_context(PrivateFile(directory, name, MAX_FILE))
                if _hash(pin.body) != digest:
                    raise unavailable()
                total += len(pin.body)
                if total > MAX_TOTAL:
                    raise unavailable()
                pins[name] = pin
            result = cls(_KEY, HOST_SOURCE, pins, resources)
            result.verify()
            return result
        except BaseException:
            resources.close()
            raise

    def verify(self):
        if self.closed or set(os.listdir(self.directory)) != set(self._pins):
            raise unavailable()
        for pin in self._pins.values():
            pin.verify()

    @property
    def inventory_sha256(self):
        self.verify()
        return self._sha256

    def require_managed_admission(self):
        raise ExecutionUnavailable('Inventory custody does not establish independent publisher or managed admission authority.')

    def capture(self, *, root, context, request, hold_binding, held_stage=False):
        _root()
        self.verify()
        scope = _scope(root, context, request, hold_binding)
        if type(held_stage) is not bool:
            raise unavailable()
        # Bootstrap C itself from held bytes before reusing its genuine pin.
        modules = _ByteModules(self)
        credential = modules.load('orbis-host-credential-service.py', '_collector_bootstrap_credential')
        with ExitStack() as resources:
            # This is custody of the retained caller's source, not proof that
            # its already-running bytecode/publisher lineage was qualified.
            source_pin = credential.PinnedFile(Path(__file__).resolve(strict=True), limit=MAX_FILE)
            resources.callback(source_pin.close)
            interpreter = credential.PinnedFile(PYTHON.resolve(strict=True), limit=64 * 1024 * 1024)
            resources.callback(interpreter.close)
            payload = {'schema': SCHEMA, 'directory': str(self.directory), 'inventorySha256': self.inventory_sha256,
                'bodies': {name: base64.b64encode(body).decode() for name, body in self.bodies.items()}, 'scope': scope}
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            resources.callback(child.close)
            resources.callback(parent.close)
            fd = os.memfd_create('orbis-fixed-collector', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            resources.callback(os.close, fd)
            if held_stage:
                capsule = _held_program(source_pin.body, child.fileno(), fd, payload)
            else:
                capsule = (source_pin.body + b'\n_child_entry(' + str(child.fileno()).encode() + b',' + repr(payload).encode() + b')\n')
            remaining = memoryview(capsule)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise unavailable()
                remaining = remaining[written:]
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                raise unavailable()
            source_pin.verify(); interpreter.verify(); self.verify()
            process = subprocess.Popen([str(interpreter.path), '-I', '-B', '/proc/self/fd/' + str(fd)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                pass_fds=(fd, child.fileno()), close_fds=True, start_new_session=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'PYTHONDONTWRITEBYTECODE': '1'})
            child.close()
            lease = ExecutionLease(_KEY, self, scope, process, None, None, fd,
                _hash(capsule), source_pin, interpreter, resources.pop_all())
            self._leases.add(lease)
            try:
                lease._held_stage = held_stage
                lease._capsule_identity = _sealed_capsule(fd, _hash(capsule))
                identity = _process_identity(process.pid)
                if identity['executable'] != list(interpreter.identity[:2]):
                    raise unavailable()
                lease._identity = identity
                lease._channel = _Duplex(parent, process, time.monotonic() + DEADLINE)
                lease._accept(lease._channel.receive())
                return lease
            except BaseException:
                lease.abort()
                raise

    def close(self):
        if self._leases:
            raise UncertainExecution(next(iter(self._leases)))
        if not self.closed:
            self.closed = True
            self._resources.close()

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, *_):
        self.close()


def _scope(root, context, request, hold_binding):
    root = Path(root)
    fields = {'operationId', 'planSha256', 'phase', 'collectionNonce', 'origin'}
    if (not root.is_absolute() or str(root) != os.path.realpath(root) or not root.is_dir()
            or type(context) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', context)
            or not _hash_value(hold_binding) or type(request) is not dict or set(request) != fields
            or not all(_hash_value(request[key]) for key in ('operationId', 'planSha256'))
            or request['phase'] not in ('proposal', 'activation') or type(request['origin']) is not str
            or not request['origin'].startswith('https://') or len(request['origin']) > 512):
        raise unavailable()
    _challenge(request['collectionNonce'])
    return {'root': str(root), 'context': context, 'request': dict(request), 'holdBinding': hold_binding}


def _process_identity(pid):
    _root()
    text = Path('/proc/' + str(pid) + '/stat').read_text()
    parts = text[text.rfind(') ') + 2:].split()
    status = Path('/proc/' + str(pid) + '/status').read_text()
    uid = re.findall(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$', status, re.M)
    exe = Path('/proc/' + str(pid) + '/exe').stat()
    if not uid or any(value != '0' for value in uid[0]) or len(parts) < 20 or not parts[19].isdigit():
        raise unavailable()
    return {'pid': pid, 'startTicks': int(parts[19]), 'executable': [exe.st_dev, exe.st_ino]}


def _sealed_capsule(fd, expected_sha256=None):
    expected = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    info = os.fstat(fd)
    if (fcntl.fcntl(fd, fcntl.F_GET_SEALS) != expected or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or not 0 < info.st_size <= MAX_TOTAL * 2 + MAX_FILE):
        raise unavailable()
    hasher = hashlib.sha256()
    offset = 0
    while offset < info.st_size:
        chunk = os.pread(fd, min(65536, info.st_size - offset), offset)
        if not chunk:
            raise unavailable()
        hasher.update(chunk); offset += len(chunk)
    observed = hasher.hexdigest()
    if expected_sha256 is not None and observed != expected_sha256:
        raise unavailable()
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size, observed)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise unavailable()
    return remaining


def _rights_read(connection, count, descriptors, maximum, *, eof=False):
    item_size = array.array('i').itemsize
    chunk, records, flags, _ = connection.recvmsg(count, socket.CMSG_SPACE((maximum + 1) * item_size),
                                                 getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
    accepted = True
    for level, kind, raw in records:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            accepted = False
            continue
        rights = array.array('i')
        rights.frombytes(raw[:len(raw) - len(raw) % item_size])
        accepted = accepted and bool(rights) and len(raw) == len(rights) * item_size
        descriptors.extend(rights)
        for fd in rights:
            os.set_inheritable(fd, False)
    if (not accepted or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
            or len(descriptors) > maximum or not chunk and not eof):
        raise unavailable()
    return chunk


def _close_rights(descriptors):
    while descriptors:
        os.close(descriptors.pop())


def receive_frame(connection, deadline, *, maximum=HELD_FRAME, rights=0):
    """Read one bounded frame. Rights may accompany only its first byte."""
    descriptors = []
    first = True

    def read(count):
        nonlocal first
        body = bytearray()
        while len(body) < count:
            connection.settimeout(_remaining(deadline))
            observed = descriptors if first else []
            try:
                body.extend(_rights_read(connection, count - len(body), observed, rights if first else 0))
            finally:
                if not first:
                    _close_rights(observed)
            first = False
        return body

    try:
        size = struct.unpack('!I', read(4))[0]
        if not 1 <= size <= (HELD_FRAME if descriptors else maximum):
            raise unavailable()
        return _decoded(read(size)), tuple(descriptors)
    except BaseException:
        _close_rights(descriptors)
        raise


def send_frame(connection, value, deadline, *, maximum=HELD_FRAME, rights=()):
    body = _encoded(value)
    if not 1 <= len(body) <= maximum:
        raise unavailable()
    frame = struct.pack('!I', len(body)) + body
    connection.settimeout(_remaining(deadline))
    if rights:
        count = connection.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', rights))])
        if not 0 < count <= len(frame):
            raise unavailable()
        frame = frame[count:]
    if frame:
        connection.settimeout(_remaining(deadline))
        connection.sendall(frame)


def require_eof(connection, deadline):
    rights = []
    try:
        connection.settimeout(_remaining(deadline))
        if _rights_read(connection, 1, rights, 0, eof=True):
            raise unavailable()
    finally:
        _close_rights(rights)


def _pidfd_pid(fd):
    with open('/proc/self/fdinfo/' + str(fd), 'rb') as stream:
        body = stream.read(4097)
    entries = re.findall(rb'(?m)^Pid:[ \t]+([1-9][0-9]*)$', body)
    if len(body) > 4096 or len(entries) != 1:
        raise unavailable()
    return int(entries[0])


def _pidfd_exited(fd):
    probe = select.poll()
    probe.register(fd, select.POLLIN | select.POLLHUP)
    ready = probe.poll(0)
    if not ready:
        return False
    if len(ready) != 1 or ready[0][0] != fd or ready[0][1] & ~(select.POLLIN | select.POLLHUP):
        raise unavailable()
    return True


def _peer_identity(connection):
    if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
        raise unavailable()
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))


def _held_program(source, duplex_fd, capsule_fd, payload):
    arguments = b'%d,%d,' % (duplex_fd, capsule_fd)
    return source + b"\n_held_child_entry(" + arguments + b"'" + base64.b64encode(_encoded(payload)) + b"')\n"


def _verify_held_program(fd, identity, *, source, scope, inventory):
    program = os.pread(fd, identity[5] + 1, 0)
    if len(program) != identity[5] or not program.startswith(source):
        raise unavailable()
    arguments = re.fullmatch(rb"\n_held_child_entry\(([0-9]{1,9}),([0-9]{1,9}),'([A-Za-z0-9+/=]+)'\)\n",
                             program[len(source):])
    if not arguments or int(arguments[1]) == int(arguments[2]):
        raise unavailable()
    payload = _decoded(base64.b64decode(arguments[3], validate=True))
    bodies = payload.get('bodies')
    if (type(bodies) is not dict or not 1 <= len(bodies) <= MAX_FILES
            or any(type(body) is not str for body in bodies.values())):
        raise unavailable()
    raw = {name: base64.b64decode(body, validate=True) for name, body in bodies.items()}
    if (any(not 0 < len(body) <= MAX_FILE for body in raw.values()) or sum(map(len, raw.values())) > MAX_TOTAL
            or _hash(_encoded(_inventory_mapping({name: _hash(body) for name, body in raw.items()}))) != inventory
            or payload != {'schema': SCHEMA, 'directory': str(HOST_SOURCE), 'inventorySha256': inventory,
                           'bodies': bodies, 'scope': scope}
            or _held_program(source, int(arguments[1]), int(arguments[2]), payload) != program):
        raise unavailable()


class HeldStageProof:
    """Receiver custody for one exact collection phase."""

    def __init__(self, offer, descriptors, deadline, *, scope, inventory):
        self.phase = scope['request']['phase']
        if offer.get('schema') != held_schema(self.phase) or len(descriptors) != 3 or len(set(descriptors)) != 3:
            raise unavailable()
        self.offer, self.deadline = dict(offer), deadline
        self.pidfd, self.capsule, peer_fd = descriptors
        duplicate = os.dup(peer_fd)
        try:
            self.peer = socket.socket(fileno=duplicate)
        except BaseException:
            os.close(duplicate)
            raise
        self.root, self.context = scope['root'], scope['context']
        self.start_ticks = None
        try:
            self.pid = _pidfd_pid(self.pidfd)
            self.identity = _sealed_capsule(self.capsule, offer['capsuleSha256'])
            if fcntl.fcntl(self.capsule, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
                raise unavailable()
            self._live()
            with Path(__file__).open('rb') as stream:
                source = stream.read(MAX_FILE + 1)
            if not 0 < len(source) <= MAX_FILE:
                raise unavailable()
            _verify_held_program(self.capsule, self.identity, source=source, scope=scope, inventory=inventory)
        except BaseException:
            self.close()
            raise

    def _live(self):
        if (_pidfd_exited(self.pidfd) or _pidfd_pid(self.pidfd) != self.pid
                or _peer_identity(self.peer) != (self.pid, 0, 0)
                or _sealed_capsule(self.capsule, self.offer['capsuleSha256']) != self.identity):
            raise unavailable()
        _remaining(self.deadline)

    def check(self, captured):
        if (captured.operation != self.offer['operationId'] or captured.plan_sha256 != self.offer['planSha256']
                or captured.phase != self.phase or captured.nonce != self.offer['collectionNonce']
                or captured.collector_pid != self.pid
                or self.start_ticks is not None and captured.collector_start_ticks != self.start_ticks
                or _hash(captured.body) != self.offer['sourceSha256']
                or captured.descriptor_sha256 != self.offer['descriptorSha256']):
            raise unavailable()
        captured.verify()
        self._live()
        fields = ('operationId', 'planSha256', 'requestId')
        challenge = secrets.token_urlsafe(32)
        common = {'schema': self.offer['schema'], **{key: self.offer[key] for key in fields}, 'challenge': challenge}
        send_frame(self.peer, {**common, 'step': 'check'}, self.deadline)
        response, _ = receive_frame(self.peer, self.deadline)
        bindings = ('sourceSha256', 'descriptorSha256', 'inventorySha256', 'capsuleSha256')
        if response != {**common, 'step': 'checked', 'capsuleIdentity': list(self.identity[:2]),
                        **{key: self.offer[key] for key in bindings}}:
            raise unavailable()
        self._live()
        captured.verify()
        self.start_ticks = captured.collector_start_ticks

    def terminal(self):
        if not _pidfd_exited(self.pidfd):
            raise unavailable()
        require_eof(self.peer, self.deadline)

    def close(self):
        self.peer.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _Duplex:
    """Finite parent-owned pipe; output and diagnostic bytes never become logs."""
    def __init__(self, connection, process, deadline):
        self.connection, self.process, self.deadline = connection, process, deadline
        self.buffer = bytearray()
        self.errors = 0
        connection.setblocking(False)
        os.set_blocking(process.stderr.fileno(), False)

    def _io(self, wanted, body=b''):
        pending = memoryview(body)
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.connection, selectors.EVENT_READ | (selectors.EVENT_WRITE if pending else 0), 'pipe')
            selector.register(self.process.stderr, selectors.EVENT_READ, 'err')
            while pending or len(self.buffer) < wanted:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise unavailable()
                for key, events in selector.select(min(remaining, 0.1)):
                    if key.data == 'pipe':
                        if events & selectors.EVENT_WRITE and pending:
                            pending = pending[self.connection.send(pending[:4096]):]
                            if not pending:
                                selector.modify(self.connection, selectors.EVENT_READ, 'pipe')
                        if events & selectors.EVENT_READ:
                            chunk = self.connection.recv(4096)
                            if not chunk:
                                raise unavailable()
                            self.buffer.extend(chunk)
                            if len(self.buffer) > FRAME + 4:
                                raise unavailable()
                    else:
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        self.errors += len(chunk)
                        if self.errors > 4096:
                            raise unavailable()
        finally:
            selector.close()

    def send(self, value):
        body = _encoded(value)
        if not 0 < len(body) <= FRAME:
            raise unavailable()
        self._io(0, struct.pack('!I', len(body)) + body)

    def receive(self):
        self._io(4)
        size = struct.unpack('!I', self.buffer[:4])[0]
        if not 0 < size <= FRAME:
            raise unavailable()
        self._io(size + 4)
        body = bytes(self.buffer[4:size + 4])
        del self.buffer[:size + 4]
        return _decoded(body)

    def terminal(self):
        if self.buffer:
            raise unavailable()
        selector = selectors.DefaultSelector()
        try:
            selector.register(self.connection, selectors.EVENT_READ, 'pipe')
            selector.register(self.process.stderr, selectors.EVENT_READ, 'err')
            while selector.get_map():
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise unavailable()
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = self.connection.recv(4096) if key.data == 'pipe' else os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.data == 'pipe':
                        raise unavailable()
                    else:
                        self.errors += len(chunk)
                        if self.errors > 4096:
                            raise unavailable()
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.process.wait(timeout=remaining):
                raise unavailable()
        finally:
            selector.close()


class ExecutionLease:
    """Local opaque live custody. Never a serialized publisher/admission ticket."""
    def __init__(self, key, inventory, scope, process, channel, identity, capsule_fd,
                 capsule_sha256, source_pin, interpreter, resources):
        if key is not _KEY:
            raise unavailable()
        self._inventory, self._scope = inventory, scope
        self._process, self._channel, self._identity = process, channel, identity
        self._capsule_fd, self._capsule_sha256 = capsule_fd, capsule_sha256
        self._capsule_identity = None
        self._source_pin, self._interpreter, self._resources = source_pin, interpreter, resources
        self._binding = None
        self._closed = False
        self._checks = 0
        self._uncertain = False
        self._pid = os.getpid()
        self._held_stage = False
        self._proof_opened = False

    def _accept(self, value):
        fields = {'schema', 'phase', 'request', 'installationId', 'sourceSha256', 'descriptorSha256', 'inventorySha256', 'executionSha256'}
        if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA or value['phase'] != 'captured'
                or value['request'] != self._scope['request'] or value['inventorySha256'] != self._inventory.inventory_sha256
                or any(not _hash_value(value[key]) for key in ('installationId', 'sourceSha256', 'descriptorSha256', 'executionSha256'))):
            raise unavailable()
        self._binding = dict(value)
        self._verify()

    def require_inventory(self, inventory):
        if inventory is not self._inventory:
            raise unavailable()
        self._verify()

    @property
    def observation(self):
        self._verify()
        return _decoded(_encoded({**self._binding, 'process': self._identity, 'capsuleSha256': self._capsule_sha256,
                'root': self._scope['root'], 'context': self._scope['context'], 'holdBinding': self._scope['holdBinding'],
                'authority': 'inventory-execution-custody-only'}))

    def _verify(self):
        if (self._closed or self._pid != os.getpid() or self._binding is None or self._process.poll() is not None
                or _process_identity(self._process.pid) != self._identity):
            raise unavailable()
        self._inventory.verify(); self._source_pin.verify(); self._interpreter.verify()
        if (self._capsule_identity is None or
                _sealed_capsule(self._capsule_fd, self._capsule_sha256) != self._capsule_identity):
            raise unavailable()
        if self._channel.connection.fileno() < 0:
            raise unavailable()

    def check(self, challenge=None):
        self._verify()
        if self._checks >= 4:
            raise unavailable()
        challenge = _challenge(challenge or secrets.token_urlsafe(32))
        self._channel.send({'schema': SCHEMA, 'operation': 'check', 'challenge': challenge})
        value = self._channel.receive()
        expected = {**self._binding, 'phase': 'checked', 'challenge': challenge}
        if value != expected:
            raise unavailable()
        self._checks += 1
        self._verify()
        return self.observation

    def open_held_proof(self, request_id):
        """The caller owns only the three transfer FDs, never the child duplex."""
        self._verify()
        if not self._held_stage or self._proof_opened or not _hash_value(request_id):
            raise unavailable()
        self._proof_opened = True
        descriptors = []
        try:
            pidfd = os.pidfd_open(self._process.pid, 0)
            descriptors.append(pidfd)
            descriptors.append(os.open('/proc/self/fd/' + str(self._capsule_fd), os.O_RDONLY | os.O_CLOEXEC))
            if _pidfd_pid(pidfd) != self._process.pid or _pidfd_exited(pidfd) or self._channel.buffer:
                raise unavailable()
            schema = held_schema(self._scope['request']['phase'])
            self._channel.send({'schema': schema, 'step': 'open', 'requestId': request_id})
            reply, rights = receive_frame(self._channel.connection, self._channel.deadline, rights=1)
            descriptors.extend(rights)
            if (reply != {'schema': schema, 'step': 'opened', 'requestId': request_id}
                    or len(descriptors) != 3):
                raise unavailable()
            self._channel.connection.setblocking(False)
            self._verify()
            return tuple(descriptors)
        except BaseException:
            _close_rights(descriptors)
            raise

    def finish(self):
        self._verify()
        receipt = self.observation
        challenge = secrets.token_urlsafe(32)
        self._channel.send({'schema': SCHEMA, 'operation': 'finish', 'challenge': challenge})
        if self._channel.receive() != {**self._binding, 'phase': 'finished', 'challenge': challenge}:
            raise unavailable()
        self._channel.terminal()
        self._inventory.verify(); self._source_pin.verify(); self._interpreter.verify()
        self._closed = True
        self._resources.close()
        self._process.stderr.close()
        self._inventory._leases.discard(self)
        return {**receipt, 'phase': 'complete', 'exitCode': 0}

    def abort(self):
        # The child/collector records and durable Host hold are NEVER retired here.
        if not self._closed:
            if self._process.poll() is None:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
                except OSError:
                    self._uncertain = True
                    raise UncertainExecution(self) from None
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._uncertain = True
                raise UncertainExecution(self) from None
            self._closed = True
            self._process.stderr.close()
            self._resources.close()
            self._inventory._leases.discard(self)

    close = abort

    def require_managed_admission(self):
        raise ExecutionUnavailable('Execution custody does not establish independent publisher or managed admission authority.')

    def __enter__(self):
        self._verify()
        return self

    def __exit__(self, *_):
        self.abort()


class _ChildInventory:
    def __init__(self, directory, bodies):
        self.directory, self.bodies = directory, MappingProxyType(dict(bodies))
        self.resources = ExitStack()
        # This first C execution is exact bytes in the sealed, parent-created
        # capsule. C has only stdlib imports; no pathname helper is executed.
        module = ModuleType('_collector_child_pin')
        module.__file__ = str(directory / 'orbis-host-credential-service.py')
        exec(compile(bodies['orbis-host-credential-service.py'], module.__file__, 'exec', dont_inherit=True), module.__dict__)
        self.bootstrap_executions = [{'alias': module.__name__, 'filename': 'orbis-host-credential-service.py',
                                     'sha256': _hash(bodies['orbis-host-credential-service.py'])}]
        self.pins = {}
        try:
            for name, body in bodies.items():
                pin = module.PinnedFile(directory / name, limit=MAX_FILE, private=True)
                self.resources.callback(pin.close)
                if pin.body != body:
                    raise unavailable()
                self.pins[name] = pin
            self.verify()
        except BaseException:
            self.resources.close()
            raise

    def verify(self):
        if set(os.listdir(self.directory)) != set(self.bodies):
            raise unavailable()
        for pin in self.pins.values():
            pin.verify()

    def close(self):
        self.resources.close()


class _ChildWire:
    def __init__(self, connection):
        self.connection = connection
        self.deadline = time.monotonic() + DEADLINE

    def _read(self, amount):
        body = bytearray()
        while len(body) < amount:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise unavailable()
            self.connection.settimeout(remaining)
            chunk = self.connection.recv(amount - len(body))
            if not chunk:
                raise unavailable()
            body.extend(chunk)
        return bytes(body)

    def receive(self):
        size = struct.unpack('!I', self._read(4))[0]
        if not 0 < size <= FRAME:
            raise unavailable()
        return _decoded(self._read(size))

    def send(self, value):
        body = _encoded(value)
        if not 0 < len(body) <= FRAME:
            raise unavailable()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise unavailable()
        self.connection.settimeout(remaining)
        self.connection.sendall(struct.pack('!I', len(body)) + body)


def _held_child_entry(descriptor, program_fd, payload):
    if sys.argv[0] != '/proc/self/fd/' + str(program_fd):
        raise unavailable()
    os.set_inheritable(program_fd, False)
    _child_entry(descriptor, _decoded(base64.b64decode(payload, validate=True)),
                 held_identity=_sealed_capsule(program_fd))


def _child_proof(wire, capture, inventory, guard, scope, request_id, binding, held_identity):
    if not _hash_value(request_id):
        raise unavailable()
    schema = held_schema(scope['request']['phase'])
    child, transferable = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    with child, transferable:
        send_frame(wire.connection, {'schema': schema, 'step': 'opened', 'requestId': request_id},
                   wire.deadline, rights=(transferable.fileno(),))
        transferable.close()
        common = {'schema': schema, 'operationId': scope['request']['operationId'],
                  'planSha256': scope['request']['planSha256'], 'requestId': request_id}
        for _ in range(2):
            packet, _ = receive_frame(child, wire.deadline)
            challenge = _challenge(packet.get('challenge'))
            if packet != {**common, 'step': 'check', 'challenge': challenge}:
                raise unavailable()
            inventory.verify()
            guard.check(scope['request']['operationId'], scope['holdBinding'])
            capture.check(challenge)
            inventory.verify()
            send_frame(child, {**common, 'step': 'checked', 'challenge': challenge,
                'sourceSha256': binding['sourceSha256'], 'descriptorSha256': binding['descriptorSha256'],
                'inventorySha256': binding['inventorySha256'], 'capsuleSha256': held_identity[-1],
                'capsuleIdentity': list(held_identity[:2])}, wire.deadline)
        command = wire.receive()
        return command


def _child_entry(descriptor, capsule, *, held_identity=None):
    """Only the fixed sealed capsule calls this; no generic command-line mode."""
    _root()
    connection = socket.socket(fileno=descriptor)
    inventory = None
    try:
        if (type(capsule) is not dict or set(capsule) != {'schema', 'directory', 'inventorySha256', 'bodies', 'scope'}
                or capsule['schema'] != SCHEMA or capsule['directory'] != str(HOST_SOURCE)
                or not _hash_value(capsule['inventorySha256']) or type(capsule['bodies']) is not dict):
            raise unavailable()
        bodies = {name: base64.b64decode(body, validate=True) for name, body in capsule['bodies'].items()}
        mapping = _inventory_mapping({name: _hash(body) for name, body in bodies.items()})
        if (sum(len(body) for body in bodies.values()) > MAX_TOTAL or any(not 0 < len(body) <= MAX_FILE for body in bodies.values())
                or _hash(_encoded(mapping)) != capsule['inventorySha256']):
            raise unavailable()
        raw_scope = capsule['scope']
        if type(raw_scope) is not dict or set(raw_scope) != {'root', 'context', 'request', 'holdBinding'}:
            raise unavailable()
        scope = _scope(raw_scope['root'], raw_scope['context'], raw_scope['request'], raw_scope['holdBinding'])
        inventory = _ChildInventory(HOST_SOURCE, bodies)
        modules = _ByteModules(inventory)
        service_module = modules.load('orbis-host-service.py', '_owned_collector_host_service')
        source_module = modules.load('orbis-host-recovery-source.py', '_owned_collector_source')
        service = service_module.HostService(Path(scope['root']), scope['context'], SNAPSHOTS, HOST_STATE,
                                            recover_interrupted_job=False)
        wire = _ChildWire(connection)
        with service.HOST.credential_fence_lock(service.root, service.context) as guard:
            guard.begin(scope['request']['operationId'], scope['holdBinding'])
            guard.check(scope['request']['operationId'], scope['holdBinding'])
            with source_module.Collector(service).open(scope['request'], guard) as capture:
                inventory.verify()
                binding = {'schema': SCHEMA, 'phase': 'captured', 'request': scope['request'],
                    'installationId': capture.descriptor['installationId'], 'sourceSha256': _hash(capture.source),
                    'descriptorSha256': _hash(_encoded(capture.descriptor)), 'inventorySha256': capsule['inventorySha256'],
                    # Initial trace only; the complete held inventory binds
                    # later lazy dependencies too. This is not a final graph.
                    'executionSha256': _hash(_encoded(modules.executions))}
                wire.send(binding)
                for _ in range(5):
                    command = wire.receive()
                    if held_identity is not None:
                        request_id = command.get('requestId')
                        if command != {'schema': held_schema(scope['request']['phase']), 'step': 'open', 'requestId': request_id}:
                            raise unavailable()
                        command = _child_proof(wire, capture, inventory, guard, scope, request_id, binding, held_identity)
                        if command.get('operation') != 'finish':
                            raise unavailable()
                        held_identity = None
                    if (set(command) != {'schema', 'operation', 'challenge'} or command['schema'] != SCHEMA
                            or command['operation'] not in ('check', 'finish')):
                        raise unavailable()
                    challenge = _challenge(command['challenge'])
                    inventory.verify(); guard.check(scope['request']['operationId'], scope['holdBinding'])
                    if command['operation'] == 'check':
                        capture.check(challenge)
                        inventory.verify()
                        wire.send({**binding, 'phase': 'checked', 'challenge': challenge})
                    else:
                        capture.finish()
                        inventory.verify(); guard.check(scope['request']['operationId'], scope['holdBinding'])
                        wire.send({**binding, 'phase': 'finished', 'challenge': challenge})
                        return
                raise unavailable()
    except BaseException:
        # Source/SQL credentials and arbitrary child exceptions never become logs.
        raise SystemExit(1) from None
    finally:
        if inventory is not None:
            inventory.close()
        connection.close()
