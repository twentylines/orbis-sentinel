"""Filesystem/valid-pyc/owned-pipe tests, not publisher or installed admission proof."""
import array
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from orbis_sentinel import collector_execution as execution
from orbis_sentinel import recovery_sessions as sessions


class HeldFrameTests(unittest.TestCase):
    def test_rights_are_received_only_with_first_byte_and_never_inheritable(self):
        left, right = socket.socketpair()
        with left, right:
            deadline = time.monotonic() + 2
            expected = {'step': 'fixture'}
            execution.send_frame(left, expected, deadline, rights=(left.fileno(), right.fileno()))
            value, descriptors = execution.receive_frame(right, deadline, rights=2)
            try:
                self.assertEqual(value, expected)
                self.assertEqual(len(descriptors), 2)
                self.assertTrue(all(not os.get_inheritable(fd) for fd in descriptors))
            finally:
                for fd in descriptors:
                    os.close(fd)

    def test_rejects_duplicate_json_extra_or_late_rights_and_partial_frames(self):
        for kind in ('duplicate', 'extra', 'late', 'partial'):
            with self.subTest(kind=kind):
                left, right = socket.socketpair()
                with left, right:
                    if kind == 'duplicate':
                        body = b'{"x":1,"x":2}'
                        left.sendall(struct.pack('!I', len(body)) + body)
                    elif kind == 'extra':
                        execution.send_frame(left, {'x': 1}, time.monotonic() + 2,
                                             rights=(left.fileno(), right.fileno()))
                    elif kind == 'late':
                        left.sendall(struct.pack('!I', 2))
                        left.sendmsg([b'{}'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [left.fileno()]))])
                    else:
                        left.sendall(struct.pack('!I', 10) + b'{')
                        left.shutdown(socket.SHUT_WR)
                    with self.assertRaises((ValueError, OSError)):
                        execution.receive_frame(right, time.monotonic() + 2, rights=1)


class _InventoryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='collector-exec-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.base.chmod(0o700)
        self.source = self.base / 'host'; self.source.mkdir(mode=0o700)
        for name in execution._REQUIRED:
            self.write(name, b'VALUE = 1\n')
        patch = mock.patch.object(execution, 'HOST_SOURCE', self.source)
        patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(sessions, '_OWNER_UID', os.getuid())
        patch.start(); self.addCleanup(patch.stop)
        self.inventories = []
        self.addCleanup(self.close_inventories)

    def close_inventories(self):
        for inventory in reversed(self.inventories):
            for lease in list(inventory._leases):
                lease.abort()
            inventory.close()

    def write(self, name, body):
        path = self.source / name; path.write_bytes(body); path.chmod(0o600)
        return path

    def open(self):
        expected = {p.name: execution._hash(p.read_bytes()) for p in self.source.iterdir()}
        inventory = execution.CollectorExecutionInventory.open_installed(expected)
        self.inventories.append(inventory)
        return inventory



class FixtureInventory(_InventoryFixture):
    def test_whole_inventory_is_held_and_never_becomes_publisher_authority(self):
        inventory = self.open()
        self.assertEqual(len(inventory.bodies), len(execution._REQUIRED))
        self.assertTrue(execution._hash_value(inventory.inventory_sha256))
        with self.assertRaises(TypeError): inventory.bodies['orbis-host-service.py'] = b'changed'
        self.assertEqual(inventory.bodies['orbis-host-service.py'], b'VALUE = 1\n')
        with self.assertRaisesRegex(execution.ExecutionUnavailable, 'does not establish independent publisher'):
            inventory.require_managed_admission()
        unused = self.source / 'orbis-host-core-pg-profiles.py'
        body = unused.read_bytes(); unused.unlink(); self.write(unused.name, body)
        with self.assertRaises(ValueError): inventory.verify()

    def test_malformed_mapping_and_extra_cache_cannot_be_adopted(self):
        with self.assertRaises(ValueError): execution.CollectorExecutionInventory.open_installed({})
        inventory = self.open()
        (self.source / '__pycache__').mkdir(mode=0o700)
        with self.assertRaises(ValueError): inventory.verify()
        expected = {n: execution._hash(b) for n, b in inventory.bodies.items()}
        with self.assertRaises(ValueError): execution.CollectorExecutionInventory.open_installed(expected)

    def test_aliases_nested_imports_compile_exact_pins_without_global_hook(self):
        dependency = self.write('orbis-dependency.py', b'VALUE = []\n')
        self.write('orbis-entry.py', b'''import importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location('same_alias', Path(__file__).with_name('orbis-dependency.py'))
child = importlib.util.module_from_spec(spec)
spec.loader.exec_module(child)
VALUE = child.VALUE
''')
        inventory = self.open(); modules = execution._ByteModules(inventory)
        original = importlib.util.spec_from_file_location
        first = modules.load('orbis-entry.py', 'first')
        second = modules.load('orbis-entry.py', 'second')
        self.assertIsNot(first.VALUE, second.VALUE)
        self.assertIs(importlib.util.spec_from_file_location, original)
        self.assertNotIn('same_alias', sys.modules)
        self.assertEqual({v['filename'] for v in modules.executions}, {'orbis-entry.py', dependency.name})
        other = execution._ByteModules(inventory)
        spec = modules._spec('owned', dependency)
        with self.assertRaises(ValueError): other._module(spec)
        with self.assertRaises(ValueError): modules._spec('bad', dependency, loader=object())
        with self.assertRaises(ValueError): modules._spec('bad', self.base / dependency.name)
        with self.assertRaises(ValueError): modules.proxy.import_module('apt')

    def test_valid_timestamp_size_stale_pyc_reproduces_and_byte_loader_never_uses_it(self):
        target = self.write('orbis-dependency.py', b"VALUE = 'stale'\n")
        entry = self.write('orbis-entry.py', b"import importlib.util\nfrom pathlib import Path\ns=importlib.util.spec_from_file_location('nested_stale',Path(__file__).with_name('orbis-dependency.py'))\nm=importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\nVALUE=m.VALUE\n")
        stamp = 1_700_000_000
        os.utime(target, (stamp, stamp))
        py_compile.compile(str(target), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        target.write_bytes(b"VALUE = 'fresh'\n"); target.chmod(0o600); os.utime(target, (stamp, stamp))
        # A real valid legacy cache, not random ignored bytes. -B prevents
        # writing bytecode, but it does not prevent reading this cache.
        with mock.patch.object(sys, 'dont_write_bytecode', True):
            spec = importlib.util.spec_from_file_location('legacy_stale_fixture', entry)
            legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
        self.assertEqual(legacy.VALUE, 'stale')
        # Full installed inventory rejects the extra cache before execution.
        expected = {p.name: execution._hash(p.read_bytes()) for p in self.source.iterdir() if p.is_file()}
        with self.assertRaises(ValueError): execution.CollectorExecutionInventory.open_installed(expected)
        # Pure held-byte loader uses actual pinned bytes. Move cache outside
        # the fixed inventory after proving it valid, retaining it as evidence
        # in this self-cleaning private fixture; do not weaken inventory policy.
        (self.source / '__pycache__').rename(self.base / 'legacy-cache-evidence')
        inventory = self.open(); modules = execution._ByteModules(inventory)
        with mock.patch('importlib.machinery.SourceFileLoader.exec_module', side_effect=AssertionError('pathname loader used')):
            fresh = modules.load(entry.name, 'fresh_fixture')
        self.assertEqual(fresh.VALUE, 'fresh')
        self.assertEqual(next(v['sha256'] for v in modules.executions if v['filename'] == target.name), execution._hash(target.read_bytes()))

    def test_nested_dependency_never_falls_back_to_a_path_loader(self):
        self.write('orbis-dependency.py', b'VALUE = 7\n')
        self.write('orbis-entry.py', b'''from importlib import util
from pathlib import Path
spec = util.spec_from_file_location('nested', Path(__file__).with_name('orbis-dependency.py'))
child = util.module_from_spec(spec)
spec.loader.exec_module(child)
VALUE = child.VALUE
''')
        inventory = self.open(); modules = execution._ByteModules(inventory)
        with mock.patch('importlib.machinery.SourceFileLoader.exec_module', side_effect=AssertionError('pathname loader used')):
            self.assertEqual(modules.load('orbis-entry.py', 'entry').VALUE, 7)
        extra = self.write('orbis-unlisted.py', b'VALUE = 9\n')
        with self.assertRaises(ValueError): modules.load(extra.name, 'unlisted')

    def test_opaque_constructors_and_exact_scope_refuse_claims(self):
        with self.assertRaises(ValueError): execution.CollectorExecutionInventory(object(), self.source, {}, ExitStack())
        with self.assertRaises(ValueError): execution.ExecutionLease(object(), *([None] * 10))
        request = {'operationId': '1' * 64, 'planSha256': '2' * 64, 'phase': 'proposal',
                   'collectionNonce': 'A' * 43, 'origin': 'https://recovery.example'}
        value = execution._scope(self.base, 'local', request, '3' * 64)
        request['operationId'] = '4' * 64
        self.assertEqual(value['request']['operationId'], '1' * 64)
        with self.assertRaises(ValueError): execution._scope(self.base, 'local', {**request, 'verified': True}, '3' * 64)
        with self.assertRaises(ValueError): execution._scope(self.base, 'local', request, True)


# Code-owned protocol fixture. It exercises real subprocess/socket IO; it does
# not pretend to run Host/Docker/PG or mint an execution/admission ticket.
def spawn_wire(test, program, *, deadline=2):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    source = '''import socket,sys,struct,json,time,os
s=socket.socket(fileno=int(sys.argv[1]))
def emit(raw): s.sendall(struct.pack('!I',len(raw))+raw)
''' + program
    process = subprocess.Popen([sys.executable, '-I', '-B', '-c', source, str(child.fileno())],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        pass_fds=(child.fileno(),), close_fds=True, start_new_session=True)
    child.close()
    def cleanup():
        if process.poll() is None: process.kill()
        process.wait(timeout=3); process.stderr.close(); parent.close()
    test.addCleanup(cleanup)
    return execution._Duplex(parent, process, time.monotonic() + deadline), process


def lease_fixture(test, inventory, scope, binding, *, mode='normal', capsule_body=None, reported_pid=None):
    """Actual opaque lease+Popen; proc/seal policy observations are portable seams.

    No Host/PG, publisher, Root process identity or kernel sealing is claimed.
    The observations still read actual process liveness, FD inode/content/pins.
    This helper never exists in production source or grants managed admission.
    """
    if mode not in ('normal', 'wrong-check', 'nonzero-finish', 'trailing-finish'):
        raise ValueError('Unknown code-owned fixture mode')
    wire_binding = {key: binding[key] for key in ('installationId', 'sourceSha256', 'descriptorSha256')}
    wire_binding.update(schema=execution.SCHEMA, phase='captured', request=scope['request'],
        inventorySha256=inventory.inventory_sha256, executionSha256=execution._hash(b'portable-fixture-initial-trace'))
    program = 'binding=' + repr(wire_binding) + '\nmode=' + repr(mode) + """
emit(json.dumps(binding,separators=(',',':')).encode())
for _ in range(5):
    head=b''
    while len(head)<4: head+=s.recv(4-len(head))
    n=struct.unpack('!I',head)[0]
    body=b''
    while len(body)<n: body+=s.recv(n-len(body))
    cmd=json.loads(body)
    phase='checked' if cmd['operation']=='check' else 'finished'
    challenge='B'*43 if mode=='wrong-check' and phase=='checked' else cmd['challenge']
    emit(json.dumps({**binding,'phase':phase,'challenge':challenge},separators=(',',':')).encode())
    if phase=='finished':
        if mode=='trailing-finish': s.sendall(b'X')
        s.close()
        sys.exit(7 if mode=='nonzero-finish' else 0)
"""
    wire, process = spawn_wire(test, program)
    path = inventory.directory.parent / ('portable-capsule-' + str(process.pid))
    path.write_bytes(capsule_body or b'code-owned portable capsule fixture'); path.chmod(0o600)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    capsule_sha = execution._hash(path.read_bytes())
    resources = ExitStack(); resources.callback(os.close, fd); resources.callback(wire.connection.close)
    exe = Path(sys.executable).resolve().stat()
    identity = {'pid': reported_pid or process.pid, 'startTicks': 1, 'executable': [exe.st_dev, exe.st_ino]}
    def process_identity(pid):
        if pid != process.pid or process.poll() is not None:
            raise execution.unavailable()
        return json.loads(json.dumps(identity))
    def capsule_identity(descriptor, expected):
        info = os.fstat(descriptor)
        body = os.pread(descriptor, info.st_size, 0)
        if execution._hash(body) != expected:
            raise execution.unavailable()
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode, info.st_size, expected)
    for name, replacement in (('_process_identity', process_identity), ('_sealed_capsule', capsule_identity)):
        patch = mock.patch.object(execution, name, side_effect=replacement)
        patch.start(); test.addCleanup(patch.stop)
    pin = next(iter(inventory._pins.values()))
    lease = execution.ExecutionLease(execution._KEY, inventory, scope, process, wire, identity, fd,
        capsule_sha, pin, pin, resources)
    inventory._leases.add(lease)
    lease._capsule_identity = capsule_identity(fd, capsule_sha)
    test.addCleanup(lease.abort)
    lease._accept(wire.receive())
    return lease


class OwnedPipeTests(unittest.TestCase):
    def test_actual_duplex_roundtrip_and_terminal_zero(self):
        wire, process = spawn_wire(self, '''emit(b'{"initial":1}')
n=struct.unpack('!I',s.recv(4))[0]
body=b''
while len(body)<n: body+=s.recv(n-len(body))
emit(body)
s.close()
''')
        self.assertEqual(wire.receive(), {'initial': 1})
        wire.send({'challenge': 'roundtrip'})
        self.assertEqual(wire.receive(), {'challenge': 'roundtrip'})
        wire.terminal(); self.assertEqual(process.returncode, 0)

    def test_actual_oversize_partial_duplicate_and_deadline_are_failures(self):
        programs = ["s.sendall(struct.pack('!I',32769));s.close()", "s.sendall(b'\\0');s.close()",
                    "emit(b'{\"x\":1,\"x\":2}');s.close()", 'time.sleep(1)']
        for program in programs:
            with self.subTest(program=program):
                wire, _ = spawn_wire(self, program, deadline=0.1)
                with self.assertRaises(ValueError): wire.receive()

    def test_trailing_nonzero_and_diagnostic_limit_never_mean_complete(self):
        programs = ["emit(b'{\"ok\":1}');s.sendall(b'X');s.close()",
                    "emit(b'{\"ok\":1}');s.close();sys.exit(7)",
                    "emit(b'{\"ok\":1}');os.write(2,b'X'*4097);s.close()"]
        for program in programs:
            with self.subTest(program=program):
                wire, _ = spawn_wire(self, program)
                self.assertEqual(wire.receive(), {'ok': 1})
                with self.assertRaises(ValueError): wire.terminal()

    def test_send_bound_and_unknown_native_claims_are_not_accepted(self):
        wire, _ = spawn_wire(self, 'time.sleep(1)')
        with self.assertRaises(ValueError): wire.send({'large': 'X' * execution.FRAME})
        with self.assertRaises(ValueError): execution._decoded(b'{"a":true,"a":false}')


class AbortCustodyTests(_InventoryFixture):
    def test_bounded_uncertain_stop_retains_actual_pins_until_reconciled(self):
        inventory = self.open()
        wire, process = spawn_wire(self, 'time.sleep(1)')
        resources = ExitStack(); retired = []; resources.callback(retired.append, 'closed')
        lease = execution.ExecutionLease(execution._KEY, inventory, {}, process, wire, None, -1,
            'a' * 64, None, None, resources)
        inventory._leases.add(lease)
        with mock.patch.object(process, 'wait', side_effect=subprocess.TimeoutExpired('owned fixture', 3)):
            with self.assertRaises(execution.UncertainExecution) as error: lease.abort()
        self.assertIs(error.exception.pending, lease)
        self.assertFalse(lease._closed); self.assertEqual(retired, [])
        with self.assertRaises(execution.UncertainExecution): inventory.close()
        lease.abort(); self.assertEqual(retired, ['closed']); inventory.close()

    def test_real_opaque_lease_pipe_checks_terminal_receipt_and_detached_observation(self):
        inventory = self.open()
        request = {'operationId': '1' * 64, 'planSha256': '2' * 64, 'phase': 'proposal',
                   'collectionNonce': 'A' * 43, 'origin': 'https://recovery.example'}
        scope = execution._scope(self.base, 'local', request, '3' * 64)
        binding = {'installationId': '4' * 64, 'sourceSha256': '5' * 64, 'descriptorSha256': '6' * 64}
        lease = lease_fixture(self, inventory, scope, binding)
        lease.require_inventory(inventory)
        observed = lease.observation; observed['request']['operationId'] = 'f' * 64
        observed['process']['executable'][0] = -1
        self.assertEqual(lease.check()['request']['operationId'], '1' * 64)
        with self.assertRaises(execution.ExecutionUnavailable): lease.require_managed_admission()
        receipt = lease.finish()
        self.assertEqual((receipt['phase'], receipt['exitCode']), ('complete', 0))
        self.assertEqual(receipt['authority'], 'inventory-execution-custody-only')
        with self.assertRaises(execution.ExecutionUnavailable): lease.check()
        self.assertFalse(inventory._leases)

    def test_wrong_reply_and_nonzero_or_trailing_finish_keep_hold_without_receipt(self):
        inventory = self.open()
        request = {'operationId': '1' * 64, 'planSha256': '2' * 64, 'phase': 'proposal',
                   'collectionNonce': 'A' * 43, 'origin': 'https://recovery.example'}
        scope = execution._scope(self.base, 'local', request, '3' * 64)
        binding = {'installationId': '4' * 64, 'sourceSha256': '5' * 64, 'descriptorSha256': '6' * 64}
        for mode in ('wrong-check', 'nonzero-finish', 'trailing-finish'):
            with self.subTest(mode=mode):
                lease = lease_fixture(self, inventory, scope, binding, mode=mode)
                with self.assertRaises(ValueError):
                    lease.check() if mode == 'wrong-check' else lease.finish()
                self.assertIn(lease, inventory._leases)
                lease.abort()

    @unittest.skipUnless(sys.platform == 'linux' and os.getuid() == 0, 'Actual Linux Root proc/capsule identity requires separate native qualification')
    def test_actual_linux_root_process_start_identity(self):
        wire, process = spawn_wire(self, 'time.sleep(1)')
        first = execution._process_identity(process.pid)
        self.assertEqual(first['pid'], process.pid)
        self.assertGreater(first['startTicks'], 0)
        self.assertEqual(execution._process_identity(process.pid), first)
        process.kill(); process.wait(timeout=3)
        with self.assertRaises((ValueError, OSError)): execution._process_identity(process.pid)


if __name__ == '__main__':
    unittest.main()
