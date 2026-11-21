"""Persistent ext4 directory identity and the fixed recovery-unit projection.

Mount numbers describe one kernel view and are checked only while descriptors
are held. The durable identity comes from the filesystem UUID and export
handle read from that same descriptor; unsupported storage must reconcile.
"""
import ctypes
from dataclasses import dataclass
import fcntl
import os
from pathlib import Path
import re
import stat
import struct
import sys

from .bootstrap_source import ACTIVATION_BRIDGE, hash_value
from .writer_journal import mount_id


BRIDGE_SCHEMA = 'orbis.credential-storage-bridge.v1'
BRIDGE_DIRECTORY = 'credential-storage-history'
ROLES = ('installation', 'namespace', 'journal', 'recovery')
_EXT4_GET_UUID = 0x8008662C  # _IOR('f', 44, struct fsuuid), Linux x86_64/aarch64.
_AT_EMPTY_PATH = 0x1000
_MAX_MOUNTINFO = 1024 * 1024
_ESCAPES = {b'040': b' ', b'011': b'\t', b'012': b'\n', b'134': b'\\'}
_ESCAPE = re.compile(rb'\\([0-9]{3})')
_HEX16 = re.compile(r'[0-9a-f]{16}\Z')
_HEX32 = re.compile(r'[0-9a-f]{32}\Z')
_RECOVERY_CGROUP = b'0::/system.slice/orbis-sentinel-recovery.service'


class CredentialStorageError(ValueError):
    pass


class UnsupportedCredentialStorage(CredentialStorageError):
    pass


def fail(message='Credential storage requires reconciliation.'):
    raise CredentialStorageError(message)


def _absolute(value):
    if (type(value) is not str or len(os.fsencode(value)) > 4096 or '\x00' in value
            or not value.startswith('/') or value.startswith('//') or os.path.normpath(value) != value):
        fail()
    return Path(value)


def _unescape(value):
    def convert(match):
        if match[1] not in _ESCAPES:
            fail()
        return _ESCAPES[match[1]]
    return os.fsdecode(_ESCAPE.sub(convert, value))


@dataclass(frozen=True)
class MountView:
    mount_id: int
    device: str
    root: Path
    point: Path
    filesystem: str
    line: bytes


def _view(body, path, mounted):
    if not 0 < len(body) <= _MAX_MOUNTINFO or not body.endswith(b'\n'):
        fail()
    points, match = set(), None
    for line in body.split(b'\n')[:-1]:
        prefix, separator, suffix = line.partition(b' - ')
        head, tail = prefix.split(b' '), suffix.split(b' ')
        if not separator or len(head) < 6 or len(tail) != 3 or not head[0].isdigit():
            fail()
        point = _absolute(_unescape(head[4]))
        if not path.is_relative_to(point):
            continue
        if point in points:
            fail('Stacked credential storage mounts require reconciliation.')
        points.add(point)
        if int(head[0]) != mounted:
            continue
        if match is not None or re.fullmatch(rb'[0-9]+:[0-9]+', head[2]) is None:
            fail()
        match = MountView(mounted, head[2].decode('ascii'), _absolute(_unescape(head[3])), point,
                          tail[0].decode('ascii'), line)
    if match is None or any(point.is_relative_to(match.point) and point != match.point for point in points):
        fail()
    return match


def _mount_view(fd, path):
    with open('/proc/self/mountinfo', 'rb') as stream:
        return _view(stream.read(_MAX_MOUNTINFO + 1), path, mount_id(fd))


class _FileHandle(ctypes.Structure):
    _fields_ = [('size', ctypes.c_uint), ('kind', ctypes.c_int), ('data', ctypes.c_ubyte * 128)]


def _ext4_handle(fd, observed_mount):
    call = ctypes.CDLL(None, use_errno=True).name_to_handle_at
    call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(_FileHandle),
                     ctypes.POINTER(ctypes.c_int), ctypes.c_int)
    call.restype = ctypes.c_int
    handle, mounted = _FileHandle(), ctypes.c_int()
    handle.size = len(handle.data)
    if (call(fd, b'', ctypes.byref(handle), ctypes.byref(mounted), _AT_EMPTY_PATH) != 0
            or handle.kind != 1 or handle.size != 8 or mounted.value != observed_mount):
        fail('The ext4 credential directory export handle is unavailable.')
    return bytes(handle.data[:handle.size]).hex()


def _ext4_uuid(fd):
    value = bytearray(struct.pack('=II', 16, 0) + bytes(16))
    fcntl.ioctl(fd, _EXT4_GET_UUID, value, True)
    if struct.unpack_from('=II', value) != (16, 0) or not any(value[8:]):
        fail('The ext4 credential filesystem UUID is unavailable.')
    return value[8:].hex()


def observe(directory):
    """Collect one canonical role with a bounded, live-verified kernel view."""
    if sys.platform != 'linux' or sys.byteorder != 'little' or os.uname().machine not in {'x86_64', 'aarch64'}:
        raise UnsupportedCredentialStorage('Persistent credential storage is unsupported on this platform.')
    path = _absolute(str(directory.path))
    directory.verify()
    info = os.fstat(directory.fd)
    view = _mount_view(directory.fd, path)
    if view.filesystem != 'ext4':
        raise UnsupportedCredentialStorage('Persistent credential storage requires a qualified ext4 filesystem.')
    if view.device != f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}':
        fail()
    try:
        uuid, handle = _ext4_uuid(directory.fd), _ext4_handle(directory.fd, view.mount_id)
    except (OSError, AttributeError):
        raise UnsupportedCredentialStorage('Persistent ext4 credential identity is unavailable.') from None
    stable = {
        'path': str(path),
        'filesystem': 'ext4',
        'uuid': uuid,
        'handle': handle,
        'owner': [info.st_uid, info.st_gid, info.st_mode],
        'filesystemPath': str(view.root / path.relative_to(view.point)),
        'mountPoint': str(view.point),
        'mountRoot': str(view.root),
    }
    directory.verify()
    if _mount_view(directory.fd, path) != view:
        fail()
    return stable


def _role(value):
    fields = {'path', 'filesystem', 'uuid', 'handle', 'owner', 'filesystemPath', 'mountPoint', 'mountRoot'}
    if type(value) is not dict or set(value) != fields or value['filesystem'] != 'ext4':
        fail()
    for key, grammar in (('uuid', _HEX32), ('handle', _HEX16)):
        if type(value[key]) is not str or grammar.fullmatch(value[key]) is None or int(value[key], 16) == 0:
            fail()
    owner = value['owner']
    if (type(owner) is not list or len(owner) != 3
            or any(type(part) is not int or not 0 <= part < 2**32 for part in owner)
            or not stat.S_ISDIR(owner[2])):
        fail()
    path, filesystem_path, point, root = (_absolute(value[name]) for name in (
        'path', 'filesystemPath', 'mountPoint', 'mountRoot'))
    if not path.is_relative_to(point) or filesystem_path != root / path.relative_to(point):
        fail()


def validate_bridge(value, *, installation, context, daemon, previous):
    _validate_bridge(value, BRIDGE_SCHEMA, installation=installation, context=context, daemon=daemon, previous=previous)


def validate_bootstrap_bridge(value, *, installation, context, daemon, previous):
    """Validate the distinct V1 bootstrap shape, without granting floor admission.

    The floor consumer must separately verify the exact published activation and
    archived never-managed predecessor. Ordinary storage upgrades cannot adopt it.
    """
    _validate_bridge(value, ACTIVATION_BRIDGE, installation=installation, context=context, daemon=daemon, previous=previous)


def _validate_bridge(value, schema, *, installation, context, daemon, previous):
    if (type(value) is not dict or set(value) != {'schema', 'installationId', 'context', 'daemon',
            'parentFloorSha256', 'publicationOperation', 'publicationSha256', 'recoveryUnitSha256', 'roles'}
            or value['schema'] != schema or value['installationId'] != installation
            or value['context'] != context or value['daemon'] != daemon or value['parentFloorSha256'] != previous
            or any(not hash_value(value[key]) for key in ('installationId', 'parentFloorSha256',
                       'publicationOperation', 'publicationSha256', 'recoveryUnitSha256'))
            or type(value['roles']) is not dict or set(value['roles']) != set(ROLES)):
        fail()
    for role in ROLES:
        _role(value['roles'][role])


def in_recovery_unit():
    if sys.platform != 'linux':
        return False
    with open('/proc/self/cgroup', 'rb') as stream:
        value = stream.read(16385)
    return len(value) <= 16384 and _RECOVERY_CGROUP in value.splitlines()


def verify_role(role, directory, expected, *, recovery=False):
    _role(expected)
    observed = observe(directory)
    if observed == expected:
        return
    # ReadWritePaths gives this one canonical directory a self-bind inside
    # the pinned recovery unit. It does not permit any other aliased role.
    may_project = recovery and role == 'recovery' and in_recovery_unit()
    if (not may_project or observed['mountPoint'] != expected['path']
            or observed['mountRoot'] != expected['filesystemPath']):
        fail()
    if observed != {**expected, 'mountPoint': expected['path'], 'mountRoot': expected['filesystemPath']}:
        fail()
