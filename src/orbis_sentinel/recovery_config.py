"""Read-only configuration supplied by the recovery installation supervisor."""

from datetime import datetime
import json
import os
import re
import stat
from types import MappingProxyType
from urllib.parse import urlsplit

_OWNER_UID = 0
_EFFECTIVE_FIELDS = frozenset({
    'LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload',
    'MainPID', 'ControlPID', 'InvocationID', 'KillMode', 'ExecStart', 'User', 'Group',
    'ProtectHome', 'ProtectProc', 'ProtectSystem', 'NoNewPrivileges', 'CapabilityBoundingSet',
})
_EXEC_STATUS = re.compile(
    r'(?P<command>\{ path=[^ ;{}]+ ; argv\[\]=[^;\r\n]+'
    r' ; ignore_errors=no) ; start_time=(?P<start>\[[^\[\]\r\n]{1,64}\])'
    r' ; stop_time=\[n/a\] ; pid=(?P<pid>0|[1-9][0-9]{0,9}) ; code=\(null\) ; status=0/0 \}'
)
_SYSTEMD_TIME = re.compile(
    r'\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([0-9]{4})-([0-9]{2})-([0-9]{2})'
    r' ([0-9]{2}):([0-9]{2}):([0-9]{2}) (?:[A-Za-z][A-Za-z0-9+-]{0,15}|[+-](?:[01][0-9]|2[0-3])(?::?[0-5][0-9])?)\]'
)
_WEEKDAY = ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun')


def builtin_effective_profile(profile, arguments):
    """Canonicalize the two ExecStatus fields cleared by PID 1 on daemon reload."""
    error = 'Invalid effective recovery listener profile.'
    if (type(profile) is not dict or set(profile) != _EFFECTIVE_FIELDS
            or any(type(value) is not str for value in profile.values())
            or not re.fullmatch(r'[1-9][0-9]{0,9}', profile['MainPID'])
            or not re.fullmatch(r'[a-f0-9]{32}', profile['InvocationID'])):
        raise ValueError(error)
    interpreter = arguments[0]
    literal = (interpreter + ' -I ${ORBIS_SENTINEL_RECOVERY_RUNTIME}'
               ' --recovery-profile ${ORBIS_SENTINEL_RECOVERY_PROFILE}')
    prefix = '{ path=' + interpreter + ' ; argv[]='
    expected = {prefix + argv + ' ; ignore_errors=no' for argv in (literal, ' '.join(arguments))}
    report = _EXEC_STATUS.fullmatch(profile['ExecStart'])
    if not report or report['command'] not in expected:
        raise ValueError(error)
    if (report['start'], report['pid']) != ('[n/a]', '0'):
        start = _SYSTEMD_TIME.fullmatch(report['start'])
        if not start or report['pid'] != profile['MainPID']:
            raise ValueError(error)
        weekday, *calendar = start.groups()
        try:
            began = datetime(*(int(part) for part in calendar))
        except ValueError:
            raise ValueError(error) from None
        if weekday != _WEEKDAY[began.weekday()]:
            raise ValueError(error)
    return {**profile, 'ExecStart': report['command'] +
            ' ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }'}


def _seal(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _absolute(value):
    return (type(value) is str and 0 < len(value) <= 4096 and '\0' not in value
            and os.path.isabs(value) and os.path.normpath(value) == value
            and os.path.realpath(value) == value)


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('Duplicate recovery configuration field.')
        value[key] = item
    return value


class RecoveryConfig:
    """Pin the protected configuration; this does not admit mounts or writers.

    Only the installation supervisor may create this file after checking storage,
    independent worker retention and the TLS route. Replacing it requires a new
    service invocation. No browser request can select or update configuration.
    """

    def __init__(self, path):
        self._directories = []
        self._file = None
        self._path = os.fspath(path)
        try:
            if not _absolute(self._path):
                raise ValueError('Recovery configuration must use a canonical path.')
            directory = '/'
            for part in ('', *os.path.dirname(self._path).strip('/').split('/')):
                if part:
                    directory = os.path.join(directory, part)
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                self._directories.append((directory, fd, (info.st_dev, info.st_ino)))
                if info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022:
                    raise ValueError('Recovery configuration directory is not protected.')
            self._file = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            before = os.fstat(self._file)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != _OWNER_UID
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= 16384):
                raise ValueError('Recovery configuration is not a protected regular file.')
            self._identity = _seal(before)
            body = os.read(self._file, 16385)
            if len(body) != before.st_size:
                raise ValueError('Recovery configuration changed while reading.')
            value = json.loads(body, object_pairs_hook=_pairs)
            self._validate(value)
            self.data = MappingProxyType(value)
            self.verify()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _validate(value):
        if (type(value) is not dict or set(value) != {'schema', 'origin', 'directory', 'imageId', 'listenPort', 'statusSocket'}
                or value['schema'] != 'orbis.sentinel-recovery-config.v1'
                or not all(_absolute(value[key]) for key in ('directory', 'statusSocket'))
                or type(value['imageId']) is not str or not re.fullmatch(r'sha256:[a-f0-9]{64}', value['imageId'])
                or type(value['listenPort']) is not int or not 1024 <= value['listenPort'] <= 65535
                or type(value['origin']) is not str or len(value['origin']) > 512):
            raise ValueError('Invalid recovery configuration.')
        origin = urlsplit(value['origin'])
        if (origin.scheme != 'https' or not origin.hostname or origin.username is not None or origin.password is not None
                or origin.path or origin.query or origin.fragment or origin.port == 0
                or any(ord(c) <= 32 or ord(c) == 127 for c in value['origin'])):
            raise ValueError('Installed recovery requires an enrolled HTTPS realm.')

    def verify(self):
        if self._file is None:
            raise ValueError('Recovery configuration is closed.')
        for path, fd, identity in self._directories:
            for info in (os.fstat(fd), os.lstat(path)):
                if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity
                        or info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022):
                    raise ValueError('Recovery configuration directory changed.')
        if self._identity != _seal(os.fstat(self._file)) or self._identity != _seal(os.lstat(self._path)):
            raise ValueError('Recovery configuration changed.')

    def close(self):
        if self._file is not None:
            os.close(self._file)
            self._file = None
        for _, fd, _ in reversed(self._directories):
            os.close(fd)
        self._directories.clear()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
