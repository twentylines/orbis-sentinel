"""Activate a publisher-verified Sentinel package with a retained rollback path.

The Linux root installer owns this transaction. It never executes recovery jobs,
changes Orbis enrollment, or removes a retained component version.
"""

from __future__ import annotations

from contextlib import closing

import argparse
import fcntl
import hashlib
import grp
import http.client
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid

if __name__ == '__main__':
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))

from stage_release import (_Parent, _manifest, _pairs, _rename_exclusive, _verify_tree,
                           DIRECTORY_FLAGS, MAX_MANIFEST_BYTES, SHA256, VERSION)
from verify_release import COMMIT, verify_release


ROOT = Path('/opt/orbis-sentinel')
STATE = Path('/var/lib/orbis-sentinel')
UNITS = Path('/etc/systemd/system')
SOCKET = Path('/run/orbis-sentinel/api.sock')
SYSTEMCTL = Path('/usr/bin/systemctl')
SYSUSERS = Path('/etc/sysusers.d')
OBSERVER_HASHES = {
    'collector': '0488d814326acad265265c8fcf538fa3afe565ae7e49fc958e726306a58144fa',
    'host': 'fb08ef308356878e33e73cee5dd61d439c7b81bd59648a5318305a38724b5d9d',
    'socket': '5a04369125cadf908e516715b790923a420572d963830f05f6fd7388cfc19f92',
    'sysusers': '9b29a027c32eb3e93b33521b6b0b8de687c33512fd6e9cf711c42cb2366a1792',
}
OBSERVER_PROFILES = {
    'orbis-observer-v1': OBSERVER_HASHES,
    'orbis-observer-v2': {**OBSERVER_HASHES,
        'collector': 'cf886ca0a13c120a587b3aae96b8595210c48b7f3eef036b3853d9e2e333c0b8'},
}
_OBSERVER_UNSET = object()
UNIT_HASHES = {
    'orbis-sentinel.service': '513adea38d6b5f640bf2d827bebec6ec665cbef39d7a7e01e25742fdfce97b06',
    'orbis-sentinel.socket': '6a77a07d0b8ef62507352565d12626e96ab63dceb6131749b893f5093c09054b',
}
PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths',
              'UnitFileState', 'NeedDaemonReload', 'KillMode', 'MainPID', 'ControlPID',
              'ControlGroup', 'InvocationID')
TERMINAL = {'complete', 'rolled-back'}
LIMIT = 2 * 1024 * 1024


class ActivationError(ValueError):
    pass


class RecoveryRequired(ActivationError):
    pass


def _operator():
    if not sys.platform.startswith('linux') or os.getuid() != 0 or os.geteuid() != 0:
        raise ActivationError('Sentinel activation requires a Linux root operator')


def _seal(value):
    return (value.st_dev, value.st_ino, value.st_uid, value.st_gid, value.st_mode,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory(path, mode):
    parent = _Parent(path.parent)
    try:
        created = False
        try:
            os.mkdir(path.name, mode, dir_fd=parent.fd)
            created = True
        except FileExistsError:
            pass
        parent.assert_current()
        if created:
            descriptor = os.open(path.name, DIRECTORY_FLAGS, dir_fd=parent.fd)
            try:
                os.fchmod(descriptor, mode)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        info = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode:
            raise ActivationError('Sentinel installation directory requires independent review')
    finally:
        parent.close()


def _read(parent, name, mode, maximum=LIMIT):
    parent.assert_current()
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent.fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != mode or not 0 < info.st_size <= maximum):
            raise ActivationError('Sentinel managed file has an untrusted identity')
        body = os.read(fd, maximum + 1)
        if (len(body) != info.st_size or _seal(os.fstat(fd)) != _seal(info)
                or _seal(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)) != _seal(info)):
            raise ActivationError('Sentinel managed file changed while being read')
        return body
    finally:
        os.close(fd)


def _write(parent, name, body, mode, previous=None):
    if len(body) > LIMIT or _read(parent, name, mode) != previous:
        raise RecoveryRequired('Sentinel managed file changed before publication')
    temporary = '.sentinel-' + uuid.uuid4().hex
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent.fd)
    identity = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
        parent.assert_current()
        if _read(parent, name, mode) != previous:
            raise RecoveryRequired('Sentinel managed file changed before publication')
        if previous is None:
            _rename_exclusive(parent.fd, temporary, name)
        else:
            os.replace(temporary, name, src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        os.fsync(parent.fd)
    finally:
        try:
            current = os.stat(temporary, dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                os.unlink(temporary, dir_fd=parent.fd)


def _json(body):
    return json.loads(body, object_pairs_hook=_pairs)


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def _retention_binding(value):
    if (type(value) is not dict or set(value) != {'operationId', 'planSha256', 'targetDigest'}
            or type(value['operationId']) is not str
            or type(value['planSha256']) is not str or not SHA256.fullmatch(value['planSha256'])
            or type(value['targetDigest']) is not str or not value['targetDigest'].startswith('sha256:')
            or not SHA256.fullmatch(value['targetDigest'][7:])):
        raise ActivationError('Sentinel retention requires an exact coordinated operation binding')
    try:
        operation = uuid.UUID(value['operationId'])
    except ValueError as error:
        raise ActivationError('Sentinel retention operation is invalid') from error
    if operation.version != 4 or str(operation) != value['operationId']:
        raise ActivationError('Sentinel retention operation is invalid')
    return dict(value)


def _retention_ticket(record, binding):
    value = {'schema': 'orbis-sentinel.upgrade-retention.v1', 'binding': binding,
             'activation': {**record, 'phase': 'prepared'}}
    body = _encoded(value)
    return body, {'schema': 'orbis-sentinel.upgrade-retention-ticket.v1',
                  'activationId': record['id'], 'sha256': hashlib.sha256(body).hexdigest(),
                  'binding': dict(binding)}


def _version_order(version):
    core, separator, suffix = version.partition('-')
    numbers = core.split('.')
    identifiers = suffix.split('.') if separator else []
    if (len(numbers) != 3 or any(not number.isascii() or not number.isdecimal()
            or str(int(number)) != number for number in numbers)
            or any(not item or (item.isdecimal() and str(int(item)) != item) for item in identifiers)):
        raise ActivationError('Sentinel version precedence requires a canonical version')
    prerelease = tuple((0, int(item)) if item.isdecimal() else (1, item) for item in identifiers)
    return (*map(int, numbers), not separator, prerelease)


def _inventory(directory, version):
    parent = _Parent(directory)
    initializer = None
    try:
        initializer = _Parent(directory / 'src' / 'orbis_sentinel')
        manifest = _read(parent, 'release.json', 0o644, MAX_MANIFEST_BYTES)
        if manifest is None:
            raise ActivationError('Sentinel release manifest is unavailable')
        value = _json(manifest)
        if not isinstance(value, dict) or not isinstance(value.get('files'), dict):
            raise ActivationError('Sentinel release manifest is invalid')
        inventory = {**value['files'], 'release.json': {
            'bytes': len(manifest), 'sha256': hashlib.sha256(manifest).hexdigest()}}
        _manifest(inventory, value, _read(initializer, '__init__.py', 0o644), version)
        _verify_tree(parent.fd, inventory, root_mode=0o755)
        parent.assert_current()
        return inventory
    finally:
        if initializer is not None:
            initializer.close()
        parent.close()


def _receipt(value):
    if (not isinstance(value, dict) or set(value) != {'schema', 'version', 'sha256', 'sourceCommit', 'files'}
            or value['schema'] != 'orbis-sentinel.installation.v1'
            or not isinstance(value['version'], str) or len(value['version']) > 128 or not VERSION.fullmatch(value['version'])
            or not isinstance(value['sha256'], str) or not SHA256.fullmatch(value['sha256'])
            or not isinstance(value['sourceCommit'], str) or not COMMIT.fullmatch(value['sourceCommit'])
            or not isinstance(value['files'], dict)):
        raise ActivationError('Sentinel installation receipt is invalid')
    if _inventory(ROOT / 'releases' / value['version'], value['version']) != value['files']:
        raise ActivationError('The retained Sentinel release changed')
    return value


def _selector(parent):
    parent.assert_current()
    try:
        info = os.stat('current', dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
        raise ActivationError('Sentinel current selector requires independent review')
    target = os.readlink('current', dir_fd=parent.fd)
    parts = Path(target).parts
    if len(parts) != 2 or parts[0] != 'releases' or not VERSION.fullmatch(parts[1]) or target != '/'.join(parts):
        raise ActivationError('Sentinel current selector is outside the managed releases')
    return {'target': target, 'seal': _seal(info)}


def _select(parent, target, previous):
    if _selector(parent) != previous:
        raise RecoveryRequired('Sentinel selector changed outside the activation transaction')
    if target is None:
        if previous is not None:
            os.unlink('current', dir_fd=parent.fd)
    else:
        name = '.current-' + uuid.uuid4().hex
        os.symlink(target, name, dir_fd=parent.fd)
        identity = _seal(os.stat(name, dir_fd=parent.fd, follow_symlinks=False))
        try:
            if _selector(parent) != previous:
                raise RecoveryRequired('Sentinel selector changed before publication')
            if previous is None:
                _rename_exclusive(parent.fd, name, 'current')
            else:
                os.replace(name, 'current', src_dir_fd=parent.fd, dst_dir_fd=parent.fd)
        finally:
            try:
                remaining = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if _seal(remaining) != identity:
                    raise RecoveryRequired('Temporary Sentinel selector changed; retained for review')
                os.unlink(name, dir_fd=parent.fd)
    os.fsync(parent.fd)
    current = _selector(parent)
    if (current or {}).get('target') != target:
        raise RecoveryRequired('Sentinel selector publication could not be confirmed')
    return current


class Systemd:
    def run(self, *arguments):
        parent = _Parent(SYSTEMCTL.parent)
        try:
            info = SYSTEMCTL.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o7022 or not info.st_mode & 0o111:
                raise ActivationError('The systemd supervisor is not trusted')
            result = subprocess.run([str(SYSTEMCTL), '--no-pager', '--no-ask-password', *arguments],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=20,
                env={'PATH': os.defpath, 'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'})
            parent.assert_current()
            if _seal(SYSTEMCTL.lstat()) != _seal(info) or result.returncode or len(result.stdout) + len(result.stderr) > 65536:
                raise ActivationError('The systemd supervisor did not confirm the requested state')
            return result.stdout.decode('utf-8')
        finally:
            parent.close()

    def inspect(self, name):
        properties = tuple(key for key in PROPERTIES if key != 'MainPID' or name.endswith('.service'))
        output = self.run('show', name, '--property=' + ','.join(properties))
        pairs = [line.split('=', 1) for line in output.splitlines()]
        if any(len(item) != 2 for item in pairs) or len(pairs) != len(properties):
            raise ActivationError('Systemd unit observation is incomplete')
        value = dict(pairs)
        if set(value) != set(properties):
            raise ActivationError('Systemd unit observation is incomplete')
        return value

    def stop(self):
        _profile(self, True, allow_transition=True)
        self.run('stop', *UNIT_HASHES)
        for name in UNIT_HASHES:
            value = self.inspect(name)
            if (value['ActiveState'] != 'inactive' or value['SubState'] != 'dead'
                    or value.get('MainPID', '0') != '0' or value['ControlPID'] != '0' or value['ControlGroup']):
                raise RecoveryRequired('Systemd could not establish Sentinel quiescence')


def _observer_profile(systemd, installed, drop_ins):
    collector = UNITS / 'orbis-sentinel.service.d' / 'observer.conf'
    with closing(_Parent(STATE)) as state:
        receipt = _read(state, 'observer-profile.json', 0o600, 8192)
    if not collector.parent.exists() and not collector.parent.is_symlink():
        if drop_ins or receipt is not None:
            raise ActivationError('The managed Sentinel observer profile requires review')
        return None
    with closing(_Parent(collector.parent)) as parent:
        entries = set(os.listdir(parent.fd))
        if not entries and not drop_ins and receipt is None:
            return None
        if entries != {collector.name}:
            raise ActivationError('Sentinel has an unreviewed observer drop-in')
    if not installed or drop_ins != str(collector) or receipt is None:
        raise ActivationError('Sentinel observer adoption requires an independently recorded managed profile')
    try:
        selected = _json(receipt)
        name = selected.get('profile') if type(selected) is dict else None
        hashes = OBSERVER_PROFILES.get(name) if type(name) is str else None
    except (ValueError, TypeError):
        hashes = None
    if hashes is None:
        raise ActivationError('The managed observer profile is unsupported')
    paths = {
        'collector': collector,
        'host': UNITS / 'orbis-host.service.d' / 'sentinel-observer.conf',
        'socket': UNITS / 'orbis-host-observer.socket',
        'sysusers': SYSUSERS / 'orbis-sentinel-observer.conf',
    }
    for role, path in paths.items():
        with closing(_Parent(path.parent)) as parent:
            if role == 'host' and set(os.listdir(parent.fd)) != {path.name}:
                raise ActivationError('The Host observer has unreviewed drop-ins')
            body = _read(parent, path.name, 0o644, 4096)
            if body is None or hashlib.sha256(body).hexdigest() != hashes[role]:
                raise ActivationError('The managed observer files changed')
    try:
        group = grp.getgrnam('orbis-observer').gr_gid
    except KeyError as error:
        raise ActivationError('The managed observer group is unavailable') from error
    if type(group) is not int or not 0 < group < 2**31:
        raise ActivationError('The managed observer group is unavailable')
    profile = {'schema': 'orbis-sentinel.observer-profile.v1', 'profile': name,
               'groupId': group, 'files': dict(hashes)}
    if receipt != _encoded(profile):
        raise ActivationError('The managed observer receipt differs from the installed profile')
    for name, fragment, expected_drop_ins in (
            ('orbis-host.service', UNITS / 'orbis-host.service', str(paths['host'])),
            ('orbis-host-observer.socket', paths['socket'], '')):
        loaded = systemd.inspect(name)
        if (loaded['LoadState'] != 'loaded' or loaded['FragmentPath'] != str(fragment)
                or loaded['DropInPaths'] != expected_drop_ins or loaded['NeedDaemonReload'] != 'no'
                or (name.endswith('.service') and loaded['KillMode'] != 'control-group')):
            raise ActivationError('The loaded Host observer profile requires review')
    return profile


def _profile(systemd, installed, *, allow_transition=False):
    observed = {}
    collector_drop_ins = None
    for name in UNIT_HASHES:
        value = systemd.inspect(name)
        if not installed:
            if (value['LoadState'] != 'not-found' or value['FragmentPath'] or value['DropInPaths']
                    or value['ActiveState'] != 'inactive' or value['SubState'] != 'dead'
                    or value.get('MainPID', '0') != '0' or value['ControlPID'] != '0' or value['ControlGroup']):
                raise ActivationError('An unmanaged Sentinel systemd unit already exists')
        elif (value['LoadState'] != 'loaded' or value['FragmentPath'] != str(UNITS / name)
                or value['DropInPaths'] not in ({'', str(UNITS / 'orbis-sentinel.service.d' / 'observer.conf')} if name.endswith('.service') else {''})
                or value['NeedDaemonReload'] != 'no'
                or value['UnitFileState'] not in {'enabled', 'disabled'}
                or value['ActiveState'] not in ({'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'}
                                              if allow_transition else {'active', 'inactive', 'failed'})
                or (name.endswith('.service') and value['KillMode'] != 'control-group')):
            raise ActivationError('The loaded Sentinel profile requires independent review')
        observed[name] = {'active': value['ActiveState'] == 'active', 'enabled': value['UnitFileState'] == 'enabled'}
        if name == 'orbis-sentinel.service':
            collector_drop_ins = value['DropInPaths']
    if (installed and not allow_transition and observed['orbis-sentinel.service']['active']
            and not observed['orbis-sentinel.socket']['active']):
        raise ActivationError('The service and its required socket observations disagree')
    observer = _observer_profile(systemd, installed, collector_drop_ins)
    previous = systemd.__dict__.get('_orbis_observer_profile', _OBSERVER_UNSET)
    if previous is not _OBSERVER_UNSET and previous != observer:
        raise RecoveryRequired('The managed observer identity changed during activation')
    systemd._orbis_observer_profile = observer
    if observer is not None:
        observed['observerProfile'] = observer
    return observed


def _health(version, timeout):
    parent = _Parent(SOCKET.parent)
    try:
        before = SOCKET.lstat()
        if not stat.S_ISSOCK(before.st_mode) or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
            raise ActivationError('Sentinel health socket is not trusted')
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(str(SOCKET))
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.sendall(b'GET /sentinel/api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            wire = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ActivationError('Sentinel health observation timed out')
                connection.settimeout(remaining)
                data = connection.recv(4096)
                if not data:
                    break
                wire.extend(data)
                if len(wire) > 16384:
                    raise ActivationError('Sentinel health response exceeds its bound')
        class ResponseBuffer(io.BytesIO):
            def close(self):
                if not self.closed:
                    self.final_position = self.tell()
                super().close()
        stream = ResponseBuffer(wire)
        response = http.client.HTTPResponse(SimpleNamespace(makefile=lambda *args, **kwargs: stream))
        try:
            response.begin()
            if (len(response.headers.get_all('Content-Length', [])) > 1
                    or ('Content-Length' in response.headers and 'Transfer-Encoding' in response.headers)):
                raise ActivationError('Sentinel health HTTP framing is ambiguous')
            body = response.read()
            consumed = stream.final_position if stream.closed else stream.tell()
            if response.status != 200 or len(body) > 4096 or consumed != len(wire):
                raise ActivationError('Sentinel health response is unavailable')
        finally:
            response.close()
        parent.assert_current()
        value = _json(body)
        if (_seal(SOCKET.lstat()) != _seal(before) or not isinstance(value, dict)
                or type(value.get('protocolVersion')) is not int or value != {
                'schema': 'orbis-sentinel.health.v1', 'state': 'ready', 'version': version, 'protocolVersion': 1}):
            raise ActivationError('The activated Sentinel identity does not match the candidate')
    finally:
        parent.close()


def _ready(systemd, version, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        try:
            _profile(systemd, True)
            before = systemd.inspect('orbis-sentinel.service')
            listening = systemd.inspect('orbis-sentinel.socket')
            if (before['ActiveState'] != 'active' or before['SubState'] != 'running'
                    or not before['MainPID'].isdecimal() or int(before['MainPID']) <= 0
                    or before['ControlPID'] != '0' or not before['ControlGroup']
                    or not before['InvocationID'] or listening['ActiveState'] != 'active'
                    or listening['SubState'] not in {'listening', 'running'}):
                raise ActivationError('Sentinel has not reached its running state')
            _health(version, min(1, max(0.001, deadline - time.monotonic())))
            after = systemd.inspect('orbis-sentinel.service')
            if any(before[key] != after[key] for key in ('MainPID', 'InvocationID', 'ControlGroup', 'ActiveState', 'SubState')):
                raise ActivationError('Sentinel restarted during its health observation')
            _profile(systemd, True)
            return
        except (OSError, ValueError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                raise ActivationError('Sentinel did not confirm a healthy candidate identity')
            time.sleep(0.1)


def activate_release(artifact, bundle, workspace, *, sha256, version, source_commit, verifier, retain=None):
    _operator()
    binding = _retention_binding(retain) if retain is not None else None
    if (not isinstance(version, str) or len(version) > 128 or not VERSION.fullmatch(version)
            or not isinstance(sha256, str) or not SHA256.fullmatch(sha256)
            or not isinstance(source_commit, str) or not COMMIT.fullmatch(source_commit)):
        raise ActivationError('A reviewed Sentinel version, checksum and full source revision are required')
    candidate_order = _version_order(version)
    _directory(ROOT, 0o755)
    _directory(ROOT / 'releases', 0o755)
    _directory(STATE, 0o700)
    parents = []
    lock = None
    try:
        for path in (ROOT, STATE, UNITS):
            parents.append(_Parent(path))
        root, state, units = parents
        lock = os.open('activation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=state.fd)
        identity = os.fstat(lock)
        if not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.geteuid() or identity.st_nlink != 1 or stat.S_IMODE(identity.st_mode) != 0o600:
            raise ActivationError('Sentinel activation lock is not protected')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if _seal(os.stat('activation.lock', dir_fd=state.fd, follow_symlinks=False)) != _seal(identity):
            raise ActivationError('Sentinel activation lock changed')
        current_journal = _read(state, 'activation.json', 0o600)
        prior = None
        if current_journal is not None:
            prior = _json(current_journal)
            if (not isinstance(prior, dict) or prior.get('schema') != 'orbis-sentinel.activation.v1'
                    or prior.get('phase') not in TERMINAL):
                raise RecoveryRequired('An interrupted Sentinel activation requires independent reconciliation')
        installed_bytes = _read(state, 'installed.json', 0o600)
        installed = _receipt(_json(installed_bytes)) if installed_bytes is not None else None
        if installed is not None and candidate_order < _version_order(installed['version']):
            raise ActivationError('The installed Sentinel is newer than the candidate; no downgrade was made')
        if prior is not None:
            if (set(prior) != {'schema', 'id', 'phase', 'candidate', 'previous', 'previousUnits'}
                    or not isinstance(prior['id'], str) or len(prior['id']) != 32
                    or any(character not in '0123456789abcdef' for character in prior['id'])
                    or prior['candidate' if prior['phase'] == 'complete' else 'previous'] != installed
                    or _read(state, 'admission-' + prior['id'] + '.json', 0o600) != _encoded({**prior, 'phase': 'prepared'})):
                raise RecoveryRequired('The previous Sentinel activation identity requires review')
            archive_name = 'result-' + prior['id'] + '.json'
            archived = _read(state, archive_name, 0o600)
            if archived is None:
                _write(state, archive_name, current_journal, 0o600)
            elif archived != current_journal:
                raise RecoveryRequired('The previous Sentinel activation outcome changed')
        previous_selector = _selector(root)
        if (previous_selector or {}).get('target') != ('releases/' + installed['version'] if installed else None):
            raise ActivationError('Sentinel selector and installation receipt disagree')
        unit_bytes = {}
        for name, digest in UNIT_HASHES.items():
            body = _read(units, name, 0o644)
            if (body is None) != (installed is None) or (body is not None and hashlib.sha256(body).hexdigest() != digest):
                raise ActivationError('An unmanaged Sentinel unit file must be preserved for review')
            unit_bytes[name] = body
        systemd = Systemd()
        previous_units = _profile(systemd, installed is not None)
        if binding is not None:
            if (installed is None or not all(previous_units[name]['active'] for name in UNIT_HASHES)):
                raise ActivationError('Coordinated retention requires an existing healthy Sentinel installation')
            _ready(systemd, installed['version'])
        verified = verify_release(artifact, bundle, ROOT / 'releases', workspace,
            sha256=sha256, version=version, source_commit=source_commit, verifier=verifier, reuse_existing=True)
        if verified.get('publisherVerified') is not True or verified.get('activated') is not False:
            raise ActivationError('The candidate lacks verified publisher staging')
        candidate = ROOT / 'releases' / version
        inventory = _inventory(candidate, version)
        candidate_units = {}
        with_units = _Parent(candidate / 'packaging' / 'systemd')
        try:
            for name, digest in UNIT_HASHES.items():
                body = _read(with_units, name, 0o644)
                if body is None or hashlib.sha256(body).hexdigest() != digest:
                    raise ActivationError('The candidate systemd profile requires a reviewed installer update')
                candidate_units[name] = body
        finally:
            with_units.close()
        receipt = {'schema': 'orbis-sentinel.installation.v1', 'version': version, 'sha256': sha256,
                   'sourceCommit': source_commit, 'files': inventory}
        receipt_bytes = _encoded(receipt)
        record = {'schema': 'orbis-sentinel.activation.v1', 'id': uuid.uuid4().hex,
                  'phase': 'prepared', 'candidate': receipt, 'previous': installed,
                  'previousUnits': previous_units}
        journal = current_journal
        def persist(phase):
            nonlocal journal
            record['phase'] = phase
            body = _encoded(record)
            _write(state, 'activation.json', body, 0o600, journal)
            journal = body
        persist('prepared')
        retention = None
        if binding is not None:
            retained_body, retention = _retention_ticket(record, binding)
            _write(state, 'retention-' + record['id'] + '.json', retained_body, 0o600)
        # Keep an immutable admission record even when the current journal advances.
        _write(state, 'admission-' + record['id'] + '.json', journal, 0o600)
        selected = previous_selector
        created = []
        try:
            persist('activating')
            for parent in parents:
                parent.assert_current()
            if _inventory(candidate, version) != inventory:
                raise RecoveryRequired('The verified Sentinel candidate changed')
            for name, body in candidate_units.items():
                if unit_bytes[name] is None:
                    _write(units, name, body, 0o644)
                    created.append(name)
            selected = _select(root, 'releases/' + version, previous_selector)
            systemd.run('daemon-reload')
            systemd.run('enable', *UNIT_HASHES)
            systemd.run('start', 'orbis-sentinel.socket')
            systemd.run('restart', 'orbis-sentinel.service')
            _ready(systemd, version)
            _profile(systemd, True)
            if _selector(root) != selected or _inventory(candidate, version) != inventory:
                raise RecoveryRequired('Sentinel activation identity changed during startup')
            for name, body in candidate_units.items():
                if _read(units, name, 0o644) != body:
                    raise RecoveryRequired('Sentinel unit changed during activation')
            _write(state, 'installed.json', receipt_bytes, 0o600, installed_bytes)
            persist('complete')
            return {**verified, 'activated': True, 'previousVersion': installed['version'] if installed else None,
                    'activationId': record['id'], 'retainedVersionsRemoved': 0,
                    **({'retainedRollback': retention} if retention is not None else {})}
        except BaseException as original:
            try:
                if isinstance(original, RecoveryRequired):
                    raise original
                persist('rolling-back')
                if _selector(root) != selected:
                    raise RecoveryRequired('Sentinel selector changed; automatic rollback is not authorized')
                if installed is not None:
                    _receipt(installed)
                for name, body in candidate_units.items():
                    observed = _read(units, name, 0o644)
                    if observed != (body if name in created or installed else None):
                        raise RecoveryRequired('Sentinel unit changed; automatic rollback is not authorized')
                systemd.stop()
                _select(root, previous_selector['target'] if previous_selector else None, selected)
                for name in UNIT_HASHES:
                    systemd.run('enable' if previous_units[name]['enabled'] else 'disable', name)
                for name in created:
                    if _read(units, name, 0o644) != candidate_units[name]:
                        raise RecoveryRequired('Sentinel unit changed during rollback')
                    os.unlink(name, dir_fd=units.fd)
                os.fsync(units.fd)
                systemd.run('daemon-reload')
                if installed:
                    _receipt(installed)
                    for name in reversed(tuple(UNIT_HASHES)):
                        if previous_units[name]['active']:
                            systemd.run('start', name)
                    if previous_units['orbis-sentinel.service']['active']:
                        _ready(systemd, installed['version'])
                _profile(systemd, installed is not None)
                written = _read(state, 'installed.json', 0o600)
                if written not in (installed_bytes, receipt_bytes):
                    raise RecoveryRequired('Sentinel installation receipt changed during rollback')
                if written != installed_bytes:
                    if installed_bytes is None:
                        os.unlink('installed.json', dir_fd=state.fd)
                        os.fsync(state.fd)
                    else:
                        _write(state, 'installed.json', installed_bytes, 0o600, written)
                persist('rolled-back')
            except BaseException as failure:
                try:
                    persist('recovery-required')
                except (OSError, ValueError):
                    pass
                raise RecoveryRequired('Sentinel activation needs independent reconciliation; retained versions and journal were preserved') from failure
            raise ActivationError('Sentinel activation failed and the previous configuration was restored') from original
    finally:
        if lock is not None:
            os.close(lock)
        for parent in reversed(parents):
            parent.close()


def restore_retained(ticket):
    """Return only the most recently completed, explicitly retained activation.

    This Linux Root API has no version/path/force option. Its ticket identifies
    an immutable admission created by activate_release, not caller observations.
    Uncertain restoration effects require reconciliation instead of replay.
    """
    _operator()
    if (type(ticket) is not dict
            or set(ticket) != {'schema', 'activationId', 'sha256', 'binding'}
            or ticket['schema'] != 'orbis-sentinel.upgrade-retention-ticket.v1'
            or type(ticket['activationId']) is not str or len(ticket['activationId']) != 32
            or any(character not in '0123456789abcdef' for character in ticket['activationId'])
            or type(ticket['sha256']) is not str or not SHA256.fullmatch(ticket['sha256'])):
        raise ActivationError('Sentinel retained activation ticket is invalid')
    binding = _retention_binding(ticket['binding'])
    parents, lock = [], None
    try:
        for path in (ROOT, STATE, UNITS):
            parents.append(_Parent(path))
        root, state, units = parents
        # Share exactly the normal activation lock. Absence is not permission
        # to create a new installation or restore unrecorded runtime bytes.
        lock = os.open('activation.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=state.fd)
        identity = os.fstat(lock)
        if (not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.geteuid()
                or identity.st_nlink != 1 or stat.S_IMODE(identity.st_mode) != 0o600):
            raise ActivationError('Sentinel activation lock is not protected')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if _seal(os.stat('activation.lock', dir_fd=state.fd, follow_symlinks=False)) != _seal(identity):
            raise ActivationError('Sentinel activation lock changed')
        retained = _read(state, 'retention-' + ticket['activationId'] + '.json', 0o600)
        if retained is None or hashlib.sha256(retained).hexdigest() != ticket['sha256']:
            raise RecoveryRequired('The retained Sentinel admission changed or is unavailable')
        value = _json(retained)
        if (type(value) is not dict or set(value) != {'schema', 'binding', 'activation'}
                or value['schema'] != 'orbis-sentinel.upgrade-retention.v1' or value['binding'] != binding):
            raise RecoveryRequired('The retained Sentinel operation differs from its ticket')
        original = value['activation']
        if (type(original) is not dict
                or set(original) != {'schema', 'id', 'phase', 'candidate', 'previous', 'previousUnits'}
                or original['schema'] != 'orbis-sentinel.activation.v1' or original['phase'] != 'prepared'
                or original['id'] != ticket['activationId'] or original['previous'] is None
                or _retention_ticket(original, binding) != (retained, ticket)
                or _read(state, 'admission-' + original['id'] + '.json', 0o600) != _encoded(original)):
            raise RecoveryRequired('The retained Sentinel activation lacks its exact original admission')
        candidate, previous = _receipt(original['candidate']), _receipt(original['previous'])
        desired = original['previousUnits']
        if (type(desired) is not dict or set(desired) not in (set(UNIT_HASHES), {*UNIT_HASHES, 'observerProfile'})
                or any(type(desired[name]) is not dict or set(desired[name]) != {'active', 'enabled'}
                       or any(type(item) is not bool for item in desired[name].values())
                       or not desired[name]['active'] for name in UNIT_HASHES)):
            raise RecoveryRequired('The retained Sentinel unit observations require review')
        for name, digest in UNIT_HASHES.items():
            body = _read(units, name, 0o644)
            if body is None or hashlib.sha256(body).hexdigest() != digest:
                raise RecoveryRequired('Sentinel unit bytes changed before retained restoration')
        systemd = Systemd()
        observed = _profile(systemd, True)
        if observed.get('observerProfile') != desired.get('observerProfile'):
            raise RecoveryRequired('Restore the original managed observer profile before returning Sentinel')
        current = _read(state, 'activation.json', 0o600)
        installed = _read(state, 'installed.json', 0o600)
        selected = _selector(root)
        restoration_name = 'restoration-' + original['id'] + '.json'
        restoration = _read(state, restoration_name, 0o600)
        if restoration is not None:
            saved = _json(restoration)
            if (type(saved) is not dict or set(saved) != {'schema', 'ticket', 'activation'}
                    or saved['schema'] != 'orbis-sentinel.retained-restoration.v1' or saved['ticket'] != ticket):
                raise RecoveryRequired('The Sentinel restoration receipt requires review')
            record = saved['activation']
            if (type(record) is not dict or set(record) != set(original)
                    or type(record.get('id')) is not str or len(record['id']) != 32
                    or any(character not in '0123456789abcdef' for character in record['id'])
                    or record['id'] == original['id']
                    or record != {**original, 'id': record['id'], 'candidate': previous, 'previous': candidate,
                                  'previousUnits': record['previousUnits']}
                    or _read(state, 'admission-' + record['id'] + '.json', 0o600) != _encoded(record)
                    or current != _encoded({**record, 'phase': 'complete'})
                    or installed != _encoded(previous)
                    or (selected or {}).get('target') != 'releases/' + previous['version'] or observed != desired):
                raise RecoveryRequired('An interrupted or superseded Sentinel restoration cannot be replayed')
            _ready(systemd, previous['version'])
            return {'restored': True, 'activationId': record['id'], 'restoredActivationId': original['id'],
                    'version': previous['version'], 'retainedVersionsRemoved': 0}
        if (current != _encoded({**original, 'phase': 'complete'}) or installed != _encoded(candidate)
                or (selected or {}).get('target') != 'releases/' + candidate['version']
                or any(not all(observed[name].values()) for name in UNIT_HASHES)):
            raise RecoveryRequired('Only the current completed retained Sentinel activation can be restored')
        _ready(systemd, candidate['version'])
        result_name = 'result-' + original['id'] + '.json'
        archived = _read(state, result_name, 0o600)
        if archived is None:
            _write(state, result_name, current, 0o600)
        elif archived != current:
            raise RecoveryRequired('The original Sentinel activation outcome changed')
        record = {**original, 'id': uuid.uuid4().hex, 'candidate': previous,
                  'previous': candidate, 'previousUnits': observed}
        _write(state, restoration_name, _encoded({'schema': 'orbis-sentinel.retained-restoration.v1',
                                                'ticket': ticket, 'activation': record}), 0o600)
        journal = current

        def persist(phase):
            nonlocal journal
            record['phase'] = phase
            body = _encoded(record)
            _write(state, 'activation.json', body, 0o600, journal)
            journal = body

        persist('prepared')
        _write(state, 'admission-' + record['id'] + '.json', journal, 0o600)
        try:
            # Durable intent precedes every service/selector effect. A failure
            # here remains visible and never authorizes another stop/select.
            persist('activating')
            for parent in parents:
                parent.assert_current()
            if (_read(state, 'installed.json', 0o600) != installed or _selector(root) != selected
                    or _receipt(candidate) != candidate or _receipt(previous) != previous
                    or _profile(systemd, True) != observed):
                raise RecoveryRequired('Sentinel identity changed before retained restoration')
            systemd.stop()
            selected = _select(root, 'releases/' + previous['version'], selected)
            for name in UNIT_HASHES:
                systemd.run('enable' if desired[name]['enabled'] else 'disable', name)
            systemd.run('daemon-reload')
            for name in reversed(tuple(UNIT_HASHES)):
                systemd.run('start', name)
            _ready(systemd, previous['version'])
            if (_profile(systemd, True) != desired or _selector(root) != selected
                    or _receipt(previous) != previous or _receipt(candidate) != candidate):
                raise RecoveryRequired('Restored Sentinel identity changed during startup')
            for name, digest in UNIT_HASHES.items():
                body = _read(units, name, 0o644)
                if body is None or hashlib.sha256(body).hexdigest() != digest:
                    raise RecoveryRequired('Sentinel units changed during retained restoration')
            _write(state, 'installed.json', _encoded(previous), 0o600, installed)
            persist('complete')
            return {'restored': True, 'activationId': record['id'], 'restoredActivationId': original['id'],
                    'version': previous['version'], 'retainedVersionsRemoved': 0}
        except BaseException as error:
            try:
                persist('recovery-required')
            except (OSError, ValueError):
                pass
            raise RecoveryRequired('Sentinel retained restoration needs reconciliation; no effect may be replayed') from error
    finally:
        if lock is not None:
            os.close(lock)
        for parent in reversed(parents):
            parent.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('artifact', 'bundle', 'workspace', 'verifier'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('sha256', 'version', 'source-commit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    try:
        result = activate_release(args.artifact, args.bundle, args.workspace, sha256=args.sha256,
            version=args.version, source_commit=args.source_commit, verifier=args.verifier)
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, 'Sentinel activation did not complete; inspect the retained activation journal before retrying.\n')
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
