"""Verify official Host source and retain evidence through the qualified Sentinel launcher."""

import ast
import contextlib
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import sys
import tarfile
import time
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, ProxyHandler, Request, build_opener

from . import recovery_sessions as sessions
from .writer_journal import directory_seal, mount_id, seal

ROOT = Path('/opt/orbis-sentinel')
STATE = Path('/var/lib/orbis-sentinel')
OPERATIONS = STATE / 'source-publication'
HOST_SOURCE = Path('/opt/orbis/host-service')
HOST_UNIT = Path('/etc/systemd/system/orbis-host.service')
HOST_ENV = Path('/etc/orbis/host-service.env')
SITE = 'https://twentylines.github.io/orbis/'
RELEASES = 'https://github.com/twentylines/orbis/releases/download/'
RAW = 'https://raw.githubusercontent.com/twentylines/orbis/'
CDN = 'https://release-assets.githubusercontent.com'
POLICY = 'orbis.official-https-installer.v1'
SCHEMA = 'orbis.host-source-bundle-receipt.v1'
SCHEMA_CUSTODY = 'orbis.host-source-bundle-receipt.v2'
PLAN = 'orbis.host-source-publication-plan.v1'
PLAN_CUSTODY = 'orbis.host-source-publication-plan.v2'
APPROVAL = 'orbis.host-source-publication-approval.v1'
INTENT = 'orbis.host-source-publication-intent.v1'
COMPLETE = 'orbis.host-source-publication-complete.v1'
MAX_FILE = 1024 * 1024
MAX_ARCHIVE = 8 * MAX_FILE
MAX_TAR = 16 * MAX_FILE
MAX_FILES = 128
_SENTINEL_PAYLOAD_FILES = 512
_SENTINEL_MANIFEST_BYTES = 256 * 1024
_PROOF_LIMITS = {'core': 16384, 'launcher': MAX_FILE, 'manifest': 65536, 'archive': MAX_ARCHIVE}
_SELECTION_PROOFS = {'core': 'release-manifest.json', 'launcher': 'installer-source-launcher.py',
                     'manifest': 'orbis-installer-manifest.json', 'archive': 'orbis-installer.tar.gz'}
_CUSTODY_FILES = {'copy-custody.json': 65536, 'installer-source-selection.json': 16384,
                  'installer-source-execution.json': 4096}
_HOST_COPY_FIELDS = ('schema', 'root', 'context', 'selection', 'installed', 'bindings')
_BUNDLE_LIMITS = {'release': {'orbis.installer-bundle.v1': 66, 'orbis.installer-bundle.v3': MAX_FILES,
                              'orbis.installer-bundle.v5': 160},
                  'modular': {'orbis.installer-bundle.v2': 66, 'orbis.installer-bundle.v4': MAX_FILES,
                              'orbis.installer-bundle.v6': 160}}
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_IMAGE_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_COMMIT = re.compile(r'[a-f0-9]{40}\Z')
_ACTIVATION = re.compile(r'[a-f0-9]{32}\Z')
_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z')
_TAG = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(beta|rc)\.(0|[1-9][0-9]*))?\Z')
_MEMBER = re.compile(r'scripts/(?:orbis-[a-z-]+|install-orbis|migration-preflight)\.py'
                     r'|scripts/(?:orbis-host-maintenance-responder|orbis-controller-bootstrap-profile)\.mjs'
                     r'|packaging/systemd/orbis-host\.service')
_SETUP = 'scripts/orbis-host-service-setup.py'
_LAUNCHER = 'scripts/install-orbis.py'
_UNIT = 'packaging/systemd/orbis-host.service'
_REQUIRED = {_SETUP, _LAUNCHER, _UNIT, 'scripts/orbis-host-service.py', 'scripts/orbis-install.py',
             'scripts/orbis-host-service-enable.py', 'scripts/orbis-host-service-upgrade.py'}
_CORE_REQUIRED = {'schema', 'tag', 'commit', 'image', 'digest', 'installationProtocol', 'runtipiCompatibility'}
_CORE_OPTIONAL = {'releaseChannel', 'updatePriority', 'criticalThrough', 'criticalFixes', 'platforms',
                  'dataCompatibility', 'accountIdentifierCompatibility', 'migrationFingerprint'}
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_KEY = object()


class SourcePublicationError(ValueError):
    pass


def fail():
    raise SourcePublicationError('Protected Host source publication requires reconciliation.') from None


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def sha(body):
    return hashlib.sha256(body).hexdigest()


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        fail()


def _json(body):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                fail()
            result[key] = value
        return result

    def invalid(_):
        fail()

    try:
        return json.loads(body.decode('utf-8', 'strict'), object_pairs_hook=pairs,
                          parse_float=invalid, parse_constant=invalid)
    except (ValueError, RecursionError):
        fail()


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _hash(value):
    if not _matches(value, _SHA):
        fail()


def _root():
    if sys.platform != 'linux' or os.getuid() != 0 or os.geteuid() != 0:
        fail()


class _Pins:
    """Keep shared directory FDs, exact files, and selected directory listings."""
    def __init__(self):
        self.directories = {}
        self.files = {}
        self.listings = {}
        self.held_checks = []
        self.closed = False

    def directory(self, path, mode=None, *, protected=True):
        if self.closed or not path.is_absolute() or str(path) != os.path.realpath(path):
            fail()
        chain = (*reversed(path.parents), path) if protected else (path,)
        for current in chain:
            if current in self.directories:
                if protected and not self.directories[current][3]:
                    fail()
                continue
            parent = self.directories.get(current.parent) if protected else None
            fd = os.open(current.name if parent else current, _DIRECTORY, dir_fd=parent[0] if parent else None)
            try:
                info = os.fstat(fd)
                if protected and (info.st_uid not in {0, sessions._OWNER_UID} or info.st_mode & 0o022):
                    fail()
                self.directories[current] = (fd, directory_seal(info), mount_id(fd), protected)
            except BaseException:
                os.close(fd)
                raise
        fd, identity, _, _ = self.directories[path]
        if (protected and identity[2] != sessions._OWNER_UID
                or mode is not None and stat.S_IMODE(identity[4]) != mode):
            fail()
        return fd

    def file(self, path, maximum, mode):
        parent = self.directory(path.parent)
        if path not in self.files:
            fd = os.open(path.name, _FILE, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) != mode or not 0 <= info.st_size <= maximum):
                    fail()
                parts = bytearray()
                while len(parts) <= maximum:
                    chunk = os.read(fd, min(65536, maximum + 1 - len(parts)))
                    if not chunk:
                        break
                    parts.extend(chunk)
                identity, mounted = seal(info), mount_id(fd)
                if len(parts) != info.st_size or seal(os.fstat(fd)) != identity:
                    fail()
                self.files[path] = (fd, identity, mounted, bytes(parts))
            except BaseException:
                os.close(fd)
                raise
        _, identity, _, body = self.files[path]
        if len(body) > maximum or stat.S_IMODE(identity[4]) != mode:
            fail()
        return body

    def children(self, path, mode):
        fd = self.directory(path, mode)
        names = set(os.listdir(fd))
        if self.listings.setdefault(path, names) != names:
            fail()
        return names

    def verify(self):
        if self.closed:
            fail()
        for path, (fd, identity, mounted, _) in self.directories.items():
            if str(path) != os.path.realpath(path):
                fail()
            fresh = os.open(path, _DIRECTORY)
            try:
                if any(directory_seal(os.fstat(probe)) != identity or mount_id(probe) != mounted
                       for probe in (fd, fresh)):
                    fail()
                if path in self.listings and set(os.listdir(fresh)) != self.listings[path]:
                    fail()
            finally:
                os.close(fresh)
        for path, (fd, identity, mounted, _) in self.files.items():
            parent = self.directories[path.parent][0]
            fresh = os.open(path.name, _FILE, dir_fd=parent)
            try:
                if any(seal(os.fstat(probe)) != identity or mount_id(probe) != mounted for probe in (fd, fresh)):
                    fail()
            finally:
                os.close(fresh)
        for check in self.held_checks:
            check()

    def close(self):
        if not self.closed:
            self.closed = True
            for fd, _, _, _ in reversed(tuple(self.files.values())):
                os.close(fd)
            for fd, _, _, _ in reversed(tuple(self.directories.values())):
                os.close(fd)


def _safe_name(name):
    path = PurePosixPath(name)
    if (not name or len(name) > 512 or path.is_absolute() or str(path) != name
            or any(not part or part.startswith('.') for part in name.split('/'))
            or any(ord(c) < 33 or ord(c) > 126 for c in name) or '\\' in name):
        fail()


def _runtime_payload(pins, installation):
    _exact(installation, ('schema', 'version', 'sha256', 'sourceCommit', 'files'))
    version = installation['version']
    if (installation['schema'] != 'orbis-sentinel.installation.v1' or not _matches(version, _VERSION)
            or len(version) > 128 or not _matches(installation['sourceCommit'], _COMMIT)
            or type(installation['files']) is not dict or not 1 <= len(installation['files']) <= _SENTINEL_PAYLOAD_FILES + 1):
        fail()
    _hash(installation['sha256'])
    base = ROOT / 'releases' / version
    files = installation['files']
    required = {'release.json', 'bin/orbis-sentinel', 'src/orbis_sentinel/host_source_publication.py',
                'src/orbis_sentinel/runtime.py', 'src/orbis_sentinel/__init__.py'}
    if not required <= set(files):
        fail()
    total, children = 0, {}
    for name, record in files.items():
        _safe_name(name)
        _exact(record, ('bytes', 'sha256'))
        _hash(record['sha256'])
        size = record['bytes']
        maximum = _SENTINEL_MANIFEST_BYTES if name == 'release.json' else 16 * MAX_FILE
        if type(size) is not int or not 0 <= size <= maximum:
            fail()
        if name != 'release.json':
            total += size
        if total > 64 * MAX_FILE:
            fail()
        path = base / name
        body = pins.file(path, size, 0o755 if name.startswith('bin/') else 0o644)
        if len(body) != size or sha(body) != record['sha256']:
            fail()
        while path != base:
            children.setdefault(path.parent, set()).add(path.name)
            path = path.parent
    for path, expected in children.items():
        if pins.children(path, 0o755) != expected:
            fail()
    release = _json(pins.file(base / 'release.json', _SENTINEL_MANIFEST_BYTES, 0o644))
    _exact(release, ('format', 'component', 'version', 'python', 'files'))
    if (type(release['format']) is not int or release['format'] != 1 or release['component'] != 'orbis-sentinel'
            or release['version'] != version or release['python'] != '>=3.10'
            or release['files'] != {name: record for name, record in files.items() if name != 'release.json'}):
        fail()
    return base


def _running_from(base):
    if (Path(sys.argv[0]) != base / 'bin/orbis-sentinel'
            or Path(__file__) != base / 'src/orbis_sentinel/host_source_publication.py'
            or not sys.flags.isolated or sys.pycache_prefix is not None or not sys.dont_write_bytecode):
        fail()


def _selector(pins, version):
    parent = pins.directory(ROOT, 0o755)

    def observe():
        info = os.stat('current', dir_fd=parent, follow_symlinks=False)
        if (not stat.S_ISLNK(info.st_mode) or info.st_uid != sessions._OWNER_UID
                or os.readlink('current', dir_fd=parent) != 'releases/' + version):
            fail()
        return seal(info)

    identity = observe()

    def check():
        if observe() != identity:
            fail()

    pins.held_checks.append(check)


def _producer(pins, *, recorded=None):
    state_fd = pins.directory(STATE, 0o700)
    if recorded is None:
        installation = _json(pins.file(STATE / 'installed.json', MAX_FILE, 0o600))
        activation_path = STATE / 'activation.json'
    else:
        _exact(recorded, ('activationId', 'installation', 'activationSha256', 'admissionSha256'))
        activation_id = recorded['activationId']
        if not _matches(activation_id, _ACTIVATION):
            fail()
        installation = recorded['installation']
        archive = 'result-' + activation_id + '.json'
        # A later installation may have replaced or removed the current selector/journal.
        activation_path = STATE / (archive if _exists(state_fd, archive) else 'activation.json')
    body = pins.file(activation_path, MAX_FILE, 0o600)
    activation = _json(body)
    _exact(activation, ('schema', 'id', 'phase', 'candidate', 'previous', 'previousUnits'))
    if (activation['schema'] != 'orbis-sentinel.activation.v1' or activation['phase'] != 'complete'
            or not _matches(activation['id'], _ACTIVATION) or activation['candidate'] != installation
            or recorded is not None and activation['id'] != recorded['activationId']):
        fail()
    prepared = pins.file(STATE / ('admission-' + activation['id'] + '.json'), MAX_FILE, 0o600)
    if _json(prepared) != {**activation, 'phase': 'prepared'}:
        fail()
    result = {'activationId': activation['id'], 'installation': installation,
              'activationSha256': sha(body), 'admissionSha256': sha(prepared)}
    if recorded is not None and result != recorded:
        fail()
    base = _runtime_payload(pins, installation)
    if recorded is None:
        _running_from(base)
        _selector(pins, installation['version'])
    pins.verify()
    return result


def _location(url):
    if type(url) is not str or any(ord(character) < 33 or ord(character) > 126 for character in url):
        fail()
    parts = urlsplit(url)
    if (parts.scheme != 'https' or parts.netloc != parts.hostname or parts.fragment
            or parts.hostname not in {'github.com', 'twentylines.github.io', 'raw.githubusercontent.com',
                                      'release-assets.githubusercontent.com'}):
        fail()
    return parts


def _final_origin(locator, target):
    original, final = _location(locator), _location(target)
    if original.query:
        fail()
    bundle = {'orbis-installer-manifest.json', 'orbis-installer.tar.gz'}
    if locator.startswith(RELEASES):
        tag, _, asset = locator[len(RELEASES):].partition('/')
        _tag_order(tag)
        if asset not in bundle | {'release-manifest.json', 'install-orbis.py'}:
            fail()
    elif locator.startswith(SITE + 'installer/'):
        commit, _, asset = locator[len(SITE + 'installer/'):].partition('/')
        if not _matches(commit, _COMMIT) or asset not in bundle:
            fail()
    elif locator.startswith(RAW):
        commit, _, asset = locator[len(RAW):].partition('/')
        if not _matches(commit, _COMMIT) or asset != _LAUNCHER:
            fail()
    else:
        fail()
    if target == locator:
        return 'https://' + original.netloc
    if (locator.startswith(RELEASES) and final.netloc == 'release-assets.githubusercontent.com'
            and re.fullmatch(r'/github-production-release-asset-2e65/[0-9]+/[a-zA-Z0-9-]+', final.path)):
        return CDN
    fail()


class _Redirects(HTTPRedirectHandler):
    def __init__(self, locator):
        self.locator = locator
        self.count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.count += 1
        if self.count > 4:
            fail()
        _final_origin(self.locator, newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _tls():
    # Use the interpreter's platform CA locations without environment overrides.
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile if paths.openssl_cafile and os.path.isfile(paths.openssl_cafile) else None
    capath = paths.openssl_capath if paths.openssl_capath and os.path.isdir(paths.openssl_capath) else None
    if cafile is None and capath is None:
        fail()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile, capath=capath)
    return context


def _fetch(locator, maximum):
    _final_origin(locator, locator)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=_tls()), _Redirects(locator))
    deadline = time.monotonic() + 60
    with opener.open(Request(locator, headers={'User-Agent': 'Orbis-Sentinel-source-verifier/1'}),
                     timeout=15) as response:
        origin = _final_origin(locator, response.geturl())
        if response.status != 200:
            fail()
        body = bytearray()
        while len(body) <= maximum:
            if time.monotonic() > deadline:
                fail()
            chunk = response.read1(min(65536, maximum + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if not 0 < len(body) <= maximum or time.monotonic() > deadline:
            fail()
        return bytes(body), origin


def _literal(body, name):
    try:
        tree = ast.parse(body.decode('utf-8', 'strict'))
        assignments = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                       and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        if len(assignments) != 1:
            fail()
        assignment = assignments[0]
        for node in ast.walk(tree):
            if (isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))
                    and node is not assignment.targets[0]):
                fail()
            if (isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.value, ast.Name)
                    and node.value.id == name and (isinstance(node.ctx, (ast.Store, ast.Del))
                                                   or name == 'SCRIPTS' and isinstance(node, ast.Attribute))):
                fail()
        if isinstance(assignment.value, ast.Dict):
            keys = [key.value for key in assignment.value.keys
                    if isinstance(key, ast.Constant) and type(key.value) is str]
            if len(keys) != len(assignment.value.keys) or len(set(keys)) != len(keys):
                fail()
        return ast.literal_eval(assignment.value)
    except (SyntaxError, ValueError, RecursionError):
        fail()


def _manifest(body, mode, identity):
    value = _json(body)
    fields = {'schema', 'archive', 'archiveBytes', 'archiveSha256', 'files'} | (
        {'tag', 'commit', 'releaseManifestSha256'} if mode == 'release' else {'installerCommit'})
    _exact(value, fields)
    if sha(body) != identity['manifestSha256'] or value['archive'] != 'orbis-installer.tar.gz':
        fail()
    limits = _BUNDLE_LIMITS[mode]
    schema = value['schema']
    if type(schema) is not str or schema not in limits:
        fail()
    if mode == 'release':
        if value['tag'] != identity['tag'] or value['commit'] != identity['commit']:
            fail()
        _hash(value['releaseManifestSha256'])
    elif value['installerCommit'] != identity['commit']:
        fail()
    _hash(value['archiveSha256'])
    if (type(value['archiveBytes']) is not int or not 0 < value['archiveBytes'] <= MAX_ARCHIVE
            or type(value['files']) is not dict or not _REQUIRED <= set(value['files'])
            or not 1 <= len(value['files']) <= limits[schema]):
        fail()
    total = 0
    for name, record in value['files'].items():
        if len(name) > 100 or not _MEMBER.fullmatch(name):
            fail()
        _exact(record, ('size', 'sha256'))
        _hash(record['sha256'])
        if type(record['size']) is not int or not 0 <= record['size'] <= MAX_FILE:
            fail()
        total += record['size']
    if total > MAX_ARCHIVE:
        fail()
    return value


def _archive(body, manifest):
    if len(body) != manifest['archiveBytes'] or sha(body) != manifest['archiveSha256']:
        fail()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as compressed:
            raw = compressed.read(MAX_TAR + 1)
        if len(raw) > MAX_TAR or len(raw) % 512:
            fail()
        result, offset = {}, 0
        zero = bytes(512)
        while offset + 512 <= len(raw) and raw[offset:offset + 512] != zero:
            header = raw[offset:offset + 512]
            # The publisher writes raw USTAR, without GNU/PAX extraction aliases.
            if header[257:265] != b'ustar\0' + b'00' or any(header[345:500]):
                fail()
            info = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            record = manifest['files'].get(info.name)
            if (info.type != tarfile.REGTYPE or info.linkname or info.sparse is not None
                    or not _MEMBER.fullmatch(info.name) or info.name in result or record is None
                    or info.size != record['size']):
                fail()
            start = offset + 512
            end = start + info.size
            offset = start + ((info.size + 511) // 512) * 512
            content = raw[start:end]
            if offset > len(raw) or any(raw[end:offset]) or sha(content) != record['sha256']:
                fail()
            result[info.name] = content
        if len(raw) - offset < 1024 or any(raw[offset:]) or set(result) != set(manifest['files']):
            fail()
        return result
    except (OSError, EOFError, tarfile.TarError, ValueError):
        fail()


def _tag_order(tag):
    if type(tag) is not str or len(tag) > 80 or not (match := _TAG.fullmatch(tag)):
        fail()
    major, minor, patch, stage, iteration = match.groups()
    numbers = tuple(map(int, (major, minor, patch, iteration or '0')))
    if max(numbers) > 9_007_199_254_740_991:
        fail()
    return (*numbers[:3], {'beta': 0, 'rc': 1, None: 2}[stage], numbers[3])


def _core(value):
    if type(value) is not dict or not _CORE_REQUIRED <= set(value) <= _CORE_REQUIRED | _CORE_OPTIONAL:
        fail()
    order = _tag_order(value['tag'])
    channel = 'stable' if order[3] == 2 else 'nightly'
    if (value['schema'] != 'orbis.release.v1' or value['image'] != 'ghcr.io/twentylines/orbis'
            or value['installationProtocol'] != 'orbis.installation-state.v1'
            or value['runtipiCompatibility'] not in ('4.10.1', 'v4.10.1')
            or not _matches(value['commit'], _COMMIT) or not _matches(value['digest'], _IMAGE_DIGEST)):
        fail()
    if (value.get('releaseChannel', channel) != channel or value.get('updatePriority', 'normal') not in ('normal', 'critical')
            or value.get('platforms', ['linux/amd64', 'linux/arm64']) != ['linux/amd64', 'linux/arm64']
            or value.get('dataCompatibility', 'orbis.data.v1') != 'orbis.data.v1'
            or value.get('accountIdentifierCompatibility', 'orbis.account-identifier.v1') != 'orbis.account-identifier.v1'):
        fail()
    if 'migrationFingerprint' in value and not _matches(value['migrationFingerprint'], _IMAGE_DIGEST):
        fail()
    marker = value.get('criticalThrough')
    if marker is not None:
        marker_order = _tag_order(marker)
        if marker_order > order or (channel == 'stable' and marker_order[3] != 2):
            fail()
    fixes = value.get('criticalFixes', [])
    if type(fixes) is not list or len(fixes) > 128:
        fail()
    for fix in fixes:
        _tag_order(fix)
    if len(set(fixes)) != len(fixes):
        fail()


def _exists(fd, name):
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _check_plan(plan, operation):
    fields = ('schema', 'operationId', 'mode', 'installer', 'core', 'root', 'context')
    if type(plan) is dict and plan.get('schema') == PLAN_CUSTODY:
        fields += ('copyCustodySha256',)
    _exact(plan, fields)
    if (plan['schema'] not in (PLAN, PLAN_CUSTODY) or plan['operationId'] != operation
            or plan['mode'] not in ('release', 'modular')
            or type(plan['root']) is not str or not 1 <= len(os.fsencode(plan['root'])) <= 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in plan['root'])
            or type(plan['context']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', plan['context'])):
        fail()
    if plan['schema'] == PLAN_CUSTODY:
        _hash(plan['copyCustodySha256'])
    root = Path(plan['root'])
    if (str(root) != plan['root'] or not root.is_absolute()
            or any(root.is_relative_to(path) or path.is_relative_to(root)
                   for path in (ROOT, STATE, HOST_SOURCE, HOST_UNIT, HOST_ENV))):
        fail()
    _core(plan['core'])
    identity = plan['installer']
    _exact(identity, ('tag', 'commit', 'manifestSha256') if plan['mode'] == 'release' else ('commit', 'manifestSha256'))
    _hash(identity['manifestSha256'])
    if not _matches(identity['commit'], _COMMIT):
        fail()
    if plan['mode'] == 'release' and (identity['tag'] != plan['core']['tag'] or identity['commit'] != plan['core']['commit']):
        fail()


def _plan(pins, operation):
    pins.directory(OPERATIONS, 0o700)
    directory = OPERATIONS / operation
    body = pins.file(directory / 'plan.json', 32768, 0o600)
    plan = _json(body)
    _check_plan(plan, operation)
    approval_body = pins.file(directory / 'approval.json', 4096, 0o600)
    approval = _json(approval_body)
    _exact(approval, ('schema', 'operationId', 'planSha256', 'approvalId'))
    _hash(approval['approvalId'])
    if approval['schema'] != APPROVAL or approval['operationId'] != operation or approval['planSha256'] != sha(body):
        fail()
    return directory, plan, sha(body), sha(approval_body)


def _scripts(files):
    names = _literal(files[_SETUP], 'SCRIPTS')
    if (type(names) is not tuple or not 1 <= len(names) <= MAX_FILES or 'orbis-host-service.py' not in names
            or any(type(name) is not str or 'scripts/' + name not in files for name in names)
            or len(set(names)) != len(names)):
        fail()
    return {name: sha(files['scripts/' + name]) for name in names}


def _identity(pin):
    # Mount IDs identify a held mount in this namespace. They need not be the
    # same when the same installation is opened by an offline service process.
    return list(pin[1])


def _installed_copy(pins, plan):
    root = Path(plan['root'])
    pins.directory(root, protected=False)
    names = pins.children(HOST_SOURCE, 0o700)
    if ('orbis-host-service.py' not in names or len(names) > MAX_FILES
            or any(not _MEMBER.fullmatch('scripts/' + name) for name in names)):
        fail()
    inventory, identities, total = {}, {}, 0
    for name in sorted(names):
        path = HOST_SOURCE / name
        body = pins.file(path, MAX_FILE, 0o600)
        total += len(body)
        if total > MAX_ARCHIVE:
            fail()
        identities[name] = _identity(pins.files[path])
        inventory[name] = sha(body)
    unit = pins.file(HOST_UNIT, 32768, 0o644)
    environment = pins.file(HOST_ENV, 16384, 0o600)

    def quoted(value):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

    expected = (f'ORBIS_SERVICE_SOURCE={quoted(str(HOST_SOURCE / "orbis-host-service.py"))}\n'
                f'ORBIS_ROOT={quoted(plan["root"])}\n'
                f'ORBIS_DOCKER_CONTEXT={quoted(plan["context"])}\n').encode()
    root_pin = pins.directories[root]
    if environment != expected or any(pin[1][:2] == root_pin[1][:2] and pin[3]
                                      for pin in pins.directories.values()):
        fail()
    pins.verify()
    return {'root': plan['root'], 'context': plan['context'], 'installationRoot': _identity(root_pin),
            'sourceDirectory': _identity(pins.directories[HOST_SOURCE]), 'fileIdentities': identities,
            'unit': _identity(pins.files[HOST_UNIT]), 'environment': _identity(pins.files[HOST_ENV]),
            'inventory': inventory, 'inventorySha256': sha(encoded(inventory)),
            'unitSha256': sha(unit), 'environmentSha256': sha(environment)}


def _locators(plan):
    identity = plan['installer']
    release = RELEASES + plan['core']['tag'] + '/'
    if plan['mode'] == 'release':
        base, launcher = release, release + 'install-orbis.py'
    else:
        base = SITE + 'installer/' + identity['commit'] + '/'
        launcher = RAW + identity['commit'] + '/scripts/install-orbis.py'
    return {'core': release + 'release-manifest.json', 'launcher': launcher,
            'manifest': base + 'orbis-installer-manifest.json', 'archive': base + 'orbis-installer.tar.gz'}


def _check_origin(locator, origin):
    if origin != _final_origin(locator, locator) and (not locator.startswith(RELEASES) or origin != CDN):
        fail()


def _check_proofs(plan, proofs, *, selected=False):
    mode, identity = plan['mode'], plan['installer']
    core = _json(proofs['core'])
    _core(core)
    if core != plan['core']:
        fail()
    manifest = _manifest(proofs['manifest'], mode, identity)
    files = _archive(proofs['archive'], manifest)
    template, launcher = files[_LAUNCHER], proofs['launcher']
    if _literal(template, 'EXPECTED_RELEASE') is not None:
        fail()
    if mode == 'release':
        ordered_identity = {name: identity[name] for name in ('tag', 'commit', 'manifestSha256')}
        marker = b'EXPECTED_RELEASE = None'
        if (template.count(marker) != 1 or _literal(launcher, 'EXPECTED_RELEASE') != identity
                or launcher != template.replace(marker, ('EXPECTED_RELEASE = ' + repr(ordered_identity)).encode())
                or sha(proofs['core']) != manifest['releaseManifestSha256']):
            fail()
    else:
        expected = _render_custody_launcher(mode, identity, template) if selected else template
        if launcher != expected or _literal(template, 'INSTALLER') is not None:
            fail()
    return manifest, files


def _render_custody_launcher(mode, identity, template):
    capability = _literal(template, 'INSTALLER_SOURCE_CUSTODY')
    if type(capability) is not int or capability != 1:
        fail()
    variable = 'EXPECTED_RELEASE' if mode == 'release' else 'INSTALLER'
    marker = (variable + ' = None').encode()
    fields = ('tag', 'commit', 'manifestSha256') if mode == 'release' else ('commit', 'manifestSha256')
    if template.count(marker) != 1 or _literal(template, variable) is not None:
        fail()
    return template.replace(marker, (variable + ' = ' + repr({key: identity[key] for key in fields})).encode())


def _check_custody(plan, bodies, copied, proofs, files):
    copy_body = bodies['copy-custody.json']
    copy_custody = _json(copy_body)
    _exact(copy_custody, _HOST_COPY_FIELDS)
    bound_copy = {key: copied[key] for key in ('inventory', 'unitSha256', 'environmentSha256')}
    bindings = {key: copied[key] for key in ('fileIdentities', 'sourceDirectory', 'unit', 'environment')}
    if (sha(copy_body) != plan['copyCustodySha256'] or copy_custody['schema'] != 'orbis.host-copy-custody.v1'
            or copy_custody['root'] != plan['root'] or copy_custody['context'] != plan['context']
            or copy_custody['installed'] != bound_copy or copy_custody['bindings'] != bindings):
        fail()
    claim = copy_custody['selection']
    _exact(claim, ('directory', 'selectionSha256', 'executionSha256', 'mode', 'installer', 'coreSha256'))
    selection_body = bodies['installer-source-selection.json']
    execution_body = bodies['installer-source-execution.json']
    selection = _json(selection_body)
    _exact(selection, ('schema', 'mode', 'installer', 'channel', 'proofs'))
    if (claim['selectionSha256'] != sha(selection_body) or claim['executionSha256'] != sha(execution_body)
            or claim['mode'] != plan['mode'] or claim['installer'] != plan['installer']
            or claim['coreSha256'] != sha(proofs['core'])
            or selection['schema'] != 'orbis.installer-source-selection.v1' or selection['mode'] != plan['mode']
            or selection['installer'] != plan['installer'] or selection['channel'] not in ('stable', 'nightly')):
        fail()
    rendered = _render_custody_launcher(plan['mode'], plan['installer'], files[_LAUNCHER])
    if plan['mode'] == 'release' and rendered != proofs['launcher']:
        fail()
    selected = {**proofs, 'launcher': rendered}
    expected = {name: {'bytes': len(selected[key]), 'sha256': sha(selected[key])}
                for key, name in _SELECTION_PROOFS.items()}
    if (selection['proofs'] != expected or _json(execution_body) != {
            'schema': 'orbis.installer-source-execution.v1', 'selectionSha256': sha(selection_body),
            'launcherSha256': sha(rendered), 'channel': selection['channel']}):
        fail()


def _retained_custody(pins, directory, plan, copied, proofs, files):
    if plan['schema'] == PLAN_CUSTODY:
        bodies = {name: pins.file(directory / name, limit, 0o600) for name, limit in _CUSTODY_FILES.items()}
        _check_custody(plan, bodies, copied, proofs, files)


def _download(plan):
    proofs, records = {}, {}
    for name, locator in _locators(plan).items():
        maximum = _PROOF_LIMITS[name]
        if name == 'archive':
            maximum = _manifest(proofs['manifest'], plan['mode'], plan['installer'])['archiveBytes']
        body, origin = _fetch(locator, maximum)
        _check_origin(locator, origin)
        if not 0 < len(body) <= maximum:
            fail()
        proofs[name] = body
        records[name] = {'locator': locator, 'origin': origin, 'bytes': len(body), 'sha256': sha(body)}
    return proofs, records


def _write_exact(pins, directory, name, body):
    fd = pins.directory(directory, 0o700)
    pins.verify()
    if _exists(fd, name):
        if pins.file(directory / name, len(body), 0o600) != body:
            fail()
        os.fsync(pins.files[directory / name][0])
        os.fsync(fd)
        return
    prefix = '.' + name + '.'
    pending = prefix + sha(body) + '.pending'
    with os.scandir(fd) as entries:
        if any(entry.name.startswith(prefix) and entry.name.endswith('.pending') and entry.name != pending
               for entry in entries):
            fail()
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(pending, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
    except FileExistsError:
        descriptor = os.open(pending, flags, dir_fd=fd)
    else:
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            os.fsync(fd)
        except BaseException:
            os.close(descriptor)
            raise
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > len(body)
                or seal(os.stat(pending, dir_fd=fd, follow_symlinks=False)) != seal(info)
                or mount_id(descriptor) != pins.directories[directory][2]):
            fail()
        offset = 0
        while offset < info.st_size:
            chunk = os.read(descriptor, min(65536, info.st_size - offset))
            if not chunk or chunk != body[offset:offset + len(chunk)]:
                fail()
            offset += len(chunk)
        if seal(os.fstat(descriptor)) != seal(info):
            fail()
        while offset < len(body):
            count = os.write(descriptor, memoryview(body)[offset:])
            if count <= 0:
                fail()
            offset += count
        os.fsync(descriptor)
        pins.verify()
        if (_exists(fd, name) or seal(os.stat(pending, dir_fd=fd, follow_symlinks=False)) != seal(os.fstat(descriptor))
                or mount_id(descriptor) != pins.directories[directory][2]):
            fail()
        os.rename(pending, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
        if pins.file(directory / name, len(body), 0o600) != body:
            fail()
    finally:
        os.close(descriptor)


def _intent(operation, plan_sha, approval_sha, producer, copied):
    return {'schema': INTENT, 'operationId': operation, 'planSha256': plan_sha,
            'approvalSha256': approval_sha, 'producer': producer, 'policy': POLICY,
            'copySha256': sha(encoded(copied))}


def _completion(intent, digest):
    return {'schema': COMPLETE, 'operationId': intent['operationId'], 'planSha256': intent['planSha256'],
            'receiptSha256': digest}


def _receipt(intent, plan, copied, manifest, records):
    receipt = {**intent, 'schema': SCHEMA, 'mode': plan['mode'], 'installer': plan['installer'],
            'associatedCore': plan['core'], 'copy': copied, 'manifest': manifest, 'proofs': records,
            'launcherKind': 'release-launcher' if plan['mode'] == 'release' else 'committed-template'}
    if plan['schema'] == PLAN_CUSTODY:
        receipt.update(schema=SCHEMA_CUSTODY, copyCustodySha256=plan['copyCustodySha256'])
    return receipt


def _check_copy(copied, files):
    if copied['inventory'] != _scripts(files) or copied['unitSha256'] != sha(files[_UNIT]):
        fail()


class PublishedSourceEvidence:
    """Process-local publisher evidence bound to retained files and, offline, a live floor."""
    def __init__(self, key, pins, receipt, receipt_sha256):
        if key is not _KEY:
            fail()
        self._pins, self._receipt, self._receipt_sha256 = pins, receipt, receipt_sha256
        self._pid, self._closed = os.getpid(), False

    @property
    def observation(self):
        self.recheck()
        return _json(encoded(self._receipt))

    @property
    def receipt_sha256(self):
        self.recheck()
        return self._receipt_sha256

    def recheck(self):
        if self._closed or self._pid != os.getpid():
            fail()
        self._pins.verify()

    def require_managed_admission(self):
        raise SourcePublicationError('Publisher evidence does not authorize managed admission or startup.')

    def close(self):
        if not self._closed:
            self._closed = True
            self._pins.close()

    def __enter__(self):
        try:
            self.recheck()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()


def _locked_operation(pins, operation, lock):
    _hash(operation)
    fd = pins.directory(OPERATIONS / operation, 0o700)
    fcntl.flock(fd, lock | fcntl.LOCK_NB)
    return fd


def _activation_lock(pins):
    pins.directory(STATE, 0o700)
    path = STATE / 'activation.lock'
    pins.file(path, 0, 0o600)
    fd = pins.files[path][0]
    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
    pins.verify()
    return fd


def review_copy(operation, selection_directory, copy_sha256):
    """Stage the exact plan for independent Root review and later verification."""
    _root()
    _hash(operation)
    _hash(copy_sha256)
    with contextlib.closing(_Pins()) as pins:
        _activation_lock(pins)
        _producer(pins)
        if not selection_directory.is_absolute():
            fail()
        pins.directory(selection_directory, 0o700)
        copies = selection_directory / 'host-copy-custody'
        pins.directory(copies, 0o700)
        paths = {name: selection_directory / name for name in _CUSTODY_FILES}
        paths['copy-custody.json'] = copies / f'host-copy-{copy_sha256}.json'
        bodies = {name: pins.file(paths[name], maximum, 0o600) for name, maximum in _CUSTODY_FILES.items()}
        copy_custody = _json(bodies['copy-custody.json'])
        _exact(copy_custody, _HOST_COPY_FIELDS)
        claim = copy_custody['selection']
        _exact(claim, ('directory', 'selectionSha256', 'executionSha256', 'mode', 'installer', 'coreSha256'))
        if claim['directory'] != str(selection_directory):
            fail()
        proofs = {key: pins.file(selection_directory / name, _PROOF_LIMITS[key], 0o600)
                  for key, name in _SELECTION_PROOFS.items()}
        plan = {'schema': PLAN_CUSTODY, 'operationId': operation, 'mode': claim['mode'],
                'installer': claim['installer'], 'core': _json(proofs['core']), 'root': copy_custody['root'],
                'context': copy_custody['context'], 'copyCustodySha256': copy_sha256}
        _check_plan(plan, operation)
        _, files = _check_proofs(plan, proofs, selected=True)
        copied = _installed_copy(pins, plan)
        _check_copy(copied, files)
        _check_custody(plan, bodies, copied, proofs, files)
        state_fd = pins.directory(STATE, 0o700)
        try:
            os.mkdir(OPERATIONS.name, 0o700, dir_fd=state_fd)
            os.fsync(state_fd)
        except FileExistsError:
            pass
        base = pins.directory(OPERATIONS, 0o700)
        try:
            os.mkdir(operation, 0o700, dir_fd=base)
            os.fsync(base)
        except FileExistsError:
            pass
        fd = _locked_operation(pins, operation, fcntl.LOCK_EX)
        directory = OPERATIONS / operation
        body = encoded(plan)
        if _exists(fd, 'plan.json'):
            if pins.file(directory / 'plan.json', 32768, 0o600) != body:
                fail()
        elif any(_exists(fd, name) for name in ('approval.json', 'intent.json', 'complete.json', 'receipt.json')):
            fail()
        for name, proof in bodies.items():
            _write_exact(pins, directory, name, proof)
        _write_exact(pins, directory, 'plan.json', body)
        return {'schema': PLAN_CUSTODY, 'operationId': operation, 'planSha256': sha(body), 'phase': 'review-required'}


def verify_operation(operation):
    """Independently verify official bytes from an already qualified Sentinel installation."""
    _hash(operation)
    _root()
    pins = _Pins()
    try:
        activation_fd = _activation_lock(pins)
        operation_fd = _locked_operation(pins, operation, fcntl.LOCK_EX)
        producer = _producer(pins)
        directory, plan, plan_sha, approval_sha = _plan(pins, operation)
        if _exists(operation_fd, 'complete.json'):
            evidence = _read(pins, directory, plan, plan_sha, approval_sha)
        else:
            copied = _installed_copy(pins, plan)
            intent = _intent(operation, plan_sha, approval_sha, producer, copied)
            _write_exact(pins, directory, 'intent.json', encoded(intent))
            proofs, records = _download(plan)
            manifest, files = _check_proofs(plan, proofs)
            _check_copy(copied, files)
            _retained_custody(pins, directory, plan, copied, proofs, files)
            for name, body in proofs.items():
                _write_exact(pins, directory, 'proof-' + name + '.bin', body)
            receipt = _receipt(intent, plan, copied, manifest, records)
            body = encoded(receipt)
            result = sha(body)
            _write_exact(pins, directory, 'receipt.json', body)
            _write_exact(pins, directory, 'complete.json', encoded(_completion(intent, result)))
            pins.verify()
            evidence = PublishedSourceEvidence(_KEY, pins, receipt, result)
        fcntl.flock(operation_fd, fcntl.LOCK_UN)
        fcntl.flock(activation_fd, fcntl.LOCK_UN)
        return evidence
    except BaseException:
        pins.close()
        raise


def _read(pins, directory, plan, plan_sha, approval_sha):
    complete = _json(pins.file(directory / 'complete.json', 4096, 0o600))
    body = pins.file(directory / 'receipt.json', MAX_FILE, 0o600)
    receipt = _json(body)
    fields = ('schema', 'operationId', 'planSha256', 'approvalSha256', 'producer', 'policy', 'copySha256',
              'mode', 'installer', 'associatedCore', 'copy', 'manifest', 'proofs', 'launcherKind')
    _exact(receipt, fields + ('copyCustodySha256',) if plan['schema'] == PLAN_CUSTODY else fields)
    copied = _installed_copy(pins, plan)
    intent = _intent(plan['operationId'], plan_sha, approval_sha, receipt['producer'], copied)
    result = sha(body)
    if (complete != _completion(intent, result)
            or pins.file(directory / 'intent.json', MAX_FILE, 0o600) != encoded(intent)):
        fail()
    _producer(pins, recorded=receipt['producer'])
    proofs, records = {}, receipt['proofs']
    locators = _locators(plan)
    _exact(records, locators)
    for name, locator in locators.items():
        record = records[name]
        _exact(record, ('locator', 'origin', 'bytes', 'sha256'))
        _hash(record['sha256'])
        if record['locator'] != locator or type(record['bytes']) is not int or not 0 < record['bytes'] <= _PROOF_LIMITS[name]:
            fail()
        _check_origin(locator, record['origin'])
        proof = pins.file(directory / ('proof-' + name + '.bin'), record['bytes'], 0o600)
        if len(proof) != record['bytes'] or sha(proof) != record['sha256']:
            fail()
        proofs[name] = proof
    manifest, files = _check_proofs(plan, proofs)
    _check_copy(copied, files)
    _retained_custody(pins, directory, plan, copied, proofs, files)
    if body != encoded(_receipt(intent, plan, copied, manifest, records)):
        fail()
    pins.verify()
    return PublishedSourceEvidence(_KEY, pins, receipt, result)


def _check_floor_publication(evidence, root, context, current, *, root_identity=None):
    receipt = evidence.observation
    copied = receipt['copy']
    # Host's enrolled/current-manifest reader normalizes either retained or
    # ordinary controller identity with its corresponding local version.
    core = receipt['associatedCore']
    retained = {name: core[name] for name in _CORE_REQUIRED}
    ordinary = {name: retained[name] for name in retained if name != 'installationProtocol'}
    ordinary['runtipiCompatibility'] = ordinary['runtipiCompatibility'].removeprefix('v')
    publication_hashes = {sha(encoded(ordinary)), sha(encoded(retained))}
    if (str(root) != copied['root'] or context != copied['context']
            or current['host'] != {key: copied[key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')}
            or current['main']['publicationSha256'] not in publication_hashes
            or root_identity is not None and copied['installationRoot'] != list(root_identity)):
        fail()


def _bind_floor(pins, evidence, floor):
    from .credential_floor import FloorSnapshot

    if type(floor) is not FloorSnapshot or floor.report.classification != 'record-consistent' or floor._value is None:
        fail()
    _check_floor_publication(evidence, floor._reader.root, floor._reader.context, floor._value['current'])
    pins.held_checks.append(floor.recheck)
    evidence.recheck()


def _completed(operation, bind):
    _root()
    pins = _Pins()
    try:
        fd = _locked_operation(pins, operation, fcntl.LOCK_SH)
        directory, plan, plan_sha, approval_sha = _plan(pins, operation)
        evidence = _read(pins, directory, plan, plan_sha, approval_sha)
        bind(pins, evidence)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return evidence
    except BaseException:
        pins.close()
        raise


def read_completed(operation, *, floor_snapshot):
    """Read completed evidence offline against the currently held credential floor."""
    return _completed(operation, lambda pins, evidence: _bind_floor(pins, evidence, floor_snapshot))


def read_completed_for_storage_upgrade(operation, *, root, context, current, root_identity, receipt_sha256):
    """Re-open exact completed publisher evidence for a protected storage intent.

    This has no current-admission authority. The storage consumer revalidates
    the exact predecessor, successor and actual held kernel identities separately.
    """
    def bind(_, evidence):
        _check_floor_publication(evidence, root, context, current, root_identity=root_identity)
        if evidence.receipt_sha256 != receipt_sha256:
            fail()
    return _completed(operation, bind)


def read_completed_for_bootstrap_review(operation, *, root, context, current, root_identity, receipt_sha256):
    """Hold an exact B copy receipt against the visible installed Main and Host."""
    _hash(receipt_sha256)

    def bind(_, evidence):
        if evidence.receipt_sha256 != receipt_sha256 or evidence.observation['schema'] != SCHEMA_CUSTODY:
            fail()
        _check_floor_publication(evidence, root, context, current, root_identity=root_identity)

    return _completed(operation, bind)


def main(operation):
    try:
        with verify_operation(operation) as evidence:
            print(json.dumps({'schema': evidence.observation['schema'], 'operationId': operation,
                              'receiptSha256': evidence.receipt_sha256,
                              'phase': 'publisher-evidence-complete'}))
        return 0
    except (OSError, ValueError, RuntimeError, EOFError):
        print('Host source publication verification did not complete; retain its private operation.', file=sys.stderr)
        return 1


def review(operation, selection_directory, copy_sha256):
    try:
        print(json.dumps(review_copy(operation, Path(selection_directory), copy_sha256)))
        return 0
    except (OSError, ValueError, RuntimeError, EOFError):
        print('Host source review plan did not complete; retain its private operation.', file=sys.stderr)
        return 1
