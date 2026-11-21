"""Retained Root plan and immutable TLS generations for the recovery edge."""

from contextlib import closing, contextmanager
from ipaddress import IPv4Address
import fcntl
import grp
import os
from pathlib import Path
import pwd
import re
import socket
import ssl
import stat
import subprocess
import time
from urllib.parse import urlsplit

from . import host_source_publication as publisher
from .bootstrap_source import PrivateDirectory, decode, digest, encoded, fail, hash_value
from .credential_floor import _InstallationDirectory
from .recovery_https_edge import BACKEND_FILES, PRINCIPAL, _deadline, dynamic_identity, profile, server_context
from .recovery_listener_install import _canonical, _make_protected_directory, _new_file, _read_fixed
from .recovery_worker_provision import _read, _subdirectory
from .writer_journal import seal

STATE = publisher.STATE / 'recovery-https'
UNIT_ROOT = Path('/etc/systemd/system')
ENV = Path('/etc/orbis-sentinel/recovery-https.env')
SSL_TOOL = '/usr/bin/openssl'
SYSTEMCTL = '/usr/bin/systemctl'
UNIT = 'orbis-sentinel-recovery-https'
SERVICE, SOCKET = UNIT + '.service', UNIT + '.socket'
REQUEST = 'orbis.sentinel-recovery-https-request.v1'
REVIEW = 'orbis.sentinel-recovery-https-review.v1'
APPROVAL = 'orbis.sentinel-recovery-https-approval.v1'
RESULT = 'orbis.sentinel-recovery-https-receipt.v1'
ATTACHMENT = 'backend-attachment.json'
ATTACHMENTS = 'backend-attachments'
ATTACH_SCHEMA = 'orbis.sentinel-recovery-https-attachment.v1'
ATTACH_DROPIN = '90-recovery-backend.conf'
MAX_CHAIN = 16384
MAX_KEY = 16384
CERT = re.compile(rb'-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?')
CONTROL_ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}


def _command(program, *args, value=None, maximum=65536, allowed=(0,)):
    result = subprocess.run([program, *args], input=value or b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=CONTROL_ENV, timeout=12, check=False)
    if result.returncode not in allowed or len(result.stdout) > maximum or len(result.stderr) > 8192:
        fail()
    return result.stdout


def _ssl(*args, value=None):
    return _command(SSL_TOOL, *args, value=value)


def _certificates(body):
    parts = []
    unused = body.strip()
    while unused and len(parts) < 8:
        found = CERT.match(unused)
        if found is None:
            fail()
        part = found[0].rstrip() + b'\n'
        ssl.PEM_cert_to_DER_cert(part.decode('ascii'))
        parts.append(part)
        unused = unused[found.end():].lstrip()
    if unused or not parts:
        fail()
    return parts


def _certificate_sha(body):
    return digest(ssl.PEM_cert_to_DER_cert(_certificates(body)[0].decode('ascii')))


def _component(directory, name, produce, *, maximum=MAX_CHAIN):
    """Reuse only this generation's complete or exact staged file."""
    with closing(publisher._Pins()) as pins:
        final, pending = directory.path / name, directory.path / ('.' + name + '.pending')
        current = _read_fixed(pins, final, 0o600, optional=True, maximum=maximum)
        staged = _read_fixed(pins, pending, 0o600, optional=True, maximum=maximum)
        pins.verify()
    if current is not None and staged is not None:
        fail()
    body = current if current is not None else staged if staged is not None else produce()
    if type(body) is not bytes or not 0 < len(body) <= maximum:
        fail()
    _new_file(final, body, 0o600)
    return body


def _exact_component(directory, name, body):
    _new_file(directory.path / name, body, 0o600)


def _read_generation(directory, name, maximum=MAX_CHAIN):
    with closing(publisher._Pins()) as pins:
        value = _read_fixed(pins, directory.path / name, 0o600, maximum=maximum)
        pins.verify()
        return value


def _public_key(path):
    return _ssl('pkey', '-in', str(path), '-passin', 'pass:', '-pubout')


def _certificate_key(cert):
    return _ssl('x509', '-noout', '-pubkey', value=cert)


def _certificate_expiry(cert):
    value = _ssl('x509', '-noout', '-enddate', value=cert).decode('ascii').strip()
    prefix = 'notAfter='
    if not value.startswith(prefix):
        fail()
    return ssl.cert_time_to_seconds(value[len(prefix):])


def _key():
    return _ssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256')


def _ca(authority, request):
    hostname = urlsplit(request['profile']['origin']).hostname
    owner = {'installationId': request['installationId'], 'origin': request['profile']['origin']}
    owner_body = encoded(owner)
    key = authority.path / 'ca-key.pem'
    if request['previous'] is None:
        _exact_component(authority, 'authority.json', owner_body)
        _component(authority, key.name, _key, maximum=MAX_KEY)
    else:
        if _read_generation(authority, 'authority.json') != owner_body:
            fail()
        _read_generation(authority, key.name, MAX_KEY)
    public = _public_key(key)
    serial = '0x' + digest(encoded(owner))[:36]
    def create():
        return _ssl('req', '-new', '-x509', '-sha256', '-key', str(key), '-passin', 'pass:', '-days', '3650',
                    '-subj', '/CN=Orbis Recovery ' + hostname, '-set_serial', serial,
                    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                    '-addext', 'subjectKeyIdentifier=hash',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    ca = (_component(authority, 'ca.pem', create) if request['previous'] is None
          else _read_generation(authority, 'ca.pem'))
    if len(_certificates(ca)) != 1 or public != _certificate_key(ca):
        fail()
    return ca


def _issue(directory, authority, request):
    hostname = urlsplit(request['profile']['origin']).hostname
    key = directory.path / 'key.pem'
    extensions = directory.path / 'leaf.conf'
    _exact_component(directory, extensions.name, (
        '[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
        'extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
        'subjectAltName=DNS:' + hostname + '\n').encode('ascii'))
    csr = _ssl('req', '-new', '-key', str(key), '-passin', 'pass:', '-subj', '/CN=' + hostname)
    return _ssl('x509', '-req', '-sha256', '-CA', str(authority.path / 'ca.pem'),
                '-CAkey', str(authority.path / 'ca-key.pem'), '-passin', 'pass:',
                '-set_serial', '0x' + request['operationId'][:36], '-days', '90', '-extfile', str(extensions),
                '-extensions', 'leaf', value=csr)


def _leaf_scope(cert, hostname):
    # An imported wildcard or SAN shared with a dashboard is ineligible.
    def extension(name):
        content = _ssl('x509', '-noout', '-ext', name, value=cert).decode('ascii').splitlines()
        if len(content) != 2:
            fail()
        return content[1].strip()
    usage = set(extension('keyUsage').split(', '))
    if (extension('subjectAltName') != 'DNS:' + hostname or extension('basicConstraints') != 'CA:FALSE'
            or not usage.intersection({'Digital Signature', 'Key Encipherment'})
            or usage.intersection({'Certificate Sign', 'CRL Sign'})):
        fail()


def _validate_pair(directory, hostname, mode, chain, trust):
    certs = _certificates(chain)
    first = certs[0]
    _leaf_scope(first, hostname)
    _ssl('x509', '-noout', '-checkend', '86400', value=first)
    public = _public_key(directory.path / 'key.pem')
    if public != _certificate_key(first):
        fail()
    _exact_component(directory, 'leaf.pem', first)
    options = []
    if len(certs) > 1:
        _exact_component(directory, 'intermediates.pem', b''.join(certs[1:]))
        options += ['-untrusted', str(directory.path / 'intermediates.pem')]
    if mode == 'local':
        _exact_component(directory, 'trust.pem', trust)
        options += ['-CAfile', str(directory.path / 'trust.pem'), '-no-CApath']
    _ssl('verify', '-x509_strict', '-purpose', 'sslserver', '-verify_hostname', hostname, *options, str(directory.path / 'leaf.pem'))
    server_context(str(directory.path / 'chain.pem'), str(directory.path / 'key.pem'), hostname)
    return {'certificateSha256': _certificate_sha(first), 'publicKeySha256': digest(public),
            'chainSha256': digest(chain), 'trustSha256': _certificate_sha(trust) if trust is not None else None,
            'leafExpiresAtSec': _certificate_expiry(first)}


def _check_request(value, operation):
    static = ('schema', 'operationId', 'root', 'context', 'daemon', 'installationId', 'profile',
              'mode', 'previous', 'dashboardHosts', 'dashboardHttpsPorts')
    if (set(value) != set(static) or value['schema'] != REQUEST or value['operationId'] != operation
            or not hash_value(value['installationId']) or value['mode'] not in ('local', 'import')
            or type(value['root']) is not str or not 1 <= len(value['root']) <= 4096
            or type(value['context']) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['context'])
            or type(value['daemon']) is not str or not re.fullmatch(r'[!-~]{1,128}', value['daemon'])):
        fail()
    config = profile(encoded(value['profile']))
    host, port = urlsplit(config['origin']).hostname, urlsplit(config['origin']).port
    dashboard, ports = value['dashboardHosts'], value['dashboardHttpsPorts']
    if (IPv4Address(config['bind']).is_loopback or type(dashboard) is not list or not 1 <= len(dashboard) <= 8
            or any(type(name) is not str or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', name) for name in dashboard)
            or host in {name.lower().rstrip('.') for name in dashboard}
            or type(ports) is not list or not 1 <= len(ports) <= 8
            or any(type(item) is not int or not 1 <= item <= 65535 for item in ports)
            or len(ports) != len(set(ports)) or port in ports or config['upstreamPort'] in ports):
        fail()
    previous = value['previous']
    if (previous is not None and (type(previous) is not dict or set(previous) != {'generation', 'receiptSha256'}
            or not all(hash_value(item) for item in previous.values()) or previous['generation'] == operation)):
        fail()
    return value


def _prior_link(root):
    try:
        info = os.stat('active', dir_fd=root.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        fail()
    value = os.readlink('active', dir_fd=root.fd)
    if not re.fullmatch(r'generations/[a-f0-9]{64}', value):
        fail()
    return value.split('/')[1]


def _select(root, generation, previous):
    if not hash_value(generation) or previous is not None and not hash_value(previous) or _prior_link(root) != previous:
        fail()
    destination = f'generations/{generation}'
    pending = '.active.pending'
    try:
        os.symlink(destination, pending, dir_fd=root.fd)
        os.fsync(root.fd)
    except FileExistsError:
        pass
    info = os.stat(pending, dir_fd=root.fd, follow_symlinks=False)
    root.verify()
    if (not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or os.readlink(pending, dir_fd=root.fd) != destination or _prior_link(root) != previous):
        fail()
    os.replace(pending, 'active', src_dir_fd=root.fd, dst_dir_fd=root.fd)
    os.fsync(root.fd)
    if _prior_link(root) != generation:
        fail()


def _absence(directory, name):
    if os.path.lexists(directory.path / name):
        fail()


def _one_file(path, maximum, mode=0o600):
    with closing(publisher._Pins()) as pins:
        result = _read_fixed(pins, path, mode, maximum=maximum)
        pins.verify()
        return result


def _cert_context(directory, mode):
    path = directory.path / 'trust.pem'
    context = ssl.create_default_context(cafile=str(path) if mode == 'local' else None)
    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        fail()
    return context


def _expired(metadata):
    return metadata['leafExpiresAtSec'] <= time.time()


def _wire_fingerprint(config, context, deadline):
    origin = urlsplit(config['origin'])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        _deadline(connection, deadline)
        connection.connect((config['bind'], origin.port))
        _deadline(connection, deadline)
        with context.wrap_socket(connection, server_hostname=origin.hostname) as peer:
            return digest(peer.getpeercert(binary_form=True))


def _reported_worker(service):
    pid, invocation = service['MainPID'], service['InvocationID']
    if (service['ActiveState'] != 'active' or not re.fullmatch(r'[1-9][0-9]{0,9}', pid)
            or not re.fullmatch(r'[a-f0-9]{32}', invocation)):
        fail()
    return pid, invocation


def _worker_identity(service, launcher):
    pid, invocation = _reported_worker(service)
    path = Path('/proc') / pid
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        def read(name, maximum):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                data = stream.read(maximum + 1)
            if not 0 < len(data) <= maximum:
                fail()
            return data

        def start():
            stat_line = read('stat', 4096)
            trailing = stat_line.rsplit(b') ', 1)[-1].split()
            if not stat_line.startswith(pid.encode() + b' (') or len(trailing) < 20 or not trailing[19].isdigit():
                fail()
            return trailing[19]

        began = start()
        spec = ('/usr/bin/python3', '-I', launcher, '--recovery-https-edge')
        if (read('cmdline', 4096) != b'\0'.join(os.fsencode(part) for part in spec) + b'\0'
                or [entry for entry in read('environ', 8192).split(b'\0') if entry.startswith(b'INVOCATION_ID=')]
                != [b'INVOCATION_ID=' + invocation.encode()]
                or not os.path.samestat(os.stat('exe', dir_fd=directory), Path('/usr/bin/python3').stat())):
            fail()
        status = read('status', 8192)
        ids = []
        for name in (b'Uid', b'Gid'):
            values = re.findall(rb'(?m)^' + name + rb':[ \t]+([0-9]+)[ \t]+\1[ \t]+\1[ \t]+\1$', status)
            if len(values) != 1:
                fail()
            ids.append(int(values[0]))
        dynamic_identity(*ids)
        for name in (b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb'):
            if len(re.findall(rb'(?m)^' + name + rb':[ \t]+0{16}$', status)) != 1:
                fail()
        if (len(re.findall(rb'(?m)^NoNewPrivs:[ \t]+1$', status)) != 1
                or began != start() or not os.path.samestat(os.fstat(directory), path.stat())):
            fail()
        return pid, invocation, began
    finally:
        os.close(directory)


class EdgeSystem:
    """Operate only the two fixed HTTPS units, using already approved files."""

    def show(self, name, fields):
        if name not in (SERVICE, SOCKET):
            fail()
        return self._show(name, fields)

    def listener_profile(self):
        from .credential_floor import RECOVERY_UNIT

        return self._show(RECOVERY_UNIT.name, (
            'LoadState','ActiveState','SubState','FragmentPath','DropInPaths','NeedDaemonReload','MainPID','ControlPID',
            'InvocationID','KillMode','ExecStart','User','Group','ProtectHome','ProtectProc','ProtectSystem',
            'NoNewPrivileges','CapabilityBoundingSet'))

    @staticmethod
    def _show(name, fields):
        output = _command(SYSTEMCTL, 'show', '--no-pager', '--all',
                          *('--property=' + field for field in fields), name, allowed=(0, 4)).decode('ascii')
        facts = {}
        for line in output.splitlines():
            key, sep, value = line.partition('=')
            if not sep or key in facts:
                fail()
            facts[key] = value
        if set(facts) != set(fields):
            fail()
        return facts

    def assert_vacant(self, request):
        for lookup in (pwd.getpwnam, grp.getgrnam):
            try:
                lookup(PRINCIPAL)
            except KeyError:
                continue
            fail()
        address, port = request['profile']['bind'], urlsplit(request['profile']['origin']).port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((address, port))
        for name in (SERVICE, SOCKET):
            current = self.show(name, ('LoadState', 'ActiveState', 'FragmentPath', 'DropInPaths'))
            if current != {'LoadState': 'not-found', 'ActiveState': 'inactive', 'FragmentPath': '', 'DropInPaths': ''}:
                fail()
        dropin = UNIT_ROOT / (SOCKET + '.d')
        if (any(os.path.lexists(path) for path in (UNIT_ROOT / SERVICE, UNIT_ROOT / SOCKET, ENV, dropin))
                or os.path.lexists(UNIT_ROOT / (SERVICE + '.d'))):
            fail()

    def configure(self, package, request):
        config = request['profile']
        dropin = UNIT_ROOT / (SOCKET + '.d')
        _make_protected_directory(ENV.parent, private=False)
        _make_protected_directory(dropin, private=False)
        with closing(publisher._Pins()) as pins:
            names = set(os.listdir(pins.directory(dropin)))
            if names - {'10-installation.conf', '.10-installation.conf.pending'}:
                fail()
        _new_file(dropin / '10-installation.conf', self.dropin(config), 0o644)
        for name in (SERVICE, SOCKET):
            _new_file(UNIT_ROOT / name, package['units'][name], 0o644)
        _new_file(ENV, self.environment(package), 0o600)
        self.verify_files(package, request)

    @staticmethod
    def environment(package):
        return f'ORBIS_SENTINEL_EDGE_RUNTIME={package["launcher"]}\n'.encode('ascii')

    @staticmethod
    def dropin(config):
        port = urlsplit(config['origin']).port
        return f'[Socket]\nListenStream={config["bind"]}:{port}\nIPAddressAllow={config["allow"]}\n'.encode('ascii')

    def verify_files(self, package, request):
        dropin = UNIT_ROOT / (SOCKET + '.d')
        protected = [(UNIT_ROOT / name, package['units'][name], 0o644) for name in (SERVICE, SOCKET)]
        protected.extend(((ENV, self.environment(package), 0o600),
                          (dropin / '10-installation.conf', self.dropin(request['profile']), 0o644)))
        with closing(publisher._Pins()) as pins:
            if set(os.listdir(pins.directory(dropin))) != {'10-installation.conf'}:
                fail()
            for path, value, mode in protected:
                if _read_fixed(pins, path, mode) != value:
                    fail()
            pins.verify()

    def loaded(self, package, request, *, socket_active, attachment=None):
        self.verify_files(package, request)
        config = request['profile']
        socket_fields = ('LoadState', 'ActiveState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'Listen', 'Accept',
                         'FileDescriptorName')
        endpoint = f'{config["bind"]}:{urlsplit(config["origin"]).port} (Stream)'
        endpoint_dropin = str(UNIT_ROOT / (SOCKET + '.d') / '10-installation.conf')
        listener = self.show(SOCKET, socket_fields)
        if (listener != {'LoadState': 'loaded', 'ActiveState': 'active' if socket_active else 'inactive',
                         'FragmentPath': str(UNIT_ROOT / SOCKET), 'DropInPaths': endpoint_dropin, 'NeedDaemonReload': 'no',
                         'Listen': endpoint, 'Accept': 'no', 'FileDescriptorName': 'recovery-https'}):
            fail()
        fields = ('LoadState', 'ActiveState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload',
                  'ExecStart', 'DynamicUser', 'User', 'Group', 'NoNewPrivileges', 'CapabilityBoundingSet', 'MainPID',
                  'InvocationID', 'ProtectHome', 'ProtectSystem')
        service = self.show(SERVICE, fields)
        expected = {'LoadState': 'loaded', 'FragmentPath': str(UNIT_ROOT / SERVICE), 'DropInPaths': '',
                    'NeedDaemonReload': 'no', 'DynamicUser': 'yes', 'User': 'orbis-sentinel-https',
                    'Group': 'orbis-sentinel-https', 'NoNewPrivileges': 'yes', 'CapabilityBoundingSet': '',
                    'ProtectHome': 'yes', 'ProtectSystem': 'strict'}
        if attachment is not None:
            if type(attachment) is not EdgeAttachment:
                fail()
            attachment.verify_files()
            expected['DropInPaths'] = str(attachment.dropin)
        command = re.fullmatch(
            r'\{ path=/usr/bin/python3 ; argv\[\]=([^;\r\n]+) ; ignore_errors=no'
            r'(?: ; start_time=\[[^\[\];{}\r\n]+\] ; stop_time=\[[^\[\];{}\r\n]+\]'
            r' ; pid=[0-9]+ ; code=[^;{}\r\n]+ ; status=[^;{}\r\n]+)? \}',
            service['ExecStart'])
        launch = f'/usr/bin/python3 -I {package["launcher"]} --recovery-https-edge'
        literal = '/usr/bin/python3 -I ${ORBIS_SENTINEL_EDGE_RUNTIME} --recovery-https-edge'
        if (any(service[key] != item for key, item in expected.items()) or command is None
                or command[1] not in (literal, launch)):
            fail()
        # PID 1 can clear ExecStatus during daemon-reload while the worker stays live.
        return {**service, 'ExecStart': launch}

    def start(self, package, request):
        current = self.show(SOCKET, ('ActiveState',))['ActiveState']
        if current == 'active':
            self.loaded(package, request, socket_active=True)
            return
        if current != 'inactive':
            fail()
        _command(SYSTEMCTL, 'daemon-reload')
        self.loaded(package, request, socket_active=False)
        _command(SYSTEMCTL, 'start', SOCKET)
        self.loaded(package, request, socket_active=True)

    def restart(self, package, request):
        active = self.loaded(package, request, socket_active=True)
        if active['ActiveState'] not in ('active', 'failed', 'inactive'):
            fail()
        _command(SYSTEMCTL, 'restart', SERVICE)

    def enable(self, package, request):
        self.loaded(package, request, socket_active=True)
        state = self.show(SOCKET, ('UnitFileState',))['UnitFileState']
        if state == 'disabled':
            _command(SYSTEMCTL, 'enable', SOCKET)
        if self.show(SOCKET, ('UnitFileState',))['UnitFileState'] != 'enabled':
            fail()

    def prove(self, package, request, directory, *, retry=False):
        return self._prove(package, request, _cert_context(directory, request['mode']), retry)

    def prove_expired(self, package, request, directory, metadata):
        """Observe the already owned expired leaf, without sending HTTP or granting trust."""
        if not _expired(metadata) or _certificate_sha(_read_generation(directory, 'chain.pem')) != metadata['certificateSha256']:
            fail()
        identity = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        identity.check_hostname = False
        identity.verify_mode = ssl.CERT_NONE
        observed = self._prove(package, request, identity, True)
        if observed != metadata['certificateSha256']:
            fail()
        return observed

    def _prove(self, package, request, context, retry):
        before = self.loaded(package, request, socket_active=True)
        previous = _worker_identity(before, package['launcher']) if before['ActiveState'] == 'active' else None
        end = time.monotonic() + (8 if retry else 3)
        while True:
            now = time.monotonic()
            if now >= end:
                raise TimeoutError('Recovery HTTPS proof expired')
            try:
                certificate = _wire_fingerprint(request['profile'], context, min(now + 3, end))
                break
            except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
                remaining = end - time.monotonic()
                if not retry or remaining <= 0:
                    raise
                time.sleep(min(0.1, remaining))
        service = self.loaded(package, request, socket_active=True)
        current = _worker_identity(service, package['launcher'])
        if previous is not None and previous != current:
            fail()
        return certificate


def _binding(request, checked):
    return {'schema': 'orbis.sentinel-recovery-https-intent.v1', 'operationId': request['operationId'],
            'installationId': request['installationId'], 'reviewSha256': digest(checked[0]),
            'approvalSha256': digest(checked[1])}


def _approve(value, request, review_sha):
    if (value != {'schema': APPROVAL, 'operationId': request['operationId'],
                  'installationId': request['installationId'], 'reviewSha256': review_sha,
                  'approvalId': value.get('approvalId')} or not hash_value(value.get('approvalId'))):
        fail()


def _result(intent, checked, metadata):
    return {'schema': RESULT, 'scope': 'https-transport-only',
            'operationId': intent['operationId'], 'installationId': intent['installationId'],
            'reviewSha256': intent['reviewSha256'], 'approvalSha256': intent['approvalSha256'],
            'profileSha256': digest(encoded(checked['profile'])), 'mode': checked['mode'], **metadata}


def _previous(root, installation, prior_id, prior_sha, *, request=None):
    with (_subdirectory(root, 'operations') as operations, _subdirectory(operations, prior_id) as previous,
          _subdirectory(root, 'generations') as generations, _subdirectory(generations, prior_id) as generation):
        prev_request_body, prev_review_body, prev_approval_body = (_read(previous, name) for name in
                                                                  ('request.json', 'review.json', 'approval.json'))
        earlier = _check_request(_canonical(prev_request_body), prior_id)
        review, approval = _canonical(prev_review_body), _canonical(prev_approval_body)
        _approve(approval, earlier, digest(prev_review_body))
        intent = _binding(earlier, (prev_review_body, prev_approval_body))
        receipt = _read(previous, 'complete.json')
        metadata = _canonical(_read(generation, 'facts.json'))
        if ((prior_sha is not None and digest(receipt) != prior_sha)
                or receipt != encoded(_result(intent, earlier, metadata))
                or earlier['installationId'] != installation or review.get('schema') != REVIEW
                or review.get('requestSha256') != digest(prev_request_body)
                or _read(previous, 'intent.json') != encoded(intent)
                or _read(previous, 'credential-generation.json') != encoded(metadata)
                or (request is not None and any(earlier[key] != request[key] for key in ('profile', 'mode')))):
            fail()
        _validate_retained(generation, earlier, metadata)
        return earlier, review, metadata, _canonical(receipt)


def _validate_retained(directory, request, metadata):
    hashes = {'certificateSha256', 'publicKeySha256', 'chainSha256'}
    if (set(metadata) != hashes | {'trustSha256', 'leafExpiresAtSec'}
            or not all(hash_value(metadata[key]) for key in hashes)
            or type(metadata['leafExpiresAtSec']) is not int or metadata['leafExpiresAtSec'] <= 0):
        fail()
    chain = _read_generation(directory, 'chain.pem')
    _read_generation(directory, 'key.pem', MAX_KEY)
    hostname = urlsplit(request['profile']['origin']).hostname
    local = request['mode'] == 'local'
    trust = _read_generation(directory, 'trust.pem') if local else None
    if (metadata['trustSha256'] != (_certificate_sha(trust) if local else None)
            or _read_generation(directory, 'profile.json', 2048) != encoded(request['profile'])
            or metadata['certificateSha256'] != _certificate_sha(chain) or metadata['chainSha256'] != digest(chain)
            or metadata['leafExpiresAtSec'] != _certificate_expiry(_certificates(chain)[0])
            or metadata['publicKeySha256'] != digest(_public_key(directory.path / 'key.pem'))):
        fail()
    server_context(str(directory.path / 'chain.pem'), str(directory.path / 'key.pem'), hostname)


class EdgeInstall:
    def __init__(self, verify_package, system=None):
        self.verify_package = verify_package
        self.system = EdgeSystem() if system is None else system

    @contextmanager
    def _package(self):
        with closing(publisher._Pins()) as pins:
            evidence = publisher._producer(pins)
            installed = evidence['installation']
            version = installed['version']
            root = publisher.ROOT / 'releases' / version
            names = [*(f'packaging/systemd/{name}' for name in (SOCKET, SERVICE)),
                     'src/orbis_sentinel/recovery_https_edge.py', 'src/orbis_sentinel/recovery_https_install.py']
            members = installed['files']
            for name in names:
                match = members.get(name)
                if not match or not 0 < match['bytes'] <= 262144:
                    fail()
                body = _read_fixed(pins, root / name, 0o644, maximum=262144)
                if len(body) != match['bytes'] or digest(body) != match['sha256']:
                    fail()
            units = {name: _read_fixed(pins, root / 'packaging' / 'systemd' / name, 0o644) for name in (SOCKET, SERVICE)}
            package = {'launcher': str(root / 'bin' / 'orbis-sentinel'), 'units': units,
                       'binding': {'version': version, 'packageSha256': installed['sha256'],
                                   'sourceCommit': installed['sourceCommit'],
                                   'profileSha256': digest(encoded({name: members[name] for name in names}))}}
            def check():
                self.verify_package()
                pins.verify()
            check()
            yield package, check
            check()

    @contextmanager
    def _scope(self, operation):
        if not hash_value(operation):
            fail()
        with (self._package() as (package, package_check), PrivateDirectory(STATE) as root,
              _subdirectory(root, 'operations') as operations, _subdirectory(operations, operation) as directory,
              closing(publisher._Pins()) as pins):
            fcntl.flock(root.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            body = _read_fixed(pins, directory.path / 'request.json', 0o600)
            request = _check_request(_canonical(body), operation)
            installation = _InstallationDirectory(Path(request['root']))
            try:
                bound = {key: request[key] for key in ('root', 'context', 'daemon')}
                if digest(encoded({**bound, 'rootIdentity': installation.identity})) != request['installationId']:
                    fail()
                imported = {}
                if request['mode'] == 'import':
                    for name, limit in (('import-chain.pem', MAX_CHAIN), ('import-key.pem', MAX_KEY)):
                        imported[name] = _read_fixed(pins, directory.path / name, 0o600, maximum=limit)
                review = {'schema': REVIEW, 'operationId': operation, 'installationId': request['installationId'],
                          'requestSha256': digest(body), 'package': package['binding'],
                          'imports': {name: digest(data) for name, data in imported.items()}}

                def verify():
                    package_check()
                    root.verify()
                    directory.verify()
                    installation.verify()
                    pins.verify()

                verify()
                yield root, directory, request, package, review, imported, verify
                verify()
            finally:
                installation.close()

    @staticmethod
    def _prior(root, request, package):
        preceding = request['previous']
        if preceding is None:
            return None
        generation = preceding['generation']
        earlier, review, metadata, _ = _previous(root, request['installationId'], generation,
                                                 preceding['receiptSha256'], request=request)
        if review['package'] != package['binding']:
            fail()
        return generation, earlier, metadata

    def review(self, operation):
        with self._scope(operation) as (root, directory, request, package, review, _, verify):
            _attachment_clear(root)
            _absence(root, 'writer-fence.json')
            _absence(root, '.writer-fence.json.pending')
            _absence(root, '.active.pending')
            prior = self._prior(root, request, package)
            if _prior_link(root) != (prior[0] if prior else None):
                fail()
            if prior is None:
                self.system.assert_vacant(request)
            else:
                self.system.verify_files(package, request)
            verify()
            result = encoded(review)
            _new_file(directory.path / 'review.json', result, 0o600)
            return {'operationId': operation, 'reviewSha256': digest(result), 'phase': 'https-awaits-approval'}

    def _generate(self, root, generation, request, imported, prior):
        _exact_component(generation, 'profile.json', encoded(request['profile']))
        if request['mode'] == 'local':
            with _subdirectory(root, 'authority', create=prior is None) as authority:
                ca = _ca(authority, request)
                if prior is not None and _certificate_sha(ca) != prior[2]['trustSha256']:
                    fail()
                _component(generation, 'key.pem', _key, maximum=MAX_KEY)
                chain = _component(generation, 'chain.pem', lambda: _issue(generation, authority, request))
        else:
            ca = None
            chain = imported['import-chain.pem']
            _leaf_scope(_certificates(chain)[0], urlsplit(request['profile']['origin']).hostname)
            # The approved input bytes define both imported components.
            _exact_component(generation, 'key.pem', imported['import-key.pem'])
            _exact_component(generation, 'chain.pem', chain)
        facts = _validate_pair(generation, urlsplit(request['profile']['origin']).hostname, request['mode'], chain, ca)
        _exact_component(generation, 'facts.json', encoded(facts))
        _validate_retained(generation, request, facts)
        return facts

    @staticmethod
    def _clear(root, fence, check):
        check()
        if _read(root, 'writer-fence.json', optional=True) != fence:
            fail()
        os.unlink('writer-fence.json', dir_fd=root.fd)
        os.fsync(root.fd)
        root.verify()

    def apply(self, operation, review_sha, approval_sha):
        if not all(hash_value(value) for value in (review_sha, approval_sha)):
            fail()
        with (self._scope(operation) as (root, directory, request, package, review, imported, verify),
              closing(publisher._Pins()) as approvals):
            _attachment_clear(root)
            read = lambda name: _read_fixed(approvals, directory.path / name, 0o600)
            reviewed, approved = read('review.json'), read('approval.json')
            if reviewed != encoded(review) or digest(reviewed) != review_sha or digest(approved) != approval_sha:
                fail()
            _approve(_canonical(approved), request, review_sha)
            intent = _binding(request, (reviewed, approved))
            fence = encoded(intent)
            prior = self._prior(root, request, package)
            previous_id = prior[0] if prior is not None else None
            completed = _read(directory, 'complete.json', optional=True)
            rolled_back = _read(directory, 'rolled-back.json', optional=True)
            held = _read(root, 'writer-fence.json', optional=True)

            def verify_approval():
                verify()
                approvals.verify()

            def guard():
                verify_approval()
                if _read(root, 'writer-fence.json', optional=True) != fence:
                    fail()

            if held is not None and held != fence:
                fail()
            if completed is not None or rolled_back is not None:
                return self._completed(root, directory, request, package, intent, prior, completed,
                                       rolled_back, held, verify_approval)
            if _read(directory, 'intent.json', optional=True) is None:
                verify_approval()
                if _prior_link(root) != previous_id or os.path.lexists(root.path / '.active.pending'):
                    fail()
                if prior is None:
                    self.system.assert_vacant(request)
                _new_file(root.path / 'writer-fence.json', fence, 0o600)
                guard()
                _new_file(directory.path / 'intent.json', fence, 0o600)
            elif _read(directory, 'intent.json') != fence or held != fence:
                fail()
            guard()
            with (_subdirectory(root, 'generations', create=True) as generations,
                  _subdirectory(generations, operation, create=True) as generation):
                return self._apply_generation(root, directory, generation, request, package, imported,
                                              intent, prior, guard)

    def _apply_generation(self, root, directory, generation, request, package, imported, intent, prior, guard):
        operation = request['operationId']
        previous_id = prior[0] if prior else None
        fence = encoded(intent)
        generation_body = _read(directory, 'credential-generation.json', optional=True)
        if generation_body is None:
            if _prior_link(root) != previous_id:
                fail()
            guard()
            metadata = self._generate(root, generation, request, imported, prior)
            _exact_component(directory, 'credential-generation.json', encoded(metadata))
        else:
            metadata = _canonical(generation_body)
            if _read(generation, 'facts.json') != generation_body:
                fail()
            _validate_retained(generation, request, metadata)
        if prior is not None and metadata['certificateSha256'] == prior[2]['certificateSha256']:
            fail()
        staged = _read(directory, 'selection.json', optional=True)
        selection = encoded({'generation': operation, 'previousGeneration': previous_id, 'factsSha256': digest(encoded(metadata))})
        if staged is None:
            if _prior_link(root) != previous_id:
                fail()
            guard()
            if prior is None:
                self.system.configure(package, request)
            else:
                self._prove_previous(root, request, package, prior, allow_expired=True)
            _exact_component(directory, 'selection.json', selection)
        elif staged != selection:
            fail()

        rollback = _read(directory, 'rolling-back.json', optional=True)
        if rollback is not None:
            if prior is None or rollback != selection:
                fail()
            return self._rollback(root, directory, request, package, prior, selection, fence, guard)

        guard()
        active = _prior_link(root)
        if active == previous_id:
            _select(root, operation, previous_id)
        elif active != operation or os.path.lexists(root.path / '.active.pending'):
            fail()

        if prior is None:
            self.system.start(package, request)
        certificate = self._presented(package, request, generation, retry=prior is None)
        if certificate is None and prior is not None and _expired(prior[2]):
            try:
                self._prove_previous(root, request, package, prior, allow_expired=True)
                certificate = prior[2]['certificateSha256']
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
        if prior is not None and certificate == prior[2]['certificateSha256']:
            guard()
            _exact_component(directory, 'restart-attempt.json', selection)
            # An uncertain command reply leaves this exact selection in place.
            # Replay observes the new leaf before deciding whether to restart.
            self.system.restart(package, request)
            certificate = self._presented(package, request, generation, retry=True)
        if certificate != metadata['certificateSha256']:
            if prior is None:
                fail()
            guard()
            _exact_component(directory, 'rolling-back.json', selection)
            return self._rollback(root, directory, request, package, prior, selection, fence, guard)

        guard()
        self.system.enable(package, request)
        result = encoded(_result(intent, request, metadata))
        _exact_component(directory, 'complete.json', result)
        self._clear(root, fence, guard)
        return {'phase': 'https-transport-verified', 'operationId': operation, 'receiptSha256': digest(result)}

    def _presented(self, package, request, generation, *, retry):
        try:
            return self.system.prove(package, request, generation, retry=retry)
        except (OSError, ValueError, subprocess.SubprocessError):
            return None

    def _prove_previous(self, root, request, package, prior, *, allow_expired=False):
        with (_subdirectory(root, 'generations') as generations, _subdirectory(generations, prior[0]) as old):
            metadata = prior[2]
            expired = allow_expired and _expired(metadata)
            leaf = (self.system.prove_expired(package, request, old, metadata) if expired
                    else self.system.prove(package, request, old))
            if leaf != metadata['certificateSha256']:
                fail()
            return expired

    def _rollback(self, root, directory, request, package, prior, selection, fence, guard):
        guard()
        operation = request['operationId']
        active = _prior_link(root)
        if active == operation:
            _select(root, prior[0], operation)
        elif active != prior[0] or os.path.lexists(root.path / '.active.pending'):
            fail()
        try:
            expired = self._prove_previous(root, request, package, prior, allow_expired=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            guard()
            self.system.restart(package, request)
            expired = self._prove_previous(root, request, package, prior, allow_expired=True)
        guard()
        _exact_component(directory, 'rolled-back.json', selection)
        self._clear(root, fence, guard)
        phase = 'https-rotation-rolled-back-expired' if expired else 'https-rotation-rolled-back'
        return {'phase': phase, 'operationId': operation, 'retainedGeneration': prior[0]}

    def _completed(self, root, directory, request, package, intent, prior, complete, rolled_back, held, verify):
        if (complete is not None) == (rolled_back is not None) or _read(directory, 'intent.json') != encoded(intent):
            fail()
        if rolled_back is not None:
            if (prior is None or _prior_link(root) != prior[0] or rolled_back != _read(directory, 'rolling-back.json')
                    or rolled_back != _read(directory, 'selection.json')):
                fail()
            expired = self._prove_previous(root, request, package, prior, allow_expired=True)
            phase = 'https-rotation-rolled-back-expired' if expired else 'https-rotation-rolled-back'
            result = {'phase': phase, 'operationId': request['operationId'], 'retainedGeneration': prior[0]}
        else:
            operation = request['operationId']
            if _prior_link(root) != operation:
                fail()
            _, _, metadata, _ = _previous(root, request['installationId'], operation, digest(complete))
            self._prove_previous(root, request, package, (operation, request, metadata))
            result = {'phase': 'https-transport-verified', 'operationId': operation, 'receiptSha256': digest(complete)}
        if held is not None:
            self._clear(root, held, verify)
        verify()
        return result

    def export_ca(self, operation):
        with self._scope(operation) as (root, directory, request, package, _, _, verify):
            _absence(root, 'writer-fence.json')
            if request['mode'] != 'local' or _prior_link(root) != operation:
                fail()
            _, review, metadata, receipt = _previous(root, request['installationId'], operation, None)
            if review['package'] != package['binding']:
                fail()
            with (_subdirectory(root, 'generations') as generations,
                  _subdirectory(generations, operation) as generation):
                ca = _read_generation(generation, 'trust.pem')
                if _certificate_sha(ca) != metadata['trustSha256']:
                    fail()
            verify()
            return {'origin': request['profile']['origin'], 'caCertificatePem': ca.decode('ascii'),
                    'caCertificateSha256': metadata['trustSha256'], 'leafExpiresAtSec': metadata['leafExpiresAtSec'],
                    'receiptSha256': digest(encoded(receipt))}


def run(action, operation, review, approval, *, verify_package):
    writer = EdgeInstall(verify_package)
    if action == 'review':
        return writer.review(operation)
    if action == 'apply':
        return writer.apply(operation, review, approval)
    if action == 'export-ca':
        return writer.export_ca(operation)
    fail()


def _attachment_clear(root):
    for name in (ATTACHMENT,'.'+ATTACHMENT+'.pending'):
        _absence(root,name)


def socket_identity(pid, address, port, *, inherited=None):
    """Join one actual local TCP listener to its observed unit's held process."""
    pid = str(pid)
    if not re.fullmatch(r'[1-9][0-9]{0,9}',pid) or type(port) is not int or not 1024 <= port <= 65535:
        fail()
    path = Path('/proc')/pid
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        def snapshot():
            table = os.open('net/tcp',os.O_RDONLY|os.O_CLOEXEC,dir_fd=fd)
            with os.fdopen(table,'rb') as body:
                rows = body.read(1024*1024+1)
            if len(rows) > 1024*1024:
                fail()
            token = IPv4Address(address).packed[::-1].hex().upper().encode()+f':{port:04X}'.encode()
            entries = [row.split() for row in rows.splitlines()[1:]]
            if any(len(row) < 10 for row in entries):
                fail()
            exact = [row[9] for row in entries if row[1] == token and row[3] == b'0A']
            if len(exact) != 1 or not exact[0].isdigit():
                fail()
            descriptors = os.open('fd',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=fd)
            try:
                matched = []
                names = tuple(os.listdir(descriptors)) if inherited is None else (str(inherited),)
                if len(names) > 512:
                    fail()
                for name in names:
                    try:
                        link = os.readlink(name,dir_fd=descriptors)
                    except FileNotFoundError:
                        continue
                    if link == 'socket:['+exact[0].decode('ascii')+']':
                        matched.append(int(name))
                if len(matched) != 1:
                    fail()
                return {'inode':int(exact[0]),'fd':matched[0],'address':address,'port':port}
            finally:
                os.close(descriptors)
        observed = snapshot()
        if observed != snapshot() or not os.path.samestat(os.fstat(fd),path.stat()):
            fail()
        return observed
    finally:
        os.close(fd)


def boot_identity():
    with Path('/proc/sys/kernel/random/boot_id').open('rb') as source:
        body = source.read(65)
    if not re.fullmatch(rb'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\n',body):
        fail()
    return digest(body)


class RetainedEdge:
    def __init__(self, package, request, facts, trust, reference, verify, *, key_sha256=None):
        self.package,self.request,self.facts,self.trust = package,request,facts,trust
        self.reference,self.verify = reference,verify
        self.key_sha256 = key_sha256

    def context(self):
        return ssl.create_default_context(cadata=self.trust.decode('ascii')) if self.trust is not None else ssl.create_default_context()

    def probe(self):
        self.verify()
        actual = _wire_fingerprint(self.request['profile'],self.context(),time.monotonic()+3)
        if actual != self.facts['certificateSha256']:
            fail()
        self.verify()


@contextmanager
def held_public_edge(public, installation, verify_package):
    """The old selected public certificate and socket remain the only edge identity."""
    with (EdgeInstall(verify_package)._package() as (package,package_check),PrivateDirectory(STATE) as root,
          _subdirectory(root,'generations') as generations,closing(publisher._Pins()) as pins):
        generation = public['generation']
        if not hash_value(generation) or not hash_value(public['receiptSha256']):
            fail()
        request,review,facts,receipt = _previous(root,installation,generation,public['receiptSha256'])
        if (review.get('package') != package['binding'] or facts['certificateSha256'] != public['certificateSha256']
                or receipt['profileSha256'] != public['profileSha256'] or facts['leafExpiresAtSec'] <= time.time()):
            fail()
        with _subdirectory(generations,generation) as retained:
            profile_bytes = _read_fixed(pins,retained.path/'profile.json',0o600)
            chain = _read_fixed(pins,retained.path/'chain.pem',0o600,maximum=MAX_CHAIN)
            trust = (_read_fixed(pins,retained.path/'trust.pem',0o600,maximum=MAX_CHAIN)
                     if request['mode'] == 'local' else None)
            key_sha = digest(_read_fixed(pins,retained.path/'key.pem',0o600,maximum=MAX_KEY))
            if _canonical(_read_fixed(pins,retained.path/'facts.json',0o600,maximum=MAX_CHAIN)) != facts:
                fail()
            if (profile_bytes != encoded(request['profile']) or _certificate_sha(chain) != facts['certificateSha256']
                    or facts['trustSha256'] != (_certificate_sha(trust) if trust is not None else None)):
                fail()
            with (_subdirectory(root,'operations') as operations,
                  _subdirectory(operations,generation) as operation):
                for name in ('request.json','review.json','approval.json','intent.json','complete.json','credential-generation.json'):
                    _read_fixed(pins,operation.path/name,0o600,maximum=65536)
                if digest(pins.file(operation.path/'complete.json',65536,0o600)) != public['receiptSha256']:
                    fail()
                def verify():
                    package_check()
                    root.verify()
                    pins.verify()
                    if (_prior_link(root) != generation or facts['leafExpiresAtSec'] <= time.time()
                            or _read(root,'writer-fence.json',optional=True) is not None):
                        fail()
                    for name in ('.active.pending','.writer-fence.json.pending'):
                        _absence(root,name)
                verify()
                yield RetainedEdge(package,request,facts,trust,public,verify,key_sha256=key_sha)
                verify()


class EdgeAttachment:
    """An exact pending attachment. Only the setup writer can install it."""
    def __init__(self, packet, public, root):
        operation = packet['operationId']
        if not hash_value(operation) or not hash_value(packet['pairId']):
            fail()
        self.root,self.packet,self.public = root,packet,public
        self.directory = root.path/ATTACHMENTS/operation
        self.profile = self.directory/'edge.json'
        self.dropin = UNIT_ROOT/(SERVICE+'.d')/ATTACH_DROPIN

    def bytes(self):
        from .recovery_backend_tls import AUTHORITY_ROOT

        role = AUTHORITY_ROOT/self.packet['pairId']
        paths = (self.profile,role/'ca.pem',role/'client.pem',role/'client-key.pem')
        return ('[Service]\n'+''.join(f'LoadCredential={name}:{path}\n' for name,path in zip(BACKEND_FILES,paths))).encode('ascii')

    def value(self):
        return {'schema':ATTACH_SCHEMA,'operationId':self.packet['operationId'],'pairId':self.packet['pairId'],
                'installationId':self.packet['installationId'],'markerSha256':self.packet['markerSha256'],
                'pairSha256':self.packet['pairSha256'],'edgeSha256':digest(encoded(self.packet)),
                'dropinSha256':digest(self.bytes()),'generation':self.public.request['operationId']}

    def verify_files(self):
        value = self.value()
        self.public.verify()
        with closing(publisher._Pins()) as pins:
            if (_read_fixed(pins,self.root.path/ATTACHMENT,0o600) != encoded(value)
                    or _read_fixed(pins,self.root.path/('.'+ATTACHMENT+'.pending'),0o600,optional=True) is not None
                    or _read_fixed(pins,self.profile,0o600) != encoded(self.packet)
                    or _read_fixed(pins,self.dropin,0o644) != self.bytes()
                    or set(os.listdir(pins.directory(self.dropin.parent))) != {ATTACH_DROPIN}
                    or _read_fixed(pins,self.directory/'public.json',0o600) != encoded(self.public.reference)
                    or set(os.listdir(pins.directory(self.directory,0o700))) != {'edge.json','public.json'}):
                fail()
            pins.verify()

    def install(self, system, authorize):
        authorize()
        self.public.verify()
        expected = encoded(self.value())
        existing = _read(self.root,ATTACHMENT,optional=True)
        if existing is None:
            if os.path.lexists(self.dropin) or os.path.lexists(self.directory):
                fail()
            system.loaded(self.public.package,self.public.request,socket_active=True)
        elif existing != expected:
            fail()
        _new_file(self.root.path/ATTACHMENT,expected,0o600)
        authorize()
        with (_subdirectory(self.root,ATTACHMENTS,create=True) as parent,
              _subdirectory(parent,self.packet['operationId'],create=True)):
            _new_file(self.profile,encoded(self.packet),0o600)
            authorize()
            _new_file(self.directory/'public.json',encoded(self.public.reference),0o600)
        _make_protected_directory(self.dropin.parent,private=False)
        with closing(publisher._Pins()) as files:
            if set(os.listdir(files.directory(self.dropin.parent))) - {ATTACH_DROPIN,'.'+ATTACH_DROPIN+'.pending'}:
                fail()
            for path, sha in zip((self.profile,*self._role_paths()),(self.value()['edgeSha256'],
                    self.packet['caFileSha256'],self.packet['clientFileSha256'],self.packet['clientKeySha256'])):
                if digest(_read_fixed(files,path,0o600,maximum=16384)) != sha:
                    fail()
            files.verify()
            authorize()
            _new_file(self.dropin,self.bytes(),0o644)
            files.verify()
        self.verify_files()

    def _role_paths(self):
        from .recovery_backend_tls import AUTHORITY_ROOT
        role = AUTHORITY_ROOT/self.packet['pairId']
        return role/'ca.pem',role/'client.pem',role/'client-key.pem'

    def loaded_credentials(self, pid, attachment):
        from .recovery_https_edge import TRUST_FILES
        if attachment is not None and attachment is not self:
            fail()
        path = Path('/proc')/str(pid)/'root/run/credentials'/SERVICE
        fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            profile = digest(encoded(self.public.request['profile']))
            expected = dict(zip(TRUST_FILES,(profile,self.public.facts['chainSha256'],self.public.key_sha256)))
            if attachment is self:
                expected.update(zip(BACKEND_FILES,(self.value()['edgeSha256'],self.packet['caFileSha256'],
                                                   self.packet['clientFileSha256'],self.packet['clientKeySha256'])))
            limits = dict(zip((*TRUST_FILES,*BACKEND_FILES),(2048,65536,MAX_KEY,4096,MAX_KEY,MAX_KEY,MAX_KEY)))
            if set(os.listdir(fd)) != set(expected):
                fail()
            for name, sha in expected.items():
                item = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                with os.fdopen(item,'rb') as stream:
                    observed = os.fstat(stream.fileno())
                    maximum = limits[name]
                    if not stat.S_ISREG(observed.st_mode) or not 0 < observed.st_size <= maximum:
                        fail()
                    if (digest(stream.read(maximum+1)) != sha
                            or seal(observed) != seal(os.stat(name,dir_fd=fd,follow_symlinks=False))):
                        fail()
        finally:
            os.close(fd)

    def _reload_state(self, system):
        service = system.show(SERVICE,('NeedDaemonReload','DropInPaths'))
        if service['NeedDaemonReload'] not in ('yes','no') or service['DropInPaths'] not in ('',str(self.dropin)):
            fail()
        return service

    def _ready_worker(self, system, attachment, *, expected=None):
        public = self.public
        reported = _reported_worker(system.loaded(public.package,public.request,socket_active=True,attachment=attachment))
        if expected is not None and reported != expected:
            fail()
        # Type=simple reports this invocation before exec and credentials are ready.
        # Wait for its fixed public TLS leg before reading procfs or sending HTTP.
        public.probe()
        return reported

    def activate(self, system, prior, authorize):
        authorize()
        self.verify_files()
        public = self.public
        service = self._reload_state(system)
        if service != {'NeedDaemonReload':'no','DropInPaths':str(self.dropin)}:
            authorize()
            self.verify_files()
            system.verify_files(public.package,public.request)
            if self._reload_state(system) != service:
                fail()
            _command(SYSTEMCTL,'daemon-reload')
        state = system.loaded(public.package,public.request,socket_active=True,attachment=self)
        restarting = None
        if state['ActiveState'] == 'active':
            pid, invocation = _reported_worker(state)
            if [int(pid),invocation] == prior[:2]:
                observed = _worker_identity(state,public.package['launcher'])
                if [int(observed[0]),observed[1],int(observed[2])] != prior:
                    fail()
                authorize()
                _command(SYSTEMCTL,'restart',SERVICE)
            else:
                restarting = (pid,invocation)
        elif state['ActiveState'] in ('inactive','failed'):
            if state['MainPID'] != '0':
                fail()
            authorize()
            _command(SYSTEMCTL,'start',SERVICE)
        else:
            fail()
        ready = self._ready_worker(system,self,expected=restarting)
        authorize()
        observed = self.observe(system,ready=ready)
        if [observed['pid'],observed['invocationId']] == prior[:2]:
            fail()
        return observed

    def observe(self, system, *, ready=None):
        return self._observe(system,self,ready=ready)

    def _observe(self, system, attachment, *, ready=None):
        public = self.public
        state = system.loaded(public.package,public.request,socket_active=True,attachment=attachment)
        if ready is not None and _reported_worker(state) != ready:
            fail()
        pid, invocation, began = _worker_identity(state,public.package['launcher'])
        config = public.request['profile']
        port = urlsplit(config['origin']).port
        # A pre-projection receipt cannot authorize this observation or its rollback.
        effective = {'schema':'orbis.sentinel-recovery-edge-effective.v1','profile':state}
        details = {'pid':int(pid),'startTicks':int(began),'invocationId':invocation,'effectiveSha256':digest(encoded(effective)),
                   'socket':socket_identity(pid,config['bind'],port,inherited=3)}
        self.loaded_credentials(int(pid),attachment)
        if attachment is self:
            self.verify_files()
        if _worker_identity(system.loaded(public.package,public.request,socket_active=True,attachment=attachment),
                            public.package['launcher']) != (pid,invocation,began):
            fail()
        return details

    def rollback(self,system,expected,authorize,*,restored=None):
        """Remove only our exact drop-in; leave the selector and source evidence held."""
        from .recovery_gateway import BASE
        from .recovery_listener_install import _tls_get

        def ordinary():
            profile = self.public.request['profile']
            reported = (str(restored[0]),restored[1]) if restored is not None else None
            ready = self._ready_worker(system,None,expected=reported)
            authorize()
            current = self._observe(system,None,ready=ready)
            identity = [current['pid'],current['invocationId'],current['startTicks']]
            if (identity == [expected['pid'],expected['invocationId'],expected['startTicks']]
                    or restored is not None and identity != restored):
                fail()
            status,_,headers,_ = _tls_get(profile['origin'],self.public.context(),BASE+'/',
                                           'application/json; charset=utf-8',retained=self.public)
            if status != 503 or any(name.lower() == 'set-cookie' for name,_ in headers):
                fail()
            if self._observe(system,None,ready=ready) != current:
                fail()
            return identity

        authorize()
        if _read(self.root,ATTACHMENT) != encoded(self.value()):
            fail()
        public = self.public
        system.verify_files(public.package,public.request)
        if restored is not None:
            if os.path.lexists(self.dropin) or ordinary() != restored:
                fail()
            return restored
        with closing(publisher._Pins()) as pins:
            content = _read_fixed(pins,self.dropin,0o644,optional=True)
            names = set(os.listdir(pins.directory(self.dropin.parent)))
            if names != ({ATTACH_DROPIN} if content is not None else set()):
                fail()
            if content is not None:
                if content != self.bytes() or self.observe(system) != expected:
                    fail()
                pins.verify()
                authorize()
                os.unlink(self.dropin.name,dir_fd=pins.directory(self.dropin.parent))
                os.fsync(pins.directory(self.dropin.parent))
        try:
            return ordinary()
        except (OSError,ValueError):
            authorize()
        system.verify_files(public.package,public.request)
        self._reload_state(system)
        with closing(publisher._Pins()) as pins:
            if os.listdir(pins.directory(self.dropin.parent)):
                fail()
            pins.verify()
        _command(SYSTEMCTL,'daemon-reload')
        service = system.loaded(public.package,public.request,socket_active=True)
        if service['ActiveState'] == 'active':
            observed = _worker_identity(service,public.package['launcher'])
            if [int(observed[0]),observed[1],int(observed[2])] != [expected['pid'],expected['invocationId'],expected['startTicks']]:
                fail()
        elif service['ActiveState'] not in ('inactive','failed') or service['MainPID'] != '0':
            fail()
        authorize()
        system.restart(public.package,public.request)
        return ordinary()
