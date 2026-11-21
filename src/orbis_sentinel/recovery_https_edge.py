"""Bounded HTTPS transport for the existing independent recovery gateway."""

from contextlib import ExitStack
from http.cookies import SimpleCookie
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import ssl
import stat
import sys
import threading
import time
from urllib.parse import urlsplit

from .bootstrap_source import decode, digest, encoded, fail, hash_value
from .controller_return_readiness import APPROVAL, READINESS, RETURN
from .recovery_gateway import API, ASSETS, BASE, CSP, _ASSETS

PROFILE = 'orbis.sentinel-recovery-https-edge.v1'
FD_NAME = 'recovery-https'
PRINCIPAL = 'orbis-sentinel-https'
BACKEND_NAME = 'sentinel-loopback.invalid'
TRUST_FILES = ('edge-profile', 'edge-chain', 'edge-key')
BACKEND_FILES = ('backend-profile','backend-ca','backend-client','backend-client-key')
PENDING_GETS = {BASE+'/',*{ASSETS+name for name in _ASSETS},API+'/session',API+'/options'}
PAIR_SCHEMA = 'orbis.sentinel-recovery-backend-edge.v1'
JSON = 'application/json; charset=utf-8'
HTML = 'text/html; charset=utf-8'
COOKIE_NAMES = tuple('__Host-orbis-sentinel-' + name for name in ('binding', 'session', 'csrf'))
MAX_HEADER = 16384
MAX_REQUEST = 32768
MAX_RESPONSE = 65536
MAX_CONNECTIONS = 8
TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z')
LABEL = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
HOSTNAME = re.compile(rf'{LABEL}(?:\.{LABEL})+\Z')
HEADER = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
REQUEST_LINE = re.compile(rb'(GET|POST) (/[^ ]*) HTTP/1\.[01]\Z')
REPLY_LINE = re.compile(rb'HTTP/1\.[01] ([1-5][0-9]{2}) [ -~]{1,80}\Z')
SECURITY_HEADERS = {'Cache-Control': 'no-store', 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff',
                    'Referrer-Policy': 'no-referrer', 'Cross-Origin-Opener-Policy': 'same-origin'}
ROUTES = {
    ('GET', BASE): HTML,
    ('GET', BASE + '/'): HTML,
    **{('GET', ASSETS + name): content for name, content in _ASSETS.items()},
    **{('GET', API + '/' + name): JSON for name in ('options', 'session', 'status', 'progress', 'handoff-status')},
    **{('POST', API + '/' + name): JSON for name in ('challenge', 'login', 'logout', 'active', READINESS, APPROVAL, RETURN)},
}
REPLIES = {200: 'OK', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
           405: 'Method Not Allowed', 429: 'Too Many Requests', 503: 'Service Unavailable'}
UNAVAILABLE = (503, JSON, (), b'{"error":"Recovery is temporarily unavailable. Try again shortly."}')


def profile(body):
    value = decode(body)
    if (encoded(value) != body or set(value) != {'schema', 'origin', 'bind', 'allow', 'upstreamPort'}
            or value['schema'] != PROFILE or type(value['origin']) is not str or len(value['origin']) > 512
            or type(value['bind']) is not str or type(value['allow']) is not str
            or type(value['upstreamPort']) is not int or not 1024 <= value['upstreamPort'] <= 65535):
        fail()
    origin = urlsplit(value['origin'])
    address, allowed = IPv4Address(value['bind']), IPv4Network(value['allow'], strict=True)
    if (origin.scheme != 'https' or origin.hostname is None or not HOSTNAME.fullmatch(origin.hostname)
            or len(origin.hostname) > 253 or origin.port is None or not 1024 <= origin.port <= 65535
            or value['origin'] != f'https://{origin.hostname}:{origin.port}' or value['upstreamPort'] == origin.port
            or address.is_unspecified or address.is_multicast or address.is_reserved or address.is_link_local
            or not address.is_private or address not in allowed or allowed.prefixlen < 8
            or (address.is_loopback and allowed != IPv4Network('127.0.0.0/8'))
            or (not address.is_loopback and not any(allowed.subnet_of(IPv4Network(cidr))
                for cidr in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))):
        fail()
    # A DNS-looking IPv4 literal still has no independent hostname.
    if origin.hostname.replace('.', '').isdigit():
        fail()
    return value


def _deadline(connection, expires):
    remaining = expires - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('Recovery transport deadline expired')
    connection.settimeout(remaining)


def _head(connection, expires, limit):
    data = bytearray()
    while b'\r\n\r\n' not in data:
        _deadline(connection, expires)
        chunk = connection.recv(min(4096, MAX_HEADER + 4 - len(data)))
        if not chunk:
            fail()
        data.extend(chunk)
    head, _, body = bytes(data).partition(b'\r\n\r\n')
    if len(head) > MAX_HEADER or len(body) > limit:
        fail()
    line, *rows = head.split(b'\r\n')
    if len(rows) > 32:
        fail()
    pairs = []
    for row in rows:
        name, sep, value = row.partition(b':')
        if not sep or not HEADER.fullmatch(name) or any(byte < 32 or byte > 126 for byte in value):
            fail()
        pairs.append((name.lower().decode('ascii'), value.strip().decode('ascii')))
    return line, pairs, body


def _headers(rows, *, cookies=False):
    headers, values = {}, []
    for key, item in rows:
        if cookies and key == 'set-cookie':
            values.append(item)
        elif key in headers:
            fail()
        else:
            headers[key] = item
    return headers, values


def _body(connection, first, length, expires, limit):
    if not re.fullmatch(r'0|[1-9][0-9]{0,4}', length):
        fail()
    size = int(length)
    if not len(first) <= size <= limit:
        fail()
    body = bytearray(first)
    while len(body) < size:
        _deadline(connection, expires)
        chunk = connection.recv(size - len(body))
        if not chunk:
            fail()
        body.extend(chunk)
    return bytes(body)


def _request_cookie(raw):
    selected = {}
    for item in raw.split(';'):
        name, separator, token = item.strip().partition('=')
        if name in COOKIE_NAMES:
            if not separator or name in selected or not TOKEN.fullmatch(token):
                fail()
            selected[name] = token
    return '; '.join(f'{name}={value}' for name, value in selected.items())


def _request(connection, config, expires):
    line, rows, first = _head(connection, expires, MAX_REQUEST)
    match = REQUEST_LINE.fullmatch(line)
    if match is None:
        fail()
    method, target = (item.decode('ascii') for item in match.groups())
    if (method, target) not in ROUTES:
        raise LookupError()
    headers, _ = _headers(rows)
    origin = config['origin']
    host = urlsplit(origin).netloc
    length = headers.get('content-length', '0')
    if (headers.get('host') != host or headers.get('origin', origin) != origin
            or headers.get('connection', 'close').lower() not in ('close', 'keep-alive')
            or any(name in headers for name in ('transfer-encoding', 'content-encoding', 'expect', 'upgrade', 'te',
                                               'trailer', 'forwarded', 'x-real-ip', 'authorization'))
            or any(name.startswith(('x-forwarded-', 'proxy-')) for name in headers)):
        fail()
    safe = {'Host': host, 'Connection': 'close'}
    if method == 'POST':
        if headers.get('origin') != origin or headers.get('content-type') != 'application/json' or length == '0':
            fail()
        safe.update({'Origin': origin, 'Content-Type': 'application/json', 'Content-Length': length})
    elif length != '0':
        fail()
    body = _body(connection, first, length, expires, MAX_REQUEST)
    if method == 'POST' and not body:
        fail()
    cookie = _request_cookie(headers.get('cookie', ''))
    if cookie:
        safe['Cookie'] = cookie
    if 'x-orbis-sentinel-csrf' in headers:
        csrf = headers['x-orbis-sentinel-csrf']
        if method != 'POST' or not TOKEN.fullmatch(csrf):
            fail()
        safe['X-Orbis-Sentinel-Csrf'] = csrf
    if 'x-orbis-sentinel-return-probe' in headers:
        probe = headers['x-orbis-sentinel-return-probe']
        if (cookie or 'x-orbis-sentinel-csrf' in headers or not re.fullmatch(r'[a-f0-9]{2,1024}', probe)
                or len(probe) % 2):
            fail()
        safe['X-Orbis-Sentinel-Return-Probe'] = probe
    return method, target, safe, body


def _response_cookies(values):
    seen = set()
    allowed = {'path', 'samesite', 'max-age', 'secure', 'httponly'}
    for value in values:
        cookie = SimpleCookie()
        cookie.load(value)
        if len(cookie) != 1:
            fail()
        item = next(iter(cookie.values()))
        if (item.key not in COOKIE_NAMES or item.key in seen or item['path'] != '/' or item['samesite'] != 'Strict'
                or not item['secure'] or bool(item['httponly']) != (item.key != COOKIE_NAMES[2])
                or any(item[attribute] for attribute in set(item) - allowed)):
            fail()
        if item.value:
            if item['max-age'] != '3600' or not TOKEN.fullmatch(item.value):
                fail()
        elif item['max-age'] != '0':
            fail()
        seen.add(item.key)
    return values


class BackendTLS:
    """A future retained admission must supply this exact private TLS peer."""

    def __init__(self, ca_pem, leaf_sha256):
        if type(ca_pem) is not str or not 0 < len(ca_pem) <= 16384 or not hash_value(leaf_sha256):
            fail()
        self._tls = ssl.create_default_context(cadata=ca_pem)
        self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self._leaf = leaf_sha256

    def authenticate(self, connection):
        secured = self._tls.wrap_socket(connection, server_hostname=BACKEND_NAME)
        if digest(secured.getpeercert(binary_form=True)) != self._leaf:
            secured.close()
            fail()
        return secured


def _leaf_hash(pem):
    match = re.match(rb'-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----',pem)
    if match is None:
        fail()
    return digest(ssl.PEM_cert_to_DER_cert(match[0].decode('ascii')))


class PendingBackendTLS(BackendTLS):
    """The only production backend, restricted to the retained signed-out proof."""
    def __init__(self, envelope, credentials, config, profile_body, public_chain, check):
        hashes = {'operationId','installationId','pairId','markerSha256','pairSha256','profileSha256',
                  'publicLeafSha256','serverLeafSha256','clientLeafSha256','clientFileSha256',
                  'caFileSha256','clientKeySha256'}
        if (type(envelope) is not dict or set(envelope) != hashes|{'schema','origin','listenPort','notBeforeSec','notAfterSec'}
                or envelope['schema'] != PAIR_SCHEMA or not all(hash_value(envelope[key]) for key in hashes)
                or envelope['origin'] != config['origin'] or envelope['listenPort'] != config['upstreamPort']
                or envelope['profileSha256'] != digest(profile_body) or envelope['publicLeafSha256'] != _leaf_hash(public_chain)):
            fail()
        _, ca, client, key = credentials
        if (envelope['caFileSha256'] != digest(ca[1]) or envelope['clientFileSha256'] != digest(client[1])
                or envelope['clientKeySha256'] != digest(key[1]) or envelope['clientLeafSha256'] != _leaf_hash(client[1])):
            fail()
        self._check = check
        self._validity = (envelope['notBeforeSec'],envelope['notAfterSec'])
        self.verify()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        context.load_verify_locations(cadata=ca[1].decode('ascii'))
        descriptors = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
        for fd, _ in (client,key):
            os.lseek(fd,0,os.SEEK_SET)
        context.load_cert_chain(f'{descriptors}/{client[0]}',f'{descriptors}/{key[0]}')
        self._tls = context
        self._leaf = envelope['serverLeafSha256']
        self.verify()

    def verify(self):
        before, after = self._validity
        if type(before) is not int or type(after) is not int or not 0 < before <= time.time() < after:
            fail()
        self._check()

    def permitted(self, method, target, headers, body):
        cookie = headers.get('Cookie','')
        if (method != 'GET' or target not in PENDING_GETS or body or 'X-Orbis-Sentinel-Csrf' in headers
                or cookie and (not cookie.startswith(COOKIE_NAMES[0]+'=') or not TOKEN.fullmatch(cookie.split('=',1)[1]))):
            return False
        self.verify()
        return True

    @staticmethod
    def response_cookies(target, values):
        result = []
        for value in _response_cookies(values):
            cookie = SimpleCookie()
            cookie.load(value)
            item = next(iter(cookie.values()))
            if item.value and (target != BASE+'/' or item.key != COOKIE_NAMES[0]):
                fail()
            if item.key == COOKIE_NAMES[0]:
                result.append(value)
        return result


def _pending_backend(directory, profile_files, resources, config):
    names = set(os.listdir(directory))
    if names != set(TRUST_FILES)|set(BACKEND_FILES):
        return None
    credentials = []
    for name, size in zip(BACKEND_FILES,(4096,16384,16384,16384)):
        item = _credential(directory,name,size)
        resources.callback(os.close,item[0])
        credentials.append(item)
    identities = []
    for name,item in zip((*TRUST_FILES,*BACKEND_FILES),(*profile_files,*credentials)):
        info = os.fstat(item[0])
        identities.append((name,item[0],(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                                        info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)))

    def check():
        if set(os.listdir(directory)) != names:
            fail()
        for name,fd,identity in identities:
            for info in (os.fstat(fd),os.stat(name,dir_fd=directory,follow_symlinks=False)):
                if (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,
                    info.st_size,info.st_mtime_ns,info.st_ctime_ns) != identity:
                    fail()

    packet = decode(credentials[0][1])
    if encoded(packet) != credentials[0][1]:
        fail()
    return PendingBackendTLS(packet,credentials,config,profile_files[0][1],profile_files[1][1],check)


def _upstream(config, backend, method, target, headers, request):
    pending = type(backend) is PendingBackendTLS
    if backend is None or pending and not backend.permitted(method,target,headers,request):
        return UNAVAILABLE
    # An authenticated return runs the full Host qualification. Other routes
    # keep their short timeout, and the Gateway serializes return dispatch.
    returning = (target == API + '/' + RETURN and 'X-Orbis-Sentinel-Csrf' in headers
                 and any(cookie.startswith(COOKIE_NAMES[1] + '=')
                         for cookie in headers.get('Cookie', '').split('; ')))
    expires = time.monotonic() + (48 if returning else 6)
    with ExitStack() as resources:
        connection = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        _deadline(connection, expires)
        connection.connect(('127.0.0.1', config['upstreamPort']))
        _deadline(connection, expires)
        peer = resources.enter_context(backend.authenticate(connection))
        if pending:
            backend.verify()
        wire = f'{method} {target} HTTP/1.1\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in headers.items())
        _deadline(peer, expires)
        peer.sendall(wire.encode('ascii') + b'\r\n' + request)
        line, rows, first = _head(peer, expires, MAX_RESPONSE)
        match = REPLY_LINE.fullmatch(line)
        observed, cookies = _headers(rows, cookies=True)
        if (match is None or any(name in observed for name in ('location', 'transfer-encoding', 'content-encoding',
                                                               'upgrade', 'refresh', 'trailer'))):
            fail()
        status = int(match[1])
        expected = ROUTES[(method, target)] if status == 200 else JSON
        if (status not in REPLIES or observed.get('content-type') != expected
                or any(observed.get(name.lower()) != value for name, value in SECURITY_HEADERS.items())):
            fail()
        body = _body(peer, first, observed.get('content-length', ''), expires, MAX_RESPONSE)
        accepted = backend.response_cookies(target,cookies) if pending else _response_cookies(cookies)
        return status, expected, accepted, body


def _send(connection, status, kind, cookies, body):
    headers = {'Content-Type': kind, 'Content-Length': str(len(body)), **SECURITY_HEADERS, 'Connection': 'close'}
    response = f'HTTP/1.1 {status} {REPLIES[status]}\r\n' + ''.join(f'{name}: {value}\r\n' for name, value in headers.items())
    response += ''.join(f'Set-Cookie: {value}\r\n' for value in cookies)
    connection.settimeout(2)
    connection.sendall(response.encode('ascii') + b'\r\n' + body)


class _Transport(socketserver.BaseRequestHandler):
    def handle(self):
        server = self.server
        if IPv4Address(self.client_address[0]) not in server.allowed:
            return
        try:
            self.request.settimeout(3)
            with server.context.wrap_socket(self.request, server_side=True) as secured:
                try:
                    request = _request(secured, server.config, time.monotonic() + 4)
                except LookupError:
                    _send(secured, 404, JSON, (), b'{"error":"Recovery route was not found."}')
                    return
                except (OSError, ValueError):
                    _send(secured, 400, JSON, (), b'{"error":"Invalid recovery request."}')
                    return
                try:
                    response = _upstream(server.config, server.backend, *request)
                except (OSError, ValueError):
                    response = UNAVAILABLE
                _send(secured, *response)
        except OSError:
            return


class EdgeServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Use the one already-open socket, with finite TLS workers and no queue."""
    daemon_threads = False
    block_on_close = True
    timeout = 0.2

    def __init__(self, listener, *, config, context, backend=None):
        port = urlsplit(config['origin']).port
        address = (config['bind'], port)
        if (listener.family != socket.AF_INET or listener.type != socket.SOCK_STREAM
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or listener.getsockname() != address or backend is not None and type(backend) not in (BackendTLS,PendingBackendTLS)):
            fail()
        super().__init__(address, _Transport, bind_and_activate=False)
        self.socket.close()
        self.socket = listener
        self.allowed = IPv4Network(config['allow'])
        self.config, self.context = config, context
        self.backend = backend
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # Exception diagnostics must not include HTTP headers, cookies or keys.
        return


def server_context(chain, key, hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(chain, key, password=lambda: '')

    def require_sni(connection, name, original_context):
        if name != hostname:
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.sni_callback = require_sni
    return context


def dynamic_identity(uid, gid):
    if not all(61184 <= number <= 65519 for number in (uid, gid)):
        fail()
    for path, value in (('/etc/passwd', uid), ('/etc/group', gid)):
        with open(path, 'rb') as stream:
            database = stream.read(1048577)
        if len(database) > 1048576:
            fail()
        for row in database.splitlines():
            fields = row.split(b':')
            if len(fields) >= 3 and (fields[0] == PRINCIPAL.encode() or fields[2] == str(value).encode()):
                fail()


def _privileges():
    if os.getuid() != os.geteuid() or os.getgid() != os.getegid() or set(os.getgroups()) - {os.getgid()}:
        fail()
    dynamic_identity(os.getuid(), os.getgid())
    with open('/proc/self/status', 'rb') as stream:
        body = stream.read(16385)
    if len(body) > 16384 or not re.search(rb'^NoNewPrivs:[ \t]+1$', body, re.M):
        fail()
    for name in (b'CapInh', b'CapPrm', b'CapEff', b'CapBnd', b'CapAmb'):
        if not re.search(rb'^' + name + rb':[ \t]+0{16}$', body, re.M):
            fail()


def _credential(directory, name, maximum):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    with os.fdopen(fd, 'rb', closefd=False) as stream:
        try:
            observed = os.fstat(fd)
            other = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (not os.path.samestat(observed, other) or not stat.S_ISREG(observed.st_mode)
                    or observed.st_uid not in (0, os.geteuid()) or observed.st_nlink != 1
                    or stat.S_IMODE(observed.st_mode) & 0o227 or not 0 < observed.st_size <= maximum):
                fail()
            body = stream.read(maximum + 1)
            if len(body) != observed.st_size:
                fail()
        except BaseException:
            os.close(fd)
            raise
    return fd, body


def main():
    stop = threading.Event()
    previous = {}
    try:
        _privileges()
        credential_path = f'/run/credentials/orbis-sentinel-recovery-https.service'
        if (os.environ.get('CREDENTIALS_DIRECTORY') != credential_path
                or os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1'
                or os.environ.get('LISTEN_FDNAMES') != FD_NAME):
            fail()
        with ExitStack() as resources:
            directory = os.open(credential_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            resources.callback(os.close, directory)
            files = []
            for name, limit in zip(TRUST_FILES, (2048, 65536, 16384)):
                fd, data = _credential(directory, name, limit)
                resources.callback(os.close, fd)
                files.append((fd, data))
            config = profile(files[0][1])
            context = server_context(f'/proc/self/fd/{files[1][0]}', f'/proc/self/fd/{files[2][0]}', urlsplit(config['origin']).hostname)
            listener = socket.socket(fileno=3)
            resources.callback(listener.close)
            for name in ('LISTEN_PID', 'LISTEN_FDS', 'LISTEN_FDNAMES'):
                os.environ.pop(name)
            os.set_inheritable(3, False)
            try:
                backend = _pending_backend(directory,files,resources,config)
            except (OSError,ValueError,TypeError,KeyError):
                backend = None
            if backend is None:
                server = EdgeServer(listener,config=config,context=context)
            else:
                server = EdgeServer(listener,config=config,context=context,backend=backend)
            resources.enter_context(server)
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda *_: stop.set())
            while not stop.is_set():
                server.handle_request()
        return 0
    except (OSError, ValueError, RuntimeError):
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
