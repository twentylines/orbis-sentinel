"""Independent recovery authentication, observed status and exact controller return."""

from dataclasses import dataclass
from functools import lru_cache
import http.server
import json
from pathlib import Path
import re
import secrets
import socket
import socketserver
import threading
import time
from urllib.parse import urlsplit

from .recovery_sessions import RecoverySessionError, _token
from .status import ComponentStatus, build_status
from .observer import unavailable_handoff, validate_handoff_envelope, validate_progress
from .controller_return_readiness import APPROVAL, READINESS, RETURN, ControllerReturnGateway

BASE = '/sentinel/recovery'
API = BASE + '/api/v1'
ASSETS = '/sentinel/recovery-assets/'
BACKEND_HANDSHAKE_TIMEOUT = 3
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
_ROOT = Path(__file__).resolve().parents[2] / 'web'
_ASSETS = {'recovery.css': 'text/css; charset=utf-8', 'recovery.js': 'text/javascript; charset=utf-8'}


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes
    content_type: str = 'application/json; charset=utf-8'
    cookies: tuple = ()


def _json(status, value, cookies=()):
    return Reply(status, json.dumps(value, separators=(',', ':')).encode(), cookies=cookies)


@lru_cache(maxsize=3)
def _asset(name):
    file = _ROOT / name
    if file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= 65536:
        raise ValueError('Recovery interface is unavailable')
    body = file.read_bytes()
    if not 0 < len(body) <= 65536:
        raise ValueError('Recovery interface is unavailable')
    return body


def _decode(body):
    def pairs(items):
        value = dict(items)
        if len(value) != len(items):
            raise ValueError('Duplicate request field')
        return value
    value = json.loads(body.decode('utf8'), object_pairs_hook=pairs)
    if type(value) is not dict:
        raise ValueError('Invalid request')
    return value


class RecoveryApplication:
    """Providers are enrolled privileged dependencies, never request parameters.

    verify(digest, challenge, request) must invoke the protected credential worker
    and establish its cleanup before returning. The installed listener supplies
    the controller-return dependencies from the same Sessions owner.
    """

    def __init__(self, *, origin, sessions, verify, status, check=None, binding_observer=None, progress=None, handoff_status=None,
                 controller_return=None):
        if (check is not None and not callable(check)
                or binding_observer is not None and not callable(binding_observer)
                or progress is not None and not callable(progress)
                or handoff_status is not None and not callable(handoff_status)
                or controller_return is not None and (type(controller_return) is not ControllerReturnGateway
                    or controller_return.approvals.sessions is not sessions or controller_return.approvals.origin != origin
                    or controller_return.handoff_status is not handoff_status)):
            raise ValueError('Recovery configuration check must be callable.')
        self.check = check
        self.binding_observer = binding_observer
        if type(origin) is not str or len(origin) > 512:
            raise ValueError('Recovery origin and providers must be enrolled')
        parsed = urlsplit(origin)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment or parsed.port == 0
                or (parsed.scheme == 'http' and parsed.hostname != 'localhost')
                or any(ord(c) <= 32 or ord(c) == 127 for c in origin) or not callable(verify) or not callable(status)):
            raise ValueError('Recovery origin and providers must be enrolled')
        self.origin, self.host = origin, parsed.netloc
        self.sessions, self.verify, self.status = sessions, verify, status
        self.progress = progress
        self.handoff_status = handoff_status if handoff_status is not None else unavailable_handoff
        self.controller_return = controller_return
        self.secure = parsed.scheme == 'https'
        self.prefix = '__Host-orbis-sentinel-' if self.secure else 'orbis-sentinel-local-'
        self._verification = threading.BoundedSemaphore(1)
        self._key_verification = threading.BoundedSemaphore(1)
        self._return_dispatch = threading.BoundedSemaphore(1)
        self._controller_routes = {
            ('GET', API + '/handoff-status'): self._read_handoff,
            ('POST', API + '/' + APPROVAL): self._approve_return,
            ('POST', API + '/' + RETURN): self._apply_return,
        }

    def _return_routes_ready(self):
        expected = {
            ('GET', API + '/handoff-status'): RecoveryApplication._read_handoff,
            ('POST', API + '/' + APPROVAL): RecoveryApplication._approve_return,
            ('POST', API + '/' + RETURN): RecoveryApplication._apply_return,
        }
        if set(self._controller_routes) != set(expected) or any(
                getattr(self._controller_routes[key], '__self__', None) is not self
                or getattr(self._controller_routes[key], '__func__', None) is not handler
                for key, handler in expected.items()):
            raise RuntimeError('Controller return routes are unavailable.')

    def _read_handoff(self, token, headers, body):
        self.sessions.session(token=token, origin=self.origin, touch=False)
        try:
            handoff = validate_handoff_envelope(self.handoff_status())
        except Exception:
            raise RuntimeError('Observed handoff status is unavailable') from None
        self.sessions.session(token=token, origin=self.origin, touch=False)
        return _json(200, handoff)

    def _approve_return(self, token, headers, body):
        if self.controller_return is None:
            return _json(404, {'error': 'Recovery route was not found.'})
        csrf = headers.get('x-orbis-sentinel-csrf', '')
        self.sessions.session(token=token, csrf=csrf, origin=self.origin, fresh=True, touch=False)
        return _json(200, self.controller_return.approve(
            _decode(body), token=token, csrf=csrf, origin=self.origin))

    def _apply_return(self, token, headers, body):
        if self.controller_return is None:
            return _json(404, {'error': 'Recovery route was not found.'})
        csrf = headers.get('x-orbis-sentinel-csrf', '')
        self.sessions.session(token=token, csrf=csrf, origin=self.origin, fresh=True, touch=False)
        request = _decode(body)
        if not self._return_dispatch.acquire(blocking=False):
            return _json(429, {'error': 'A controller return is being checked. Check Sentinel status.'})
        try:
            return _json(200, self.controller_return.apply(request, token=token, csrf=csrf, origin=self.origin))
        finally:
            self._return_dispatch.release()

    def _cookie(self, name, value='', *, clear=False, readable=False):
        result = f'{self.prefix}{name}={value}; Path=/; SameSite=Strict; Max-Age={0 if clear else 3600}'
        if self.secure:
            result += '; Secure'
        if not readable:
            result += '; HttpOnly'
        return result

    def _cookies(self, raw):
        found = {}
        for part in raw.split(';'):
            name, separator, value = part.strip().partition('=')
            if not name.startswith(self.prefix):
                continue
            if not separator or name in found:
                raise ValueError('Ambiguous cookie')
            _token(value)
            found[name] = value
        return found

    def _status(self):
        value = self.status()
        if (type(value) is not dict or set(value) != {'schema', 'protocolVersion', 'components'}
                or value['schema'] != 'orbis-sentinel.status.v1' or type(value['protocolVersion']) is not int
                or value['protocolVersion'] != 1 or type(value['components']) is not dict
                or set(value['components']) != {'orbis', 'sentinel'}):
            raise ValueError('Invalid observed status')
        def component(name):
            item = value['components'][name]
            if type(item) is not dict or set(item) != {'installedVersion', 'availableVersion', 'state'}:
                raise ValueError('Invalid observed component')
            return ComponentStatus(installed_version=item['installedVersion'], available_version=item['availableVersion'], state=item['state'])
        return build_status(component('orbis'), component('sentinel'))

    def _progress(self):
        value = self.progress() if self.progress is not None else {
            'schema': 'orbis-sentinel.progress.v1', 'available': False, 'progress': None,
            'ageMs': None, 'sourceState': 'unavailable'}
        if (type(value) is not dict or set(value) != {'schema', 'available', 'progress', 'ageMs', 'sourceState'}
                or value['schema'] != 'orbis-sentinel.progress.v1' or type(value['available']) is not bool
                or value['sourceState'] not in ('ready', 'stale', 'unavailable', 'starting')
                or value['ageMs'] is not None and (type(value['ageMs']) is not int or not 0 <= value['ageMs'] <= 2 ** 53 - 1)
                or value['available'] and (value['sourceState'] != 'ready' or value['ageMs'] is None or value['ageMs'] > 5000)
                or value['sourceState'] == 'starting' and value['ageMs'] is not None
                or not value['available'] and value['progress'] is not None):
            raise ValueError('Invalid observed progress')
        progress = validate_progress(value['progress']) if value['available'] else None
        return {'schema': value['schema'], 'available': value['available'], 'progress': progress,
                'ageMs': value['ageMs'], 'sourceState': value['sourceState']}

    def handle(self, method, path, headers, body=b''):
        try:
            if self.check is not None:
                try:
                    self.check()
                except Exception:
                    raise RuntimeError('Recovery configuration is unavailable.') from None
            if (headers.get('host') != self.host or len(path) > 2048 or len(body) > 32768
                    or headers.get('origin', self.origin) != self.origin):
                return _json(400, {'error': 'Invalid recovery request.'})
            if method not in ('GET', 'POST'):
                return _json(405, {'error': 'Unsupported recovery request.'})
            if method == 'GET' and body:
                return _json(400, {'error': 'Invalid recovery request.'})
            if method == 'GET' and path.startswith(ASSETS):
                name = path[len(ASSETS):]
                if name in _ASSETS:
                    return Reply(200, _asset(name), _ASSETS[name])
            if method == 'GET' and path in (BASE, BASE + '/'):
                try:
                    cookies = self._cookies(headers.get('cookie', ''))
                except (RecoverySessionError, ValueError):
                    cookies = {}
                binding = cookies.get(self.prefix + 'binding') or secrets.token_urlsafe(32)
                if self.binding_observer is not None and path == BASE + '/' and 'cookie' not in headers:
                    self.binding_observer(binding)
                reset = () if cookies else tuple(self._cookie(name, clear=True, readable=name == 'csrf') for name in ('session', 'csrf'))
                return Reply(200, _asset('recovery.html'), 'text/html; charset=utf-8', (self._cookie('binding', binding), *reset))
            cookies = self._cookies(headers.get('cookie', ''))
            if method == 'POST' and (headers.get('origin') != self.origin or headers.get('content-type') != 'application/json'):
                return _json(403, {'error': 'Invalid recovery origin.'})
            if 'x-orbis-sentinel-return-probe' in headers:
                probe = headers['x-orbis-sentinel-return-probe']
                if (self.controller_return is None or (method, path) not in self._controller_routes
                        or 'cookie' in headers or 'x-orbis-sentinel-csrf' in headers
                        or type(probe) is not str or not re.fullmatch(r'[a-f0-9]{2,1024}', probe)
                        or len(probe) % 2 or body not in (b'', b'{}')):
                    return _json(404, {'error': 'Recovery route was not found.'})
                self._return_routes_ready()
                return _json(200, self.controller_return.route_probe(_decode(bytes.fromhex(probe)), method, path))
            if method == 'POST' and path == API + '/' + READINESS:
                if self.controller_return is None or 'cookie' in headers or 'x-orbis-sentinel-csrf' in headers:
                    return _json(404, {'error': 'Recovery route was not found.'})
                self._return_routes_ready()
                return _json(200, self.controller_return.readiness(_decode(body)))
            if method == 'GET' and path == API + '/options':
                options = self.sessions.authentication_options()
                if options['origin'] != self.origin:
                    raise RuntimeError('Recovery identity origin changed')
                return _json(200, {'password': options['password'], 'recoveryKey': options['recoveryKey'],
                                   'passkey': bool(options['credentialIds']), 'totp': options['totp']})
            if method == 'POST' and path == API + '/challenge':
                request = _decode(body)
                if set(request) != {'method'} or request['method'] not in ('password', 'passkey', 'recovery-key'):
                    raise ValueError('Invalid challenge request')
                options = self.sessions.authentication_options()
                issued = self.sessions.challenge(method=request['method'], origin=self.origin, browser_binding=cookies[self.prefix + 'binding'])
                if request['method'] == 'passkey':
                    issued['publicKey'] = {'challenge': issued['challenge'], 'rpId': options['rpId'], 'userVerification': 'required',
                                           'timeout': 120000, 'allowCredentials': [{'type': 'public-key', 'id': key} for key in options['credentialIds']]}
                return _json(200, issued)
            if method == 'POST' and path == API + '/login':
                request = _decode(body)
                if set(request) != {'challenge', 'credentials'} or type(request['credentials']) is not dict:
                    raise ValueError('Invalid sign-in request')
                credentials = request['credentials']
                admission = self._key_verification if credentials.get('method') == 'recovery-key' else self._verification
                if not admission.acquire(blocking=False):
                    return _json(429, {'error': 'Another sign-in is being checked. Try again shortly.'})
                try:
                    if credentials.get('method') == 'recovery-key':
                        if set(credentials) != {'method', 'recoveryKey'}:
                            raise ValueError('Invalid recovery key request')
                        result = self.sessions.complete_recovery_key(challenge=request['challenge'],
                                                                    browser_binding=cookies[self.prefix + 'binding'], origin=self.origin,
                                                                    recovery_key=credentials['recoveryKey'])
                    else:
                        result = self.sessions.complete(challenge=request['challenge'], browser_binding=cookies[self.prefix + 'binding'], origin=self.origin,
                                                        verifier=lambda digest, nonce: self.verify(digest, nonce, credentials))
                finally:
                    admission.release()
                return _json(200, {'authenticated': True}, (self._cookie('session', result['token']),
                                                           self._cookie('csrf', result['csrfToken'], readable=True)))
            token = cookies.get(self.prefix + 'session')
            if method == 'GET' and path == API + '/session':
                if token is None:
                    return _json(200, {'authenticated': False})
                try:
                    session = self.sessions.session(token=token, origin=self.origin, touch=False)
                except RecoverySessionError:
                    return _json(200, {'authenticated': False}, tuple(self._cookie(name, clear=True, readable=name == 'csrf') for name in ('session', 'csrf')))
                return _json(200, {'authenticated': True, 'method': session['method'], 'expiresAtMs': session['expiresAtMs']})
            if method == 'POST' and path == API + '/logout':
                if _decode(body) != {}:
                    raise ValueError('Invalid session request')
                csrf = headers.get('x-orbis-sentinel-csrf', '')
                if token is not None:
                    self.sessions.logout(token=token, origin=self.origin, csrf=csrf)
                return _json(200, {'authenticated': False}, tuple(self._cookie(name, clear=True, readable=name == 'csrf') for name in ('session', 'csrf'))
                             + (self._cookie('binding', secrets.token_urlsafe(32)),))
            if token is None:
                return _json(401, {'error': 'Sign in to recovery.'})
            route = self._controller_routes.get((method, path))
            if route is not None:
                return route(token, headers, body)
            if method == 'POST' and path == API + '/active':
                if _decode(body) != {}:
                    raise ValueError('Invalid session request')
                self.sessions.session(token=token, origin=self.origin, csrf=headers.get('x-orbis-sentinel-csrf', ''))
                return _json(200, {'authenticated': True})
            if method == 'GET' and path == API + '/status':
                self.sessions.session(token=token, origin=self.origin, touch=False)
                try:
                    status = self._status()
                except Exception:
                    raise RuntimeError('Observed status is unavailable') from None
                return _json(200, status)
            if method == 'GET' and path == API + '/progress':
                self.sessions.session(token=token, origin=self.origin, touch=False)
                try:
                    progress = self._progress()
                except Exception:
                    raise RuntimeError('Observed progress is unavailable') from None
                self.sessions.session(token=token, origin=self.origin, touch=False)
                return _json(200, progress)
            return _json(404, {'error': 'Recovery route was not found.'})
        except RecoverySessionError:
            return _json(401, {'error': 'Sign-in could not be completed. Try again.'})
        except (ValueError, KeyError, TypeError, UnicodeError):
            return _json(400, {'error': 'Invalid recovery request.'})
        except Exception:
            return _json(503, {'error': 'Recovery is temporarily unavailable. Try again shortly.'})


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(3)
        self._reading_deadline = threading.Timer(3, self._expire_read)
        self._reading_deadline.daemon = True
        self._reading_deadline.start()

    def _expire_read(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._reading_deadline.cancel()
        super().finish()

    def log_message(self, *args):
        pass

    def _handle(self):
        self.close_connection = True
        names = [name.lower() for name in self.headers.keys()]
        length = self.headers.get('Content-Length', '0')
        if (self.request_version not in ('HTTP/1.0', 'HTTP/1.1') or len(names) > 32 or len(set(names)) != len(names)
                or sum(len(k) + len(v) for k, v in self.headers.items()) > 16384
                or any(name in self.headers for name in ('Transfer-Encoding', 'Content-Encoding', 'Expect'))
                or not re.fullmatch('[0-9]{1,5}', length) or int(length) > 32768
                or (self.command == 'POST' and ('Content-Length' not in self.headers or int(length) == 0))):
            reply = _json(400, {'error': 'Invalid recovery request.'})
        else:
            body = self.rfile.read(int(length))
            if len(body) != int(length):
                return
            self._reading_deadline.cancel()
            reply = self.server.application.handle(self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body)
        self.send_response(reply.status)
        for name, value in [('Content-Type', reply.content_type), ('Content-Length', str(len(reply.body))), ('Cache-Control', 'no-store'),
                            ('Content-Security-Policy', CSP), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'),
                            ('Cross-Origin-Opener-Policy', 'same-origin'), ('Connection', 'close')]:
            self.send_header(name, value)
        for cookie in reply.cookies:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(reply.body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _handle

    def handle_expect_100(self):
        self.send_error(417)
        return False


class RecoveryHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Explicit loopback listener for a separately enrolled TLS reverse proxy.

    Constructing this class does not enroll a profile or install routing/service
    configuration. Plain HTTP is accepted only for the localhost development realm.
    """
    daemon_threads = False
    block_on_close = True

    def __init__(self, address, application, *, backend=None):
        if address[0] != '127.0.0.1':
            raise ValueError('Recovery listener must use loopback')
        self.application = application
        if backend is not None:
            from .recovery_backend_tls import ListenerPeer
            if type(backend) is not ListenerPeer:
                raise ValueError('Recovery requires its exact private listener transport.')
        self._backend = backend
        self._draining = threading.Event()
        self._slots = threading.BoundedSemaphore(8)
        super().__init__(address, _Handler)

    def process_request(self, request, address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            accepted = (request,time.monotonic()+BACKEND_HANDSHAKE_TIMEOUT) if self._backend is not None else request
            super().process_request(accepted,address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            if self._backend is None:
                super().process_request_thread(request,address)
                return
            raw, expires = request
            try:
                secured = self._backend.authenticate(raw,expires,self._draining)
            except (OSError,ValueError):
                self.shutdown_request(raw)
                return
            if self._draining.is_set():
                self.shutdown_request(secured)
            else:
                super().process_request_thread(secured,address)
        finally:
            self._slots.release()

    def shutdown(self):
        self._draining.set()
        super().shutdown()

    def handle_error(self, request, address):
        pass
