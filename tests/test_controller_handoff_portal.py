"""Controller entry readiness observes only the configured HTTPS transport."""

from contextlib import contextmanager
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from orbis_sentinel import recovery_listener_install as listener


ORIGIN = 'https://sentinel.example.test:9443'
LANDING = b'<main>Recovery</main>'
ASSETS = {'recovery.html': LANDING, 'recovery.css': b':root {}', 'recovery.js': b'void 0;'}
BINDING = 'A' * 43
CERT = 'b' * 64
COOKIE = ('Set-Cookie', f'__Host-orbis-sentinel-binding={BINDING}; Path=/; Secure; HttpOnly; SameSite=Strict')
OPTIONS = {'password': True, 'recoveryKey': True, 'passkey': False, 'totp': {'password': True, 'passkey': False}}


class ControllerHandoffPortal(unittest.TestCase):
    def setUp(self):
        self.config = SimpleNamespace(data={'origin': ORIGIN})
        self.available = True
        self.edge = SimpleNamespace(context=lambda: self, reference={'generation': 'c' * 64}, probe=self.edge_check)
        self.calls = []
        self.landing = (200, LANDING, [COOKIE], CERT)
        self.options = (200, listener.encoded(OPTIONS), [], CERT)
        patcher = patch.object(listener, '_probe_edge', self.probe_edge)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(listener, '_tls_get', self.get)
        patcher.start()
        self.addCleanup(patcher.stop)

    @contextmanager
    def probe_edge(self, config, marker, *, live=False):
        self.assertIs(config, self.config)
        self.assertEqual(marker, b'protected fixture marker')
        self.assertTrue(live)
        yield self.edge, {'invocationId': 'd' * 32}, self.edge_check
        self.edge_check()

    def edge_check(self):
        if not self.available:
            raise ValueError('Edge unavailable')

    def get(self, origin, context, path, content_type, cookie=None, *, retained=None):
        self.assertEqual(origin, ORIGIN)
        self.assertIs(context, self)
        self.assertIs(retained, self.edge)
        self.calls.append((path, content_type, cookie))
        if '/recovery-assets/' in path:
            return 200, ASSETS[path.rsplit('/', 1)[-1]], [], CERT
        return self.landing if cookie is None else self.options

    def portal(self):
        return listener.controller_handoff_portal(self.config, b'protected fixture marker', {name: listener.digest(body) for name, body in ASSETS.items()})

    def test_live_paired_landing_and_both_enrolled_methods(self):
        proof = self.portal()
        self.assertEqual(proof, {'certificateSha256': CERT, 'optionsSha256': listener.digest(listener.encoded(OPTIONS)),
                                 'attachment': self.edge.reference, 'invocationId': 'd' * 32})
        self.assertEqual(self.calls, [
            ('/sentinel/recovery/', 'text/html; charset=utf-8', None),
            ('/sentinel/recovery-assets/recovery.css', 'text/css; charset=utf-8', None),
            ('/sentinel/recovery-assets/recovery.js', 'text/javascript; charset=utf-8', None),
            ('/sentinel/recovery/api/v1/options', 'application/json; charset=utf-8',
             f'__Host-orbis-sentinel-binding={BINDING}'),
        ])

    def test_held_witness_rechecks_edge_before_effect_and_at_exit(self):
        assets = {name: listener.digest(body) for name, body in ASSETS.items()}
        with self.assertRaises(ValueError):
            with listener.held_controller_handoff_portal(self.config, b'protected fixture marker', assets) as (_, check):
                self.available = False
                check()
        self.available = True
        with self.assertRaises(ValueError):
            with listener.held_controller_handoff_portal(self.config, b'protected fixture marker', assets):
                self.available = False

    def test_without_each_existing_signin_method_readiness_is_refused(self):
        for field in ('password', 'recoveryKey'):
            with self.subTest(field=field):
                self.options = (200, listener.encoded({**OPTIONS, field: False}), [], CERT)
                with self.assertRaises(ValueError):
                    self.portal()

    def test_noncanonical_portal_or_changed_certificate_is_refused(self):
        self.landing = (200, b'a different service', [COOKIE], CERT)
        with self.assertRaises(ValueError):
            self.portal()
        self.landing = (200, LANDING, [COOKIE], CERT)
        self.options = (200, listener.encoded(OPTIONS), [], 'e' * 64)
        with self.assertRaises(ValueError):
            self.portal()

    def test_does_not_accept_auth_side_effect_or_incomplete_setup(self):
        for response in [(200, listener.encoded(OPTIONS), [COOKIE], CERT), (401, b'{}', [], CERT)]:
            with self.subTest(status=response[0]):
                self.options = response
                with self.assertRaises(ValueError):
                    self.portal()


if __name__ == '__main__':
    unittest.main()
