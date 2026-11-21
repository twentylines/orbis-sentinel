"""Exact retained HTTPS certificate preparation, selection and rotation."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from orbis_sentinel import recovery_https_edge as edge, recovery_https_install as install, recovery_sessions, runtime
from orbis_sentinel.bootstrap_source import PrivateDirectory, decode, digest, encoded


SOURCE = Path(__file__).resolve().parents[1]
INSTALL = 'a' * 64
ROTATE = 'b' * 64
OTHER = 'c' * 64
HOSTNAME = 'independent.test'


class EdgeEffectiveProfileTests(unittest.TestCase):
    launcher = '/opt/orbis-sentinel/current/bin/orbis-sentinel'
    launch = f'/usr/bin/python3 -I {launcher} --recovery-https-edge'
    literal = '/usr/bin/python3 -I ${ORBIS_SENTINEL_EDGE_RUNTIME} --recovery-https-edge'
    recorded = ' ; start_time=[Sat 2026-11-21 01:02:03 UTC] ; stop_time=[n/a] ; pid=901 ; code=(null) ; status=0/0'
    cleared = ' ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0'

    @staticmethod
    def report(argv, metadata):
        return '{ path=/usr/bin/python3 ; argv[]=' + argv + ' ; ignore_errors=no' + metadata + ' }'

    def setUp(self):
        self.package = {'launcher':self.launcher}
        self.request = {'operationId':'f'*64,'profile':{'bind':'127.0.0.1','origin':'https://127.0.0.1:9443'}}
        public = SimpleNamespace(package=self.package,request=self.request)
        packet = {'operationId':'a'*64,'pairId':'b'*64,'installationId':'c'*64,'markerSha256':'d'*64,'pairSha256':'e'*64}
        self.attachment = install.EdgeAttachment(packet,public,SimpleNamespace(path=Path('/synthetic-edge-fixture')))
        self.service = {'LoadState':'loaded','ActiveState':'active','FragmentPath':str(install.UNIT_ROOT/install.SERVICE),
            'DropInPaths':str(self.attachment.dropin),'NeedDaemonReload':'no','DynamicUser':'yes',
            'User':'orbis-sentinel-https','Group':'orbis-sentinel-https','NoNewPrivileges':'yes',
            'CapabilityBoundingSet':'','ProtectHome':'yes','ProtectSystem':'strict','MainPID':'901','InvocationID':'a'*32,
            'ExecStart':self.report(self.literal,self.recorded)}
        self.socket = {'LoadState':'loaded','ActiveState':'active','FragmentPath':str(install.UNIT_ROOT/install.SOCKET),
            'DropInPaths':str(install.UNIT_ROOT/(install.SOCKET+'.d')/'10-installation.conf'),'NeedDaemonReload':'no',
            'Listen':'127.0.0.1:9443 (Stream)','Accept':'no','FileDescriptorName':'recovery-https'}
        self.system = install.EdgeSystem()
        patches = (
            mock.patch.object(self.system,'verify_files'),
            mock.patch.object(self.system,'show',side_effect=lambda name, _: (self.service if name==install.SERVICE else self.socket).copy()),
            mock.patch.object(self.attachment,'verify_files'),
            mock.patch.object(self.attachment,'loaded_credentials'),
            mock.patch.object(install,'_worker_identity',side_effect=lambda facts, _: (facts['MainPID'],facts['InvocationID'],'12345')),
            mock.patch.object(install,'socket_identity',return_value={'inode':912,'fd':3,'address':'127.0.0.1','port':9443}),
        )
        for fixture in patches:
            fixture.start()
            self.addCleanup(fixture.stop)

    def test_same_worker_and_approved_command_survive_exec_status_reset(self):
        before = self.attachment.observe(self.system)
        for argv, status in ((self.literal,self.cleared),(self.launch,self.recorded),(self.launch,self.cleared),
                            (self.launch,'')):
            with self.subTest(argv=argv,status=status):
                self.service['ExecStart'] = self.report(argv,status)
                self.assertEqual(self.attachment.observe(self.system),before)
        self.service['InvocationID'] = 'b'*32
        self.assertNotEqual(self.attachment.observe(self.system),before)
        self.attachment.loaded_credentials.assert_called_with(901,self.attachment)

    def test_foreign_command_execution_policy_and_security_fields_are_refused(self):
        original = self.service.copy()
        for field, value in (
            ('ExecStart',self.report(self.launch+' --foreign',self.cleared)),
            ('ExecStart',self.report(self.launch.replace(self.launcher,'/tmp/foreign'),self.cleared)),
            ('ExecStart',self.report(self.launch,self.cleared).replace('ignore_errors=no','ignore_errors=yes')),
            ('ExecStart',self.report(self.launch,self.cleared).replace('path=/usr/bin/python3','path=/usr/bin/python')),
            ('ExecStart',self.report(self.launch,self.cleared+' ; foreign=yes')),
            ('NoNewPrivileges','no'),('ProtectSystem','no'),('DropInPaths','/tmp/foreign.conf'),
        ):
            with self.subTest(field=field,value=value):
                self.service = {**original,field:value}
                with self.assertRaises(ValueError):
                    self.attachment.observe(self.system)

    def test_rollback_gate_refuses_raw_plan_and_accepts_same_canonical_worker(self):
        observed = self.attachment.observe(self.system)
        legacy = {**observed,'effectiveSha256':digest(encoded(self.service))}
        self.assertNotEqual(legacy,observed)
        fake_pins = mock.MagicMock()
        fake_pins.directory.return_value = 12
        authorize = mock.Mock()
        with (mock.patch.object(install,'_read',return_value=encoded(self.attachment.value())),
              mock.patch.object(install,'_read_fixed',return_value=self.attachment.bytes()),
              mock.patch.object(install.publisher,'_Pins',return_value=fake_pins),
              mock.patch.object(install.os,'listdir',return_value=[install.ATTACH_DROPIN]),
              mock.patch.object(install.os,'unlink') as unlink):
            with self.assertRaises(ValueError):
                self.attachment.rollback(self.system,legacy,authorize)
            unlink.assert_not_called()
            authorize.assert_called_once_with()
            authorize.reset_mock()
            self.service['ExecStart'] = self.report(self.launch,self.cleared)
            unlink.side_effect = OSError('fixture reached the approved removal, before writing')
            with self.assertRaisesRegex(OSError,'approved removal'):
                self.attachment.rollback(self.system,observed,authorize)
            unlink.assert_called_once_with(self.attachment.dropin.name,dir_fd=12)
            self.assertEqual(authorize.call_count,2)


class SimulatedUnits:
    """Real generated/validated keys, controlled systemd state and served-leaf readback."""

    def __init__(self, root):
        self.root = root
        self.events = []
        self.configured = False
        self.started = False
        self.enabled = False
        self.serving = None
        self.lose_restart = False
        self.wrong_candidate = None
        self.lost_enable_reply = False
        self.expired = set()
        self.expired_checks = []

    def assert_vacant(self, request):
        if self.configured or self.started:
            raise ValueError('Fixture found an existing service')

    def verify_files(self, package, request):
        if not self.configured:
            raise ValueError('Fixture files not set')

    def configure(self, package, request):
        if not self.configured:
            self.events.append('configure')
        self.configured = True

    def _select(self):
        return (self.root / 'active').resolve().name

    def start(self, package, request):
        if not self.started:
            self.events.append('start')
            self.started = True
            self.serving = self._select()

    def prove(self, package, request, generation, *, retry=False):
        if self.serving in self.expired:
            raise ssl.SSLCertVerificationError('Fixture owned leaf expired')
        return self.presented(package, request)

    def prove_expired(self, package, request, generation, metadata):
        self.expired_checks.append(generation.path.name)
        if self.serving != generation.path.name or self.serving not in self.expired:
            raise ValueError('Fixture expired-custody proof crossed generation')
        return self.presented(package, request)

    def presented(self, package, request):
        self.verify_files(package, request)
        if not self.started or self.serving is None:
            raise OSError('Fixture endpoint absent')
        if self.serving == self.wrong_candidate:
            return '0' * 64
        chain = self.root / 'generations' / self.serving / 'chain.pem'
        return install._certificate_sha(chain.read_bytes())

    def restart(self, package, request):
        self.events.append('restart')
        self.serving = self._select()
        if self.lose_restart:
            self.lose_restart = False
            raise OSError('Fixture lost successful restart reply')

    def enable(self, package, request):
        if not self.enabled:
            self.events.append('enable')
            self.enabled = True
            if self.lost_enable_reply:
                self.lost_enable_reply = False
                raise OSError('Fixture lost successful enable reply')


class InstallerTests(unittest.TestCase):
    def setUp(self):
        area = tempfile.TemporaryDirectory(prefix='https-install-')
        self.addCleanup(area.cleanup)
        self.area = Path(area.name).resolve()
        self.state = self.area / 'edge'
        self.state.mkdir(mode=0o700)
        (self.state / 'operations').mkdir(mode=0o700)
        self.main = self.area / 'installation'
        self.main.mkdir(mode=0o700)
        self.main_identity = install._InstallationDirectory(self.main)
        self.addCleanup(self.main_identity.close)
        tool = shutil.which('openssl')
        if tool is None:
            self.skipTest('OpenSSL is required for certificate generation tests')
        self.start(mock.patch.object(install, 'SSL_TOOL', tool))
        self.start(mock.patch.object(install, 'STATE', self.state))
        self.start(mock.patch.object(recovery_sessions, '_OWNER_UID', os.getuid()))
        self.profile = {'schema': edge.PROFILE, 'origin': 'https://' + HOSTNAME + ':9443',
                        'bind': '192.168.50.2', 'allow': '192.168.50.0/24', 'upstreamPort': 9444}
        self.system = SimulatedUnits(self.state)
        self.package = {'launcher': '/fixed/selected/bin/orbis-sentinel',
                        'binding': {'version': '1.0.0', 'packageSha256': '3' * 64,
                                    'sourceCommit': '4' * 40, 'profileSha256': '5' * 64}}
        self.package_valid = True
        self.writer = install.EdgeInstall(self.check_package, self.system)

        @contextmanager
        def selection():
            yield self.package, self.check_package
        self.start(mock.patch.object(self.writer, '_package', side_effect=selection))

    def start(self, patch):
        self.addCleanup(patch.stop)
        return patch.start()

    def check_package(self):
        if not self.package_valid:
            raise ValueError('Fixture selected package changed')

    @staticmethod
    def write(path, body):
        path.write_bytes(body)
        path.chmod(0o600)

    def draft(self, operation, *, previous=None, mode='local', **overrides):
        folder = self.state / 'operations' / operation
        folder.mkdir(mode=0o700)
        binding = {'root': str(self.main), 'context': 'default', 'daemon': 'installation-fixture'}
        request = {'schema': install.REQUEST, 'operationId': operation, **binding,
                   'installationId': digest(encoded({**binding, 'rootIdentity': self.main_identity.identity})),
                   'profile': self.profile, 'mode': mode, 'previous': previous,
                   'dashboardHosts': ['dashboard.test'], 'dashboardHttpsPorts': [443], **overrides}
        self.write(folder / 'request.json', encoded(request))
        return folder, request

    def approve(self, operation, folder, request):
        review = self.writer.review(operation)
        self.assertEqual(review['phase'], 'https-awaits-approval')
        self.assertFalse((folder / 'approval.json').exists())
        approved = encoded({'schema': install.APPROVAL, 'operationId': operation, 'installationId': request['installationId'],
                            'reviewSha256': review['reviewSha256'], 'approvalId': '6' * 64})
        self.write(folder / 'approval.json', approved)
        return operation, review['reviewSha256'], digest(approved)

    def initial(self):
        folder, request = self.draft(INSTALL)
        return self.approve(INSTALL, folder, request)

    def rotation(self, prior, operation=ROTATE, **kwargs):
        folder, request = self.draft(operation, previous={'generation': prior['operationId'],
            'receiptSha256': prior['receiptSha256']}, **kwargs)
        return self.approve(operation, folder, request)

    def test_pending_or_committed_backend_attachment_holds_ordinary_rotation(self):
        directory,request = self.draft(INSTALL)
        args = self.approve(INSTALL,directory,request)
        self.writer.apply(*args)
        for name in ('.'+install.ATTACHMENT+'.pending',install.ATTACHMENT):
            path = self.state/name
            self.write(path,b'protected attachment')
            with self.assertRaises(ValueError):
                self.writer.apply(*args)
            path.unlink()
        self.assertEqual((self.state/'active').readlink(),Path('generations')/INSTALL)

    def test_install_operation_creates_retained_chain_and_only_exports_the_verified_public_CA(self):
        params = self.initial()
        result = self.writer.apply(*params)
        self.assertEqual(self.writer.apply(*params), result)
        self.assertEqual(self.system.events, ['configure', 'start', 'enable'])
        self.assertFalse((self.state / 'writer-fence.json').exists())
        active = self.state / 'generations' / INSTALL
        export = self.writer.export_ca(INSTALL)
        self.assertEqual(export['origin'], self.profile['origin'])
        self.assertEqual(export['receiptSha256'], result['receiptSha256'])
        self.assertEqual(export['caCertificateSha256'], digest(ssl.PEM_cert_to_DER_cert(export['caCertificatePem'])))
        self.assertEqual(set(export), {'origin', 'caCertificatePem', 'caCertificateSha256', 'leafExpiresAtSec', 'receiptSha256'})
        self.assertGreater(export['leafExpiresAtSec'], time.time() + 86400)
        self.assertTrue(export['caCertificatePem'].startswith('-----BEGIN CERTIFICATE-----'))
        self.assertEqual(active.joinpath('trust.pem').read_text(), export['caCertificatePem'])
        for key in (active / 'key.pem', self.state / 'authority' / 'ca-key.pem'):
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(key.read_text(), str(export))
        self.assertEqual(install._cert_context(type('Directory', (), {'path': active})(), 'local').verify_mode, ssl.CERT_REQUIRED)

        serving = edge.server_context(str(active / 'chain.pem'), str(active / 'key.pem'), HOSTNAME)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(2)
            errors = []

            def handshake():
                try:
                    with listener.accept()[0] as client:
                        client.settimeout(2)
                        with serving.wrap_socket(client, server_side=True):
                            pass
                except Exception as error:
                    errors.append(error)

            server = threading.Thread(target=handshake)
            server.start()
            try:
                context = ssl.create_default_context(cadata=export['caCertificatePem'])
                live = {**self.profile, 'bind': '127.0.0.1', 'origin': f'https://{HOSTNAME}:{listener.getsockname()[1]}'}
                self.assertEqual(install._wire_fingerprint(live, context, time.monotonic() + 3),
                                 install._certificate_sha((active / 'chain.pem').read_bytes()))
            finally:
                server.join(3)
            self.assertFalse(server.is_alive())
            self.assertEqual(errors, [])

    def test_dedicated_host_refuses_declared_same_name_or_port_without_claiming_ingress_admission(self):
        folder, _ = self.draft(INSTALL, dashboardHosts=[HOSTNAME.upper() + '.'])
        with self.assertRaises(ValueError):
            self.writer.review(INSTALL)
        content = decode((folder / 'request.json').read_bytes())
        self.write(folder / 'request.json', encoded({**content, 'dashboardHosts': ['dashboard.test'], 'dashboardHttpsPorts': [9443]}))
        with self.assertRaises(ValueError):
            self.writer.review(INSTALL)
        self.assertFalse((folder / 'review.json').exists())
        self.assertFalse((self.state / 'authority').exists())

    def test_dynamic_systemd_principal_cannot_reuse_any_existing_UID_or_group(self):
        request = {'profile': self.profile}
        with mock.patch.object(install.pwd, 'getpwnam', return_value=object()) as user, self.assertRaises(ValueError):
            install.EdgeSystem().assert_vacant(request)
        user.assert_called_once_with(edge.PRINCIPAL)
        with (mock.patch.object(install.pwd, 'getpwnam', side_effect=KeyError),
              mock.patch.object(install.grp, 'getgrnam', return_value=object()) as group, self.assertRaises(ValueError)):
            install.EdgeSystem().assert_vacant(request)
        group.assert_called_once_with(edge.PRINCIPAL)

    def test_crossed_approval_and_substituted_physical_installation_have_no_effect(self):
        apply = self.initial()
        with self.assertRaises(ValueError):
            self.writer.apply(*apply[:-1], 'f' * 64)
        old = self.main.with_name('preserved')
        self.main.rename(old)
        self.main.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.writer.apply(*apply)
        self.assertFalse((self.state / 'authority').exists())
        self.assertEqual(self.system.events, [])

    def test_interrupted_generation_reuses_existing_private_material(self):
        params = self.initial()
        with mock.patch.object(install, '_issue', side_effect=OSError('Fixture interrupted certificate issue')):
            with self.assertRaises(OSError):
                self.writer.apply(*params)
        ca_path = self.state / 'authority' / 'ca-key.pem'
        leaf_path = self.state / 'generations' / INSTALL / 'key.pem'
        ca, leaf = ca_path.read_bytes(), leaf_path.read_bytes()
        self.draft(OTHER)
        with self.assertRaises(ValueError):
            self.writer.review(OTHER)
        with mock.patch.object(install, '_key', side_effect=AssertionError('Existing key was regenerated')):
            self.assertEqual(self.writer.apply(*params)['phase'], 'https-transport-verified')
        self.assertEqual((ca_path.read_bytes(), leaf_path.read_bytes()), (ca, leaf))

    def test_leaf_rotation_keeps_CA_and_previous_chain_bytes_and_never_restarts_socket(self):
        first = self.writer.apply(*self.initial())
        old = self.state / 'generations' / INSTALL
        exact = {file.name: file.read_bytes() for file in old.iterdir()}
        ca = self.writer.export_ca(INSTALL)
        updated = self.writer.apply(*self.rotation(first))
        self.assertEqual(updated['phase'], 'https-transport-verified')
        self.assertEqual(self.system.events, ['configure', 'start', 'enable', 'restart'])
        self.assertEqual({file.name: file.read_bytes() for file in old.iterdir()}, exact)
        export = self.writer.export_ca(ROTATE)
        self.assertEqual(export['caCertificateSha256'], ca['caCertificateSha256'])
        self.assertNotEqual((self.state / 'generations' / ROTATE / 'chain.pem').read_bytes(), exact['chain.pem'])
        with self.assertRaises(ValueError):
            self.writer.export_ca(INSTALL)

    def test_rotation_missing_prior_CA_key_does_not_generate_a_replacement(self):
        first = self.writer.apply(*self.initial())
        args = self.rotation(first)
        ca = self.state / 'authority' / 'ca-key.pem'
        archived = ca.with_name('existing-ca-key.pem')
        ca.rename(archived)
        with mock.patch.object(install, '_key', side_effect=AssertionError('Missing CA key was silently regenerated')):
            with self.assertRaises(FileNotFoundError):
                self.writer.apply(*args)
        self.assertTrue(archived.exists())
        self.assertFalse(ca.exists())
        self.assertEqual((self.state / 'active').resolve().name, INSTALL)

    def test_expired_owned_leaf_rotates_with_exact_custody_and_strict_successor_trust(self):
        first = self.writer.apply(*self.initial())
        args = self.rotation(first)
        meta = decode((self.state / 'generations' / INSTALL / 'facts.json').read_bytes())
        self.system.expired.add(INSTALL)
        with mock.patch.object(install, '_expired', side_effect=lambda facts: facts == meta):
            self.assertEqual(self.writer.apply(*args)['phase'], 'https-transport-verified')
        self.assertEqual(self.system.expired_checks, [INSTALL, INSTALL])
        self.assertEqual(self.system.serving, ROTATE)
        self.assertEqual(self.system.events.count('restart'), 1)

    def test_failed_rotation_to_wrong_leaf_can_restore_owned_expired_generation_without_a_ready_claim(self):
        first = self.writer.apply(*self.initial())
        args = self.rotation(first)
        meta = decode((self.state / 'generations' / INSTALL / 'facts.json').read_bytes())
        self.system.expired.add(INSTALL)
        self.system.wrong_candidate = ROTATE
        with mock.patch.object(install, '_expired', side_effect=lambda facts: facts == meta):
            result = self.writer.apply(*args)
            self.assertEqual(self.writer.apply(*args), result)
        self.assertEqual(result['phase'], 'https-rotation-rolled-back-expired')
        self.assertEqual(self.system.serving, INSTALL)
        self.assertFalse((self.state / 'operations' / ROTATE / 'complete.json').exists())
        self.assertFalse((self.state / 'writer-fence.json').exists())

    def test_rotation_cannot_rebind_to_a_different_selected_package(self):
        first = self.writer.apply(*self.initial())
        self.package['binding']['sourceCommit'] = '9' * 40
        with self.assertRaises(ValueError):
            self.rotation(first)
        self.assertEqual(self.system.serving, INSTALL)

    def test_failed_presented_leaf_restores_only_exact_previous_generation(self):
        first = self.writer.apply(*self.initial())
        apply = self.rotation(first)
        self.system.wrong_candidate = ROTATE
        result = self.writer.apply(*apply)
        self.assertEqual(result, {'phase': 'https-rotation-rolled-back', 'operationId': ROTATE, 'retainedGeneration': INSTALL})
        self.assertEqual(self.writer.apply(*apply), result)
        self.assertEqual((self.state / 'active').resolve().name, INSTALL)
        self.assertTrue((self.state / 'generations' / ROTATE / 'key.pem').is_file())
        self.assertEqual(self.system.events, ['configure', 'start', 'enable', 'restart', 'restart'])
        self.assertFalse((self.state / 'writer-fence.json').exists())

    def test_lost_restart_reply_observes_new_leaf_without_second_restart(self):
        first = self.writer.apply(*self.initial())
        args = self.rotation(first)
        self.system.lose_restart = True
        with self.assertRaises(OSError):
            self.writer.apply(*args)
        self.assertEqual(self.system.serving, ROTATE)
        self.assertTrue((self.state / 'writer-fence.json').exists())
        result = self.writer.apply(*args)
        self.assertEqual(result['phase'], 'https-transport-verified')
        self.assertEqual(self.system.events.count('restart'), 1)

    def test_lost_final_enabling_reply_preserves_proof_and_reconciles_same_request(self):
        params = self.initial()
        self.system.lost_enable_reply = True
        with self.assertRaises(OSError):
            self.writer.apply(*params)
        self.assertTrue((self.state / 'writer-fence.json').exists())
        self.assertEqual(self.writer.apply(*params)['phase'], 'https-transport-verified')
        self.assertEqual(self.system.events, ['configure', 'start', 'enable'])

    def test_crossed_pending_selector_cannot_be_promoted_or_replaced(self):
        params = self.initial()
        original = install._select

        def torn(root, generation, previous):
            os.symlink('generations/' + OTHER, '.active.pending', dir_fd=root.fd)
            raise OSError('Fixture unexpected staged selector')

        with mock.patch.object(install, '_select', side_effect=torn), self.assertRaises(OSError):
            self.writer.apply(*params)
        with self.assertRaises(ValueError):
            self.writer.apply(*params)
        self.assertEqual(os.readlink(self.state / '.active.pending'), 'generations/' + OTHER)
        self.assertFalse((self.state / 'active').exists())
        self.assertIs(install._select, original)
        self.assertEqual(self.system.events, ['configure'])

    def imported_fixture(self, folder, request, *, wrong_name=False, bad_key=False):
        foreign = self.area / 'fixture-issuer'
        foreign.mkdir(mode=0o700)
        material = self.area / 'fixture-material'
        material.mkdir(mode=0o700)
        with PrivateDirectory(foreign) as authority, PrivateDirectory(material) as directory:
            ca_request = {**request, 'profile': {**request['profile'],
                'origin': 'https://other.test:9443'} if wrong_name else request['profile']}
            trust = install._ca(authority, ca_request)
            self.write(material / 'key.pem', install._key())
            chain = install._issue(directory, authority, ca_request)
        self.write(folder / 'import-chain.pem', chain)
        self.write(folder / 'import-key.pem', install._key() if bad_key else (material / 'key.pem').read_bytes())
        self.ca_fixture = foreign / 'ca.pem'
        return trust, chain

    def fixture_trust(self):
        real_openssl = install._ssl

        def openssl(*args, **kwargs):
            if args[0] == 'verify' and '-CAfile' not in args:
                return real_openssl(*args[:-1], '-CAfile', str(self.ca_fixture), args[-1], **kwargs)
            return real_openssl(*args, **kwargs)
        return mock.patch.object(install, '_ssl', side_effect=openssl)

    def test_explicit_import_binds_only_approved_leaf_and_private_key(self):
        folder, request = self.draft(INSTALL, mode='import')
        trust, chain = self.imported_fixture(folder, request)
        params = self.approve(INSTALL, folder, request)
        source = folder / 'import-chain.pem'
        source.write_bytes(chain + trust)
        with self.assertRaises(ValueError):
            self.writer.apply(*params)
        source.write_bytes(chain)
        with self.fixture_trust():
            result = self.writer.apply(*params)
        self.assertEqual(result['phase'], 'https-transport-verified')
        receipt = decode((folder / 'complete.json').read_bytes())
        self.assertEqual(receipt['scope'], 'https-transport-only')
        self.assertFalse((self.state / 'authority').exists())
        self.assertEqual((self.state / 'generations' / INSTALL / 'chain.pem').read_bytes(), chain)
        with self.assertRaises(ValueError):
            self.writer.export_ca(INSTALL)

    def test_import_refuses_wrong_san_before_any_socket(self):
        folder, request = self.draft(INSTALL, mode='import')
        self.imported_fixture(folder, request, wrong_name=True, bad_key=True)
        params = self.approve(INSTALL, folder, request)
        with self.fixture_trust(), self.assertRaises(ValueError):
            self.writer.apply(*params)
        self.assertEqual(self.system.events, [])
        self.assertTrue((self.state / 'writer-fence.json').exists())

    def test_import_refuses_matching_san_with_wrong_private_key(self):
        folder, request = self.draft(INSTALL, mode='import')
        self.imported_fixture(folder, request, bad_key=True)
        params = self.approve(INSTALL, folder, request)
        with self.fixture_trust(), self.assertRaises(ValueError):
            self.writer.apply(*params)
        self.assertEqual(self.system.events, [])
        self.assertTrue((self.state / 'writer-fence.json').exists())

    def test_import_refuses_locally_untrusted_issuer_without_explicit_fixture_CA(self):
        folder, request = self.draft(INSTALL, mode='import')
        self.imported_fixture(folder, request)
        params = self.approve(INSTALL, folder, request)
        with self.assertRaises(ValueError):
            self.writer.apply(*params)
        self.assertEqual(self.system.events, [])

    def test_CA_with_exact_SAN_and_serverAuth_is_rejected_before_edge_key_custody(self):
        folder, request = self.draft(INSTALL, mode='import')
        key = folder / 'import-key.pem'
        self.write(key, install._key())
        certificate = install._ssl('req', '-new', '-x509', '-key', str(key), '-subj', '/CN=' + HOSTNAME, '-days', '5',
            '-addext', 'subjectAltName=DNS:' + HOSTNAME, '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
            '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign', '-addext', 'extendedKeyUsage=serverAuth')
        self.write(folder / 'import-chain.pem', certificate)
        params = self.approve(INSTALL, folder, request)
        with self.assertRaises(ValueError):
            self.writer.apply(*params)
        self.assertFalse((self.state / 'generations' / INSTALL / 'key.pem').exists())
        self.assertEqual(self.system.events, [])


class PackageAndDispatchTests(unittest.TestCase):
    def test_owned_TLS_probe_shares_one_connect_and_handshake_deadline(self):
        clock, timeouts = [100.0], []
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        connection.settimeout.side_effect = timeouts.append
        connection.connect.side_effect = lambda _: clock.__setitem__(0, 102.4)
        context = mock.MagicMock()
        context.wrap_socket.return_value.__enter__.return_value.getpeercert.return_value = b'certificate'
        config = {'origin': 'https://independent.test:9443', 'bind': '192.168.50.2'}
        with (mock.patch.object(install.socket, 'socket', return_value=connection),
              mock.patch.object(install.time, 'monotonic', side_effect=lambda: clock[0])):
            self.assertEqual(install._wire_fingerprint(config, context, 103.0), digest(b'certificate'))
        self.assertEqual(timeouts[0], 3.0)
        self.assertAlmostEqual(timeouts[1], 0.6)
        context.wrap_socket.assert_called_once_with(connection, server_hostname=HOSTNAME)

    def test_TLS_observation_retry_never_starts_an_attempt_after_its_deadline(self):
        clock = [100.0]
        system = install.EdgeSystem()
        calls = []

        def failed(config, context, deadline):
            calls.append(deadline)
            clock[0] = 107.95
            raise ConnectionRefusedError()

        with (mock.patch.object(system, 'loaded', return_value={'ActiveState': 'inactive'}),
              mock.patch.object(install, '_wire_fingerprint', side_effect=failed),
              mock.patch.object(install.time, 'monotonic', side_effect=lambda: clock[0]),
              mock.patch.object(install.time, 'sleep', side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay))):
            with self.assertRaises(TimeoutError):
                system._prove({'launcher': '/fixed'}, {'profile': {}}, object(), True)
        self.assertEqual(calls, [103.0])

    def test_units_keep_credentials_outside_recovery_and_only_fixed_socket_is_enabled(self):
        service = (SOURCE / 'packaging/systemd' / install.SERVICE).read_text()
        listener = (SOURCE / 'packaging/systemd' / install.SOCKET).read_text()
        self.assertIn('DynamicUser=yes', service)
        self.assertIn('CapabilityBoundingSet=\n', service)
        self.assertIn('RestrictAddressFamilies=AF_INET', service)
        self.assertIn('LoadCredential=edge-key:/var/lib/orbis-sentinel/recovery-https/active/key.pem', service)
        self.assertIn('Require', service)
        self.assertNotIn('ReadWritePaths=', service)
        self.assertNotIn('WantedBy=', service)
        self.assertIn('FileDescriptorName=recovery-https', listener)
        self.assertNotIn('ListenStream=', listener)

    def test_build_and_stage_publish_the_complete_contract_and_not_private_material(self):
        def module(name):
            spec = importlib.util.spec_from_file_location(name, SOURCE / 'packaging' / (name + '.py'))
            result = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(result)
            return result
        build, stage = module('build_release'), module('stage_release')
        with tempfile.TemporaryDirectory(prefix='https-package-') as temporary:
            out = Path(temporary).resolve()
            result = build.build_release(SOURCE, out)
            with Path(result['artifact']).open('rb') as handle:
                files, manifest, initializer, native_https = stage._scan(handle)
            self.assertTrue(native_https)
            stage._manifest(files, manifest, initializer, result['version'], runtime_https=native_https)
            self.assertEqual(set(manifest['files']).intersection(build.RECOVERY_HTTPS_MEMBERS), build.RECOVERY_HTTPS_MEMBERS)
            candidate = 'packaging/systemd/' + install.SOCKET
            changed = {**manifest, 'files': {k: v for k, v in manifest['files'].items() if k != candidate}}
            with self.assertRaises(stage.StageError):
                stage._manifest({k:v for k,v in files.items() if k != candidate}, changed, initializer, result['version'],
                                runtime_https=native_https)
            absent = {**manifest, 'files': {key: value for key, value in manifest['files'].items()
                                           if key not in build.RECOVERY_HTTPS_MEMBERS}}
            with self.assertRaises(stage.StageError):
                stage._manifest({key: value for key, value in files.items() if key not in build.RECOVERY_HTTPS_MEMBERS},
                                absent, initializer, result['version'], runtime_https=native_https)
            self.assertFalse(any(name.endswith('.pem') or 'HANDOFF' in name for name in files))

            small = out / 'small-source'
            for name in (*('bin/' + item for item in build.ENTRYPOINTS), 'LICENSE', 'src/orbis_sentinel/__init__.py',
                         'src/orbis_sentinel/runtime.py', 'packaging/systemd/orbis-sentinel.service',
                         'packaging/systemd/orbis-sentinel.socket'):
                to = small / name
                to.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE / name, to)
            (small / 'web').mkdir()
            (small / 'packaging/sysusers.d').mkdir()
            with self.assertRaisesRegex(ValueError, 'runtime requires'):
                build.build_release(small, out / 'incomplete')

    def test_runtime_fixed_commands_cannot_supply_tls_target_or_pass_wrong_approval(self):
        with mock.patch.object(runtime, '_run_https_install', return_value=0) as run:
            self.assertEqual(runtime.main(('--export-recovery-https-ca', INSTALL)), 0)
            run.assert_called_once_with('export-ca', INSTALL, None, None)
        with redirect_stderr(io.StringIO()):
            for args in (('--recovery-https-edge', '--disk-path', '/'),
                         ('--apply-recovery-https', INSTALL, '--https-review-sha256', ROTATE),
                         ('--review-recovery-https', INSTALL, '--publisher-receipt-sha256', OTHER)):
                with self.subTest(args=args), self.assertRaises(SystemExit):
                    runtime.main(args)
        with mock.patch.object(edge, 'main', return_value=0) as serve, redirect_stdout(io.StringIO()):
            self.assertEqual(runtime.main(('--recovery-https-edge',)), 0)
            serve.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
