"""Retain one private mutual-TLS generation for the installed recovery listener."""

from contextlib import ExitStack, closing, contextmanager
import os
from pathlib import Path
import select
import ssl
import subprocess
import sys
import tempfile
import time

from . import host_source_publication as publisher
from .bootstrap_source import PrivateDirectory, PrivateFile, decode, digest, encoded, fail, hash_value
from .writer_journal import mount_id

LISTENER_ROOT = Path('/etc/orbis-sentinel/recovery-backend')
AUTHORITY_ROOT = Path('/root/.local/state/orbis-sentinel/recovery-backend')
SERVER_NAME = 'sentinel-loopback.invalid'
CLIENT_NAME = 'sentinel-edge.invalid'
MODE = 'builtin-private-tls.v1'
PAIR = 'orbis.sentinel-recovery-backend-pair.v1'
IDENTITY = 'orbis.sentinel-recovery-backend-authority.v1'
MANIFEST = 'pair.json'
MAX_CERT = 16384
MAX_KEY = 16384
LISTENER_FILES = {'server.pem', 'server-key.pem', 'ca.pem', MANIFEST}
AUTHORITY_FILES = {'ca.pem', 'ca-key.pem', 'client.pem', 'client-key.pem', 'client.cnf', 'server.cnf',
                   'authority.json', MANIFEST}


def _document(body):
    value = decode(body)
    if type(value) is not dict or encoded(value) != body:
        fail()
    return value


@contextmanager
def retained_origin(namespace, admission, product, source, operation, receipt_sha):
    """Reopen exact Orbis 2A terminal under the already-held B/D1 Host scope."""
    from .recovery_worker_provision import _subdirectory

    if not hash_value(operation) or not hash_value(receipt_sha):
        fail()
    with (ExitStack() as resources, _subdirectory(namespace, product.ORIGIN_OPERATIONS) as operations,
          _subdirectory(operations, operation) as folder, closing(publisher._Pins()) as pins):
        held = []

        def take(name, *, directory=folder, maximum=65536):
            handle = resources.enter_context(PrivateFile(directory, name, maximum))
            if mount_id(handle.fd) != mount_id(directory.fd):
                fail()
            held.append(handle)
            return handle.body

        complete_body = take('complete.json')
        review_body, approval_body = take('review.json'), take('approval.json')
        complete, review, approval = map(_document, (complete_body, review_body, approval_body))
        request = _document(take('request.json'))
        plan_body = take('v1-plan.json')
        plan = _document(plan_body)
        ready = _document(take('v1-ready.json'))
        ingress_body = take('ingress-receipt.json')
        ingress = _document(ingress_body)
        prior = take('prior-history.json')
        prior_config = take('prior-admission.json')
        prior_env = take('prior-environment.json', maximum=product.MAXIMUM)
        binding = {'operationId': operation, 'installationId': source['scope']['installationId'],
                   'reviewSha256': digest(review_body), 'approvalSha256': digest(approval_body)}
        source_main = source['main']
        main = {key:source_main[key] for key in ('id','imageId','publicationSha256','definitionSha256','protocol')}
        scope = source['scope']
        origin = scope['origin']
        expected_request = admission.request('unmanaged', origin, unmanaged_adoption=True)
        if (digest(complete_body) != receipt_sha or complete.get('schema') != product.ORIGIN_COMPLETE
                or any(complete.get(key) != value for key, value in {**binding,'main':main,'origin':origin}.items())
                or (source_main.get('storageRestartPolicy') not in ('','no'))
                or review.get('schema') != product.ORIGIN_REVIEW or review['operationId'] != operation
                or any(review[key] != scope[key] for key in ('root','context','origin','installationId'))
                or any(request[key] != scope[key] for key in ('root','context','origin','installationId','daemon'))
                or request['operationId'] != operation or review['requestSha256'] != digest(encoded(request))
                or approval != {'schema': product.ORIGIN_APPROVAL, **{key:binding[key] for key in
                    ('operationId','installationId','reviewSha256')}, 'approvalId':approval.get('approvalId')}
                or not hash_value(approval['approvalId'])
                or _document(take('intent.json')) != {'schema':product.ORIGIN_INTENT, **binding}
                or any(os.path.lexists(folder.path/name) for name in ('aborted.json','abort-intent.json','ingress-failed.json'))
                or plan['schema'] != product.SCHEMA or plan['request'] != expected_request or plan['managedEver'] is not False
                or plan['dependencies']['main'] != main or plan['dependencies']['installationId'] != scope['installationId']
                or plan['dependencies']['sentinel'] != source['runtime']
                or plan['previousGeneration'] != decode(prior)['generation']
                or decode(prior)['managedEver'] is not False or decode(prior)['installationId'] != scope['installationId']
                or digest(prior) != plan['previousHistorySha256'] or digest(prior) != review['oldHistorySha256']
                or digest(prior_config) != plan['previousConfigSha256'] or digest(prior_config) != review['oldAdmissionSha256']
                or decode(prior)['configSha256'] != digest(prior_config) or digest(prior_env) != review['oldEnvironmentSha256']
                or ready != {'schema':product.ORIGIN_READY, **binding, 'main':main, 'origin':origin,
                            'planSha256':digest(plan_body), 'envSha256':review['newEnvironmentSha256']}
                or ingress.get('schema') != product.ORIGIN_INGRESS or ingress['ingress'] != review['ingress']
                or ingress['edge'] != review['edge'] or any(ingress.get(key) != value for key,value in binding.items())):
            fail()
        authorization_sha = complete.get('v1AuthorizationSha256')
        if not hash_value(authorization_sha):
            fail()
        approvals = resources.enter_context(_subdirectory(namespace, 'recovery-admission-approvals'))
        authorization = take(operation+'.json', directory=approvals, maximum=16384)
        if digest(authorization) != authorization_sha:
            fail()
        auth = admission._authorization(approvals.path/(operation+'.json'), authorization_sha, plan)
        result = admission._candidate(plan)
        successor = admission._desired(plan, result)
        archive_id = digest(encoded({'plan':digest(plan_body),'authorization':authorization_sha}))
        archive = take('recovery-admission-'+archive_id+'.json', directory=namespace)
        terminal = decode(archive)
        if (terminal.get('phase') != 'complete' or terminal.get('operationId') != archive_id
                or terminal.get('plan') != plan or terminal.get('authorization') != auth
                or terminal.get('history') != successor or terminal.get('candidate') != result
                or complete != {'schema':product.ORIGIN_COMPLETE, **binding, 'origin':origin, 'main':main,
                    'envSha256':ready['envSha256'], 'planSha256':digest(plan_body),
                    'historySha256':digest(product._encoded(successor)), 'admissionSha256':digest(product._encoded(result)),
                    'v1ArchiveSha256':digest(archive), 'v1AuthorizationSha256':authorization_sha}
                or (complete['historySha256'],complete['admissionSha256']) != (source['historySha256'],source['configSha256'])):
            fail()

        def exact_copy(_plan, evidence):
            observed = evidence.observation
            if (evidence.receipt_sha256 != source['publication']['receiptSha256']
                    or observed.get('schema') != publisher.SCHEMA_CUSTODY
                    or observed.get('copyCustodySha256') != review['custody']['hostCopySha256']):
                fail()

        evidence = resources.enter_context(publisher._completed(source['publication']['operationId'], exact_copy))
        environment = pins.file(admission.service.root/'.env', product.MAXIMUM, 0o600)
        if digest(environment) != complete['envSha256']:
            fail()
        observations = product.OriginObservations(admission.service)
        actor = product.OriginTransition(admission, observations)
        pinned_edge = review['edge']
        prepared_main = None
        if os.path.lexists(folder.path/'candidate.json'):
            prepared_main = _document(take('candidate.json'))
            if (set(prepared_main) != {'id','definitionSha256','networksSha256'}
                    or any(prepared_main[key] != main[key] for key in ('id','definitionSha256'))
                    or not hash_value(prepared_main['networksSha256'])):
                fail()
        elif (review['oldOrigin'] != origin or review['oldEnvironmentSha256'] != review['newEnvironmentSha256']
              or review['priorOriginFields'] != {'dotenv':True,'container':True}
              or review['priorMain']['id'] != main['id']):
            fail()
        networks = prepared_main['networksSha256'] if prepared_main is not None else review['priorMain']['networksSha256']

        def check():
            evidence.recheck()
            pins.verify()
            for handle in held:
                handle.verify()
            if any(name.endswith('.pending') for name in os.listdir(folder.fd)):
                fail()
            actor._stopped(folder.fd, request, review, binding)
            raw = observations.named('runtipi')
            (product._origin_never_started if prepared_main is not None else product._origin_stopped)(raw)
            if (raw['Id'] != main['id'] or product._origin_definition(raw) != main['definitionSha256']
                    or digest(encoded(product._origin_networks(raw, observations.network))) != networks):
                fail()

        check()
        yield {'operationId':operation,'receiptSha256':receipt_sha, 'ingressSha256':digest(ingress_body),
               'publicEdge':pinned_edge}, check
        check()


def binding_for(plan, intent):
    return {'schema':IDENTITY, 'operationId':plan['operationId'], 'pairId':plan['transport']['pairId'],
            'installationId':plan['scope']['installationId'], 'origin':plan['scope']['origin'],
            'listenPort':plan['listenPort'], 'reviewSha256':intent['reviewSha256'],
            'approvalSha256':intent['approvalSha256'], 'markerSha256':plan['markerSha256'],
            'configSha256':plan['configSha256'],'scopeSha256':digest(encoded(plan['transport']))}


def _certificate(value):
    from .recovery_https_install import _certificates
    certs = _certificates(value)
    if len(certs) != 1 or certs[0] != value:
        fail()
    return ssl.PEM_cert_to_DER_cert(value.decode('ascii'))


def _extension(role, name):
    return ('[leaf]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
            'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
            f'extendedKeyUsage={role}Auth\nsubjectAltName=DNS:{name}\n').encode('ascii')


def _require_extensions(certificate, expected):
    from .recovery_https_install import _ssl

    text = _ssl('x509','-noout','-text',value=certificate)
    lines = text.decode('ascii').splitlines()
    for label, value in expected.items():
        indexes = [index for index,line in enumerate(lines) if line.strip() == 'X509v3 '+label]
        if len(indexes) != 1 or indexes[0] + 1 >= len(lines) or lines[indexes[0]+1].strip() != value:
            fail()


def _new_key():
    from .recovery_https_install import _ssl

    return _ssl('genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256',
                '-pkeyopt','ec_param_enc:named_curve')


def _inspect_key(body):
    from .recovery_https_install import _ssl

    # Require the complete canonical, unencrypted PKCS#8 encoding generated here.
    # OpenSSL can otherwise accept a valid key followed by ignored extra data.
    if _ssl('pkey','-passin','pass:','-outform','PEM',value=body) != body:
        fail()
    public = _ssl('pkey','-passin','pass:','-pubout','-outform','DER',value=body)
    text = _ssl('pkey','-pubin','-inform','DER','-noout','-text_pub',value=public)
    if b'ASN1 OID: prime256v1' not in text or len(public) != 91:
        fail()
    return public


def _serial(pair, role):
    return digest(encoded([pair,role]))[:36]


def _serial_is(certificate, pair, role):
    from .recovery_https_install import _ssl

    serial = _ssl('x509','-noout','-serial',value=certificate).strip()
    if not serial.startswith(b'serial=') or int(serial[7:],16) != int(_serial(pair,role),16):
        fail()


def _validity(certificate):
    from .recovery_https_install import _ssl

    lines = _ssl('x509','-noout','-dates',value=certificate).decode('ascii').splitlines()
    output = {}
    for line in lines:
        key, sep, value = line.partition('=')
        if not sep or key not in ('notBefore','notAfter') or key in output:
            fail()
        output[key] = ssl.cert_time_to_seconds(value)
    if set(output) != {'notBefore','notAfter'}:
        fail()
    _current(output['notBefore'],output['notAfter'])
    return output['notBefore'],output['notAfter']


def _current(before, after):
    if type(before) is not int or type(after) is not int or not 0 < before <= time.time() < after:
        fail()


def _purpose(cert, authority, role, path):
    from .recovery_https_install import CONTROL_ENV, SSL_TOOL

    if sys.platform == 'linux':
        fixture = os.fdopen(os.memfd_create('orbis-recovery-public-ca',os.MFD_CLOEXEC),'w+b')
        descriptors = '/proc/self/fd'
    else:
        fixture = tempfile.TemporaryFile(dir=path)
        descriptors = '/dev/fd'
    with fixture as handle:
        handle.write(authority)
        handle.flush()
        handle.seek(0)
        output = subprocess.run([SSL_TOOL,'verify','-x509_strict','-check_ss_sig','-purpose',role,'-trusted',
                                 f'{descriptors}/{handle.fileno()}'],input=cert,capture_output=True,
                                timeout=12,check=False,env=CONTROL_ENV,pass_fds=(handle.fileno(),))
    if output.returncode or len(output.stdout) > 16384 or len(output.stderr) > 8192 or not output.stdout.rstrip().endswith(b': OK'):
        fail()


def _validate_authority(certificate, key_body, pair, path):
    from .recovery_https_install import _ssl

    ca_der = _certificate(certificate)
    _serial_is(certificate,pair,'ca')
    _require_extensions(certificate,{'Basic Constraints: critical':'CA:TRUE, pathlen:0',
                                     'Key Usage: critical':'Certificate Sign, CRL Sign'})
    validity = _validity(certificate)
    pub = _ssl('x509','-noout','-pubkey',value=certificate)
    if key_body is not None and _ssl('pkey','-pubin','-outform','DER',value=pub) != _inspect_key(key_body):
        fail()
    _purpose(certificate,certificate,'any',path)
    return digest(ca_der),validity


def _validate_leaf(leaf_body, key_body, ca_body, *, role, pair, path):
    from .recovery_https_install import _ssl

    name = SERVER_NAME if role == 'server' else CLIENT_NAME
    ca_der, leaf_der = _certificate(ca_body), _certificate(leaf_body)
    _serial_is(leaf_body,pair,role)
    _require_extensions(leaf_body,{'Basic Constraints: critical':'CA:FALSE','Key Usage: critical':'Digital Signature',
        'Extended Key Usage:':'TLS Web Server Authentication' if role == 'server' else 'TLS Web Client Authentication',
        'Subject Alternative Name:':'DNS:'+name})
    public = _ssl('pkey','-pubin','-outform','DER',value=_ssl('x509','-noout','-pubkey',value=leaf_body))
    if public != _inspect_key(key_body):
        fail()
    not_before,not_after = _validity(leaf_body)
    _purpose(leaf_body,ca_body,'ssl'+role,path)
    return {'leafSha256':digest(leaf_der),'certificateSha256':digest(leaf_body),'keySha256':digest(key_body),
            'caSha256':digest(ca_der),'caFileSha256':digest(ca_body),'publicKeySha256':digest(public),
            'notBeforeSec':not_before,'notAfterSec':not_after}


def _component(directory, name, produce, validate, *, maximum=MAX_CERT):
    from .recovery_listener_install import _new_file, _read_fixed

    final = directory.path/name
    with closing(publisher._Pins()) as pins:
        current = _read_fixed(pins,final,0o600,optional=True,maximum=maximum)
        pending = _read_fixed(pins,final.with_name('.'+name+'.pending'),0o600,optional=True,maximum=maximum)
        if current is not None and pending is not None:
            fail()
        body = current if current is not None else pending if pending is not None else produce()
        if type(body) is not bytes or not 0 < len(body) <= maximum:
            fail()
        facts = validate(body)
        pins.verify()
    _new_file(final,body,0o600)
    return body,facts


def _make_role_root(path):
    from .recovery_listener_install import _make_protected_directory
    until = path.parent
    absent = []
    while not os.path.lexists(until):
        absent.append(until)
        until = until.parent
    for item in (*reversed(absent), path):
        _make_protected_directory(item, private=True)


def require_fresh(pair_id):
    if not hash_value(pair_id) or any(os.path.lexists(root/pair_id) for root in (LISTENER_ROOT,AUTHORITY_ROOT)):
        fail()


def _generation_prefix(listener, authority, *, complete):
    steps = [(authority,'authority.json'),(authority,'ca-key.pem'),(authority,'ca.pem'),(listener,'ca.pem'),
             (authority,'server.cnf'),(listener,'server-key.pem'),(listener,'server.pem'),
             (authority,'client.cnf'),(authority,'client-key.pem'),(authority,'client.pem'),
             (authority,MANIFEST),(listener,MANIFEST)]
    listings = {directory:set(os.listdir(directory.fd)) for directory in (listener,authority)}
    for directory, files in ((listener,LISTENER_FILES),(authority,AUTHORITY_FILES)):
        if listings[directory] - files - {'.'+name+'.pending' for name in files}:
            fail()
    gap = False
    for directory, name in steps:
        present = name in listings[directory]
        pending = '.'+name+'.pending' in listings[directory]
        if ((present and pending) or (gap and (present or pending)) or (complete and not present)):
            fail()
        gap = not present


def prepare_pair(plan, intent, check, *, expected_sha=None):
    """Hold the existing approved D2a owner while preparing only private material."""
    from .recovery_https_install import _exact_component, _ssl
    from .recovery_worker_provision import _subdirectory

    binding = binding_for(plan,intent)
    pair = binding['pairId']
    check()
    if expected_sha is not None and (not hash_value(expected_sha) or any(
            not (folder/pair).is_dir() for folder in (LISTENER_ROOT,AUTHORITY_ROOT))):
        fail()
    for path in (LISTENER_ROOT, AUTHORITY_ROOT):
        _make_role_root(path)
    with (PrivateDirectory(LISTENER_ROOT) as listen_root, PrivateDirectory(AUTHORITY_ROOT) as auth_root,
          _subdirectory(listen_root,pair,create=True) as listener, _subdirectory(auth_root,pair,create=True) as authority):
        _generation_prefix(listener,authority,complete=expected_sha is not None)

        def exact(directory, name, body):
            check()
            _exact_component(directory,name,body)

        def component(directory,name,produce,validate,*,maximum=MAX_CERT):
            check()
            def tested(body):
                facts = validate(body)
                check()
                return facts
            return _component(directory,name,produce,tested,maximum=maximum)

        exact(authority,'authority.json',encoded(binding))
        key = authority.path/'ca-key.pem'
        ca_key,public_ca = component(authority,key.name,_new_key,_inspect_key,maximum=MAX_KEY)

        def ca_certificate():
            return _ssl('req','-new','-x509','-sha256','-key',str(key),'-passin','pass:', '-days','365',
                        '-subj','/CN=Orbis Sentinel private recovery '+pair[:16],
                        '-set_serial','0x'+_serial(pair,'ca'),
                        '-addext','basicConstraints=critical,CA:TRUE,pathlen:0',
                        '-addext','subjectKeyIdentifier=hash',
                        '-addext','keyUsage=critical,keyCertSign,cRLSign')

        ca, (ca_id, ca_times) = component(authority,'ca.pem',ca_certificate,
                                          lambda body:_validate_authority(body,ca_key,pair,authority.path))
        exact(listener,'ca.pem',ca)
        sides = {}
        keys = {public_ca}

        def distinct_key(body):
            public = _inspect_key(body)
            if public in keys:
                fail()
            return public

        for role, name, directory in (('server',SERVER_NAME,listener),('client',CLIENT_NAME,authority)):
            leaf_key = directory.path/(role+'-key.pem')
            extension = authority.path/(role+'.cnf')
            exact(authority,extension.name,_extension(role,name))
            private, public = component(directory,leaf_key.name,_new_key,distinct_key,maximum=MAX_KEY)
            keys.add(public)

            def make_leaf():
                csr = _ssl('req','-new','-key',str(leaf_key),'-passin','pass:', '-subj','/CN='+name)
                return _ssl('x509','-req','-sha256','-CA',str(authority.path/'ca.pem'),'-CAkey',str(key),
                            '-passin','pass:', '-set_serial','0x'+_serial(pair,role),'-days','90',
                            '-extfile',str(extension),'-extensions','leaf',value=csr)

            _, sides[role] = component(directory,role+'.pem',make_leaf,
                lambda body:_validate_leaf(body,private,ca,role=role,pair=pair,path=directory.path))
        if len({digest(public_ca),*(side['publicKeySha256'] for side in sides.values())}) != 3:
            fail()
        pair_record = {'schema':PAIR,'binding':binding,'caSha256':ca_id,
                       'caNotBeforeSec':ca_times[0],'caNotAfterSec':ca_times[1],
                       'server':sides['server'],'client':{key:item for key,item in sides['client'].items() if key != 'keySha256'}}
        exact(authority,MANIFEST,encoded({**pair_record,'clientKeySha256':sides['client']['keySha256']}))
        exact(listener,MANIFEST,encoded(pair_record))
        check()
        observed = digest(encoded(pair_record))
        if expected_sha is not None and observed != expected_sha:
            fail()
        return observed


class ListenerPeer:
    def __init__(self, context, client_sha, check, *, pair_sha256=None):
        self._context, self._client, self._check = context, client_sha, check
        self.pair_sha256 = pair_sha256

    def verify(self):
        self._check()

    def authenticate(self, connection, expires, draining):
        self.verify()
        secured = self._context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
        try:
            secured.setblocking(False)
            while not draining.is_set():
                left = expires - time.monotonic()
                if left <= 0:
                    break
                try:
                    secured.do_handshake()
                    if (time.monotonic() >= expires or draining.is_set()
                            or digest(secured.getpeercert(binary_form=True) or b'') != self._client):
                        fail()
                    self._check()
                    if time.monotonic() >= expires or draining.is_set():
                        fail()
                    secured.setblocking(True)
                    return secured
                except ssl.SSLWantReadError:
                    readers,writers = [secured],[]
                except ssl.SSLWantWriteError:
                    readers,writers = [],[secured]
                left = expires - time.monotonic()
                if left <= 0 or draining.is_set():
                    break
                select.select(readers,writers,[],min(left,0.1))
            fail()
        except BaseException:
            secured.close()
            raise


@contextmanager
def open_listener(marker, marker_sha, config):
    """Open only the marker-selected listener material, before creating any store."""
    from .recovery_worker_provision import _subdirectory

    pair = marker['transport']['pairId']
    if not hash_value(pair):
        fail()
    with (PrivateDirectory(LISTENER_ROOT) as root, _subdirectory(root,pair) as directory, ExitStack() as resources):
        if set(os.listdir(directory.fd)) != LISTENER_FILES:
            fail()
        def get(name, limit):
            value = resources.enter_context(PrivateFile(directory,name,limit))
            if mount_id(value.fd) != mount_id(directory.fd):
                fail()
            return value
        record, ca, leaf, key = (get(MANIFEST,16384),get('ca.pem',MAX_CERT),get('server.pem',MAX_CERT),get('server-key.pem',MAX_KEY))
        value = _document(record.body)
        if (set(value) != {'schema','binding','caSha256','caNotBeforeSec','caNotAfterSec','server','client'}
                or value['schema'] != PAIR or any(type(value[name]) is not dict for name in ('binding','server','client'))):
            fail()
        binding = value['binding']
        owner = {'schema':IDENTITY,'operationId':marker['operationId'],'installationId':marker['installationId'],
                 'origin':marker['origin'],'configSha256':marker['configSha256'],'listenPort':config['listenPort'],
                 'markerSha256':marker_sha,'pairId':pair}
        fields = set(owner)|{'approvalSha256','reviewSha256','scopeSha256'}
        server, client = value['server'],value['client']
        digests = {'leafSha256','certificateSha256','caSha256','caFileSha256','publicKeySha256'}
        role = digests | {'notBeforeSec','notAfterSec'}
        if (set(binding) != fields or any(binding.get(name) != expected for name,expected in owner.items())
                or any(not hash_value(binding[name]) for name in fields-set(owner))
                or set(server) != role|{'keySha256'} or set(client) != role
                or any(not hash_value(item[name]) for item in (server,client) for name in digests | (set(item)&{'keySha256'}))
                or value['caSha256'] != digest(_certificate(ca.body))
                or any(item['caSha256'] != value['caSha256'] or item['caFileSha256'] != digest(ca.body) for item in (server,client))
                or server['leafSha256'] != digest(_certificate(leaf.body)) or server['certificateSha256'] != digest(leaf.body)
                or server['keySha256'] != digest(key.body) or server['leafSha256'] == client['leafSha256']):
            fail()

        if (_validate_authority(ca.body,None,pair,directory.path) != (value['caSha256'],
                    (value['caNotBeforeSec'],value['caNotAfterSec']))
                or _validate_leaf(leaf.body,key.body,ca.body,role='server',pair=pair,path=directory.path) != server):
            fail()

        def check():
            _current(value['caNotBeforeSec'],value['caNotAfterSec'])
            for item in (server,client):
                _current(item['notBeforeSec'],item['notAfterSec'])
            if set(os.listdir(directory.fd)) != LISTENER_FILES:
                fail()
            for pinned in (record,ca,leaf,key):
                pinned.verify()

        check()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        context.load_verify_locations(cadata=ca.body.decode('ascii'))
        descriptors = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
        for item in (leaf,key):
            os.lseek(item.fd,0,os.SEEK_SET)
        context.load_cert_chain(f'{descriptors}/{leaf.fd}',f'{descriptors}/{key.fd}')
        context.sni_callback = lambda _connection,name,_context: None if name == SERVER_NAME else ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        check()
        yield ListenerPeer(context,client['leafSha256'],check,pair_sha256=digest(record.body))
        check()


class PreparedPair:
    """Read-only retained pair, bound to the exact approved setup and both roles."""
    def __init__(self, manifest, client_key_sha, authority, check):
        self.manifest = manifest
        self.client_key_sha = client_key_sha
        self.authority = authority
        self.verify = check

    def envelope(self, profile_sha, public_leaf):
        self.verify()
        value = self.manifest
        binding, server, client = (value[name] for name in ('binding','server','client'))
        return {'schema':'orbis.sentinel-recovery-backend-edge.v1','operationId':binding['operationId'],
                'installationId':binding['installationId'],'pairId':binding['pairId'],'markerSha256':binding['markerSha256'],
                'pairSha256':digest(encoded(value)),'origin':binding['origin'],'listenPort':binding['listenPort'],
                'profileSha256':profile_sha,'publicLeafSha256':public_leaf,'serverLeafSha256':server['leafSha256'],
                'clientLeafSha256':client['leafSha256'],'clientFileSha256':client['certificateSha256'],
                'caFileSha256':client['caFileSha256'],'clientKeySha256':self.client_key_sha,
                'notBeforeSec':max(value['caNotBeforeSec'],server['notBeforeSec'],client['notBeforeSec']),
                'notAfterSec':min(value['caNotAfterSec'],server['notAfterSec'],client['notAfterSec'])}


@contextmanager
def held_prepared_pair(plan, intent):
    """Reopen both protected roles without any path that can create material."""
    from .recovery_worker_provision import _subdirectory

    binding = binding_for(plan,intent)
    generation = binding['pairId']
    if not hash_value(generation) or not hash_value(intent['pairSha256']):
        fail()
    with (PrivateDirectory(LISTENER_ROOT) as local, PrivateDirectory(AUTHORITY_ROOT) as root,
          _subdirectory(local,generation) as listener, _subdirectory(root,generation) as authority,
          ExitStack() as pins):
        def sources(directory, inventory):
            result = {}
            for name in sorted(inventory):
                handle = pins.enter_context(PrivateFile(directory,name,MAX_CERT if name != MANIFEST else 16384))
                if mount_id(handle.fd) != mount_id(directory.fd):
                    fail()
                result[name] = handle
            return result

        _generation_prefix(listener,authority,complete=True)
        server = sources(listener,LISTENER_FILES)
        client = sources(authority,AUTHORITY_FILES)
        record = _document(server[MANIFEST].body)
        if (digest(server[MANIFEST].body) != intent['pairSha256'] or record['binding'] != binding
                or record.get('schema') != PAIR or _document(client['authority.json'].body) != binding
                or server['ca.pem'].body != client['ca.pem'].body):
            fail()
        ca = server['ca.pem'].body
        ca_sha, ca_dates = _validate_authority(ca,client['ca-key.pem'].body,generation,authority.path)
        if (ca_sha,(record['caNotBeforeSec'],record['caNotAfterSec'])) != (record['caSha256'],ca_dates):
            fail()
        for role, files, directory in (('server',server,listener),('client',client,authority)):
            facts = _validate_leaf(files[role+'.pem'].body,files[role+'-key.pem'].body,ca,
                                   role=role,pair=generation,path=directory.path)
            key_sha = facts['keySha256']
            public = facts if role == 'server' else {k:v for k,v in facts.items() if k != 'keySha256'}
            if public != record[role]:
                fail()
        if (_document(client[MANIFEST].body) != {**record,'clientKeySha256':key_sha}
                or client['server.cnf'].body != _extension('server',SERVER_NAME)
                or client['client.cnf'].body != _extension('client',CLIENT_NAME)):
            fail()

        def verify():
            _generation_prefix(listener,authority,complete=True)
            _current(*ca_dates)
            for role in ('server','client'):
                values = record[role]
                _current(values['notBeforeSec'],values['notAfterSec'])
            for pinned in (*server.values(),*client.values()):
                pinned.verify()

        verify()
        yield PreparedPair(record,key_sha,authority.path,verify)
        verify()
