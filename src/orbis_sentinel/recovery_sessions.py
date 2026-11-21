"""Root-owned recovery sessions; these records never authorize host operations."""

import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import threading
import time
from urllib.parse import urlsplit

_OWNER_UID = 0
_HEX = re.compile(r'[a-f0-9]{64}\Z')
_TOKEN = re.compile(r'[A-Za-z0-9_-]{43}\Z')
_CHALLENGE_MS = 120_000
_IDLE_MS = 900_000
_SESSION_MS = 3_600_000
_FRESH_MS = 120_000
_LISTENER_SETUP_STORE = 'listener-setup-store.json'


class RecoverySessionError(ValueError):
    """Recovery authentication is unavailable, expired or invalid."""


def _fail():
    raise RecoverySessionError('Recovery authentication could not be completed.')


def _integer(value, minimum=0, maximum=9_007_199_254_740_991):
    return type(value) is int and minimum <= value <= maximum


def _token(value):
    if type(value) is not str or not _TOKEN.fullmatch(value):
        _fail()
    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + '=')).decode().rstrip('=') != value:
        _fail()
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def _origin(value):
    if (type(value) is not str or len(value) > 512
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)):
        _fail()
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ('https', 'http') or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment or parsed.port == 0
                or (parsed.scheme == 'http' and parsed.hostname != 'localhost')):
            _fail()
    except ValueError:
        _fail()
    return value


def _recovery_key_digest(value):
    prefix = 'orbis-recovery-'
    if type(value) is not str or not value.startswith(prefix):
        _fail()
    _token(value[len(prefix):])
    return hashlib.sha256(b'orbis.sentinel-recovery-key.v1\0' + value.encode('ascii')).hexdigest()


def _enrollment(value):
    keys = {'identitySha256', 'revision', 'accountId', 'origin', 'totpEnabled', 'requireTotpAfterPasskey', 'credentials'}
    if type(value) is not dict or set(value) != keys:
        _fail()
    for key in ('identitySha256', 'revision'):
        if type(value[key]) is not str or not _HEX.fullmatch(value[key]):
            _fail()
    if (not _integer(value['accountId'], 1) or type(value['origin']) is not str
            or len(value['origin']) > 512 or not value['origin'].startswith(('https://', 'http://'))
            or any(ord(c) <= 32 or ord(c) == 127 for c in value['origin'])
            or type(value['totpEnabled']) is not bool or type(value['requireTotpAfterPasskey']) is not bool
            or type(value['credentials']) is not dict or len(value['credentials']) > 10):
        _fail()
    try:
        origin = urlsplit(value['origin'])
        if (not origin.hostname or origin.username is not None or origin.password is not None
                or origin.path or origin.query or origin.fragment or origin.port == 0):
            _fail()
    except ValueError:
        _fail()
    # The origin and digest come from the independently validated protected profile.
    for credential, counter in value['credentials'].items():
        if (type(credential) is not str or not 1 <= len(credential) <= 2048
                or not re.fullmatch(r'[A-Za-z0-9_-]+', credential)
                or not _integer(counter, 0, 0xffffffff)):
            _fail()
    return json.loads(json.dumps(value))


class RecoverySessions:
    """One protected store owner; verifier callbacks follow durable consumption.

    Enrollment is an internal supervisor action, never browser input. Its digest,
    factors and counters must describe the same protected profile passed to the
    credential worker. The gateway still enforces TLS, Host/Origin and cookie policy.
    """

    def __init__(self, directory, *, clock=None, setup=None):
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._return_monotonic = time.monotonic_ns
        self._return_clock_state = None
        self._return_sessions = {}
        self._return_deadlines = {}
        self._pid = os.getpid()
        self._mutex = threading.RLock()
        self._profile_mutex = threading.RLock()
        self._worker_mutex = threading.RLock()
        self._idle = threading.Condition(self._mutex)
        self._borrowers = {}
        self._closing = False
        self._setup = setup
        self._setup_reservation = None
        self._db = None
        self._files = []
        self._directories = []
        self._closed = False
        directory = os.fspath(directory)
        if not os.path.isabs(directory) or os.path.normpath(directory) != directory or os.path.realpath(directory) != directory:
            _fail()
        self._directory = directory
        try:
            path = '/'
            for part in ('', *directory.strip('/').split('/')):
                if part:
                    path = os.path.join(path, part)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                self._directories.append((path, fd, (info.st_dev, info.st_ino)))
                if (info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022
                        or (path == directory and (info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o700))):
                    _fail()
            lock = self._open('recovery.lock')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if setup is not None or any(os.path.lexists(os.path.join(directory, name))
                                       for name in (_LISTENER_SETUP_STORE, '.' + _LISTENER_SETUP_STORE + '.pending')):
                from .recovery_listener_install import reserve_store
                self._setup_reservation = reserve_store(directory, setup)
            self._open('recovery.sqlite3')
            journal = os.path.join(directory, 'recovery.sqlite3-journal')
            if os.path.lexists(journal):
                fd = os.open(journal, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                try:
                    info = os.fstat(fd)
                    current = os.lstat(journal)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != _OWNER_UID or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != 0o600 or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
                        _fail()
                finally:
                    os.close(fd)
            self._db = sqlite3.connect(os.path.join(directory, 'recovery.sqlite3'), isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._verify()
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=EXTRA')
            self._db.execute('PRAGMA temp_store=MEMORY')
            if self._db.execute('PRAGMA max_page_count=1024').fetchone()[0] > 1024:
                _fail()
            if self._db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete' or self._db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                _fail()
            self._db.executescript('''
                CREATE TABLE IF NOT EXISTS identities (revision TEXT PRIMARY KEY, profile TEXT NOT NULL, active INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS counters (credential TEXT PRIMARY KEY, counter INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS factors (id INTEGER PRIMARY KEY CHECK(id=1), last_step INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS challenges (digest TEXT PRIMARY KEY, binding TEXT NOT NULL, method TEXT NOT NULL, created INTEGER NOT NULL, revision TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (digest TEXT PRIMARY KEY, csrf TEXT NOT NULL, revision TEXT NOT NULL, method TEXT NOT NULL, created INTEGER NOT NULL, touched INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY CHECK(id=1), start INTEGER NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS recovery_keys (revision TEXT PRIMARY KEY, digest TEXT NOT NULL, origin TEXT NOT NULL, active INTEGER NOT NULL, previous_revision TEXT, created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS key_attempts (id INTEGER PRIMARY KEY CHECK(id=1), start INTEGER NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS operator_enrollment (id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL, nonce TEXT, target TEXT, origin TEXT);
                CREATE TABLE IF NOT EXISTS operator_prepared_begins (token TEXT PRIMARY KEY, request TEXT NOT NULL, generation INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS operator_incarnations (token TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS operator_writer_requests (token TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS main_passkey_challenges (digest TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS main_passkey_attempts (id INTEGER PRIMARY KEY CHECK(id=1), start INTEGER NOT NULL, count INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS main_passkey_receipts (digest TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS bootstrap_operations (operation TEXT PRIMARY KEY, record TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS controller_return_approvals (id TEXT PRIMARY KEY, scope TEXT NOT NULL, session TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, claim TEXT);
                CREATE TABLE IF NOT EXISTS listener_setup_binding (id INTEGER PRIMARY KEY CHECK(id=1), marker TEXT NOT NULL);
                INSERT OR IGNORE INTO operator_enrollment VALUES (1,0,NULL,NULL,NULL);
            ''')
            self._transaction(self._check_setup_binding)
            # No pre-restart browser authority survives a new owner instance.
            self._transaction(lambda: (self._db.execute('DELETE FROM challenges'), self._db.execute('DELETE FROM sessions'),
                                       self._db.execute('DELETE FROM main_passkey_challenges'),
                                       self._db.execute('DELETE FROM controller_return_approvals')))
            os.fsync(self._directories[-1][1])
        except BaseException:
            self.close()
            raise

    def _open(self, name):
        path = os.path.join(self._directory, name)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
        self._files.append((path, fd, (os.fstat(fd).st_dev, os.fstat(fd).st_ino)))
        self._verify()
        return fd

    def _verify(self, *, resources=False):
        if self._closed or (self._closing and not resources) or os.getpid() != self._pid:
            _fail()
        if self._setup is not None:
            self._setup.verify()
        if self._setup_reservation is not None:
            self._setup_reservation.verify()
        for path, fd, identity in self._directories:
            for info in (os.fstat(fd), os.lstat(path)):
                if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity
                        or info.st_uid not in {0, _OWNER_UID} or info.st_mode & 0o022
                        or (path == self._directory and (info.st_uid != _OWNER_UID or stat.S_IMODE(info.st_mode) != 0o700))):
                    _fail()
        for path, fd, identity in self._files:
            for info in (os.fstat(fd), os.lstat(path)):
                if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity
                        or info.st_uid != _OWNER_UID or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    _fail()

    def _verify_resource(self):
        with self._mutex:
            if not self._borrowers.get(threading.get_ident()):
                _fail()
            self._verify(resources=True)

    @contextmanager
    def _borrow(self):
        """Pin root resources during bounded callbacks without locking key auth."""
        owner = threading.get_ident()
        with self._mutex:
            self._verify()
            self._borrowers[owner] = self._borrowers.get(owner, 0) + 1
        try:
            yield
        finally:
            with self._mutex:
                try:
                    self._verify(resources=True)
                finally:
                    self._borrowers[owner] -= 1
                    if not self._borrowers[owner]:
                        del self._borrowers[owner]
                    self._idle.notify_all()

    def _transaction(self, action):
        with self._mutex:
            self._verify()
            self._db.execute('BEGIN IMMEDIATE')
            try:
                result = action()
                self._verify()
                self._db.execute('COMMIT')
                return result
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def _now(self):
        now = self._clock()
        if not _integer(now, 1):
            _fail()
        return now

    def _return_now(self, wall=None):
        """One decision sample, with owner-scoped elapsed time that cannot roll back.

        Return grants and sessions are cleared on owner startup, so these anchors
        require no persistent clock identity or second store owner.
        """
        wall = self._now() if wall is None else wall
        elapsed = self._return_monotonic()
        if type(elapsed) is not int or elapsed < 0:
            _fail()
        previous = self._return_clock_state
        if previous is not None and elapsed < previous[1]:
            _fail()
        projected = previous[0] + elapsed - previous[1] if previous is not None else wall * 1000000
        policy = max(wall * 1000000, projected)
        self._return_clock_state = (policy, elapsed)
        return wall, policy // 1000000

    def _check_setup_binding(self):
        row = self._db.execute('SELECT marker FROM listener_setup_binding WHERE id=1').fetchone()
        if row is None:
            if self._setup is not None:
                self._db.execute('INSERT INTO listener_setup_binding VALUES (1,?)', (self._setup.sha256,))
        elif self._setup is None or row['marker'] != self._setup.sha256:
            _fail()

    def _identity(self, method='password'):
        self._publication_idle()
        if method not in ('password', 'passkey', 'recovery-key'):
            _fail()
        if method == 'recovery-key':
            rows = self._db.execute('SELECT revision, digest, origin FROM recovery_keys WHERE active=1').fetchall()
            if len(rows) != 1:
                _fail()
            row = dict(rows[0])
            if not _HEX.fullmatch(row['revision']) or not _HEX.fullmatch(row['digest']):
                _fail()
            _origin(row['origin'])
            return row
        rows = self._db.execute('SELECT profile FROM identities WHERE active=1').fetchall()
        if len(rows) != 1:
            _fail()
        return _enrollment(json.loads(rows[0]['profile']))

    def _bootstrap_idle(self):
        if self._setup is not None:
            _fail()
        rows = self._db.execute('SELECT record FROM bootstrap_operations').fetchall()
        if not rows:
            return
        from .recovery_bootstrap import _record
        for row in rows:
            if _record(row['record'])['phase'] != 'active':
                _fail()

    def _publication_idle(self):
        from .recovery_bootstrap import _PAIRED_PHASES, _record
        rows = self._db.execute('SELECT operation,record FROM bootstrap_operations')
        if self._setup is not None:
            row = rows.fetchone()
            if row is None or rows.fetchone() is not None:
                _fail()
            value = _record(row['record'])
            if value['phase'] != 'paired-published' or value['operationId'] != row['operation']:
                _fail()
            self._check_paired_publication(value)
            return
        for row in rows:
            if _record(row['record'])['phase'] in _PAIRED_PHASES:
                _fail()

    def _check_paired_publication(self, record):
        from .bootstrap_publication import PROOF_FILE, proof_record
        from .bootstrap_source import PrivateDirectory, PrivateFile, encoded, mount_id
        setup, ready = self._setup, record['pairedPublication']['ready']
        if (setup is None or setup.backend is None or setup.installation != record['installationId']
                or setup.origin != record['origin'] or setup.sha256 != ready['setupSha256']
                or setup.backend.pair_sha256 != ready['pairSha256']):
            _fail()
        self._paired_published_rows(record)
        try:
            with (PrivateDirectory(Path(self._directory) / 'bootstrap' / record['operationId']) as directory,
                  PrivateFile(directory, PROOF_FILE, 16384) as proof):
                if (mount_id(directory.fd) != mount_id(self._directories[-1][1])
                        or mount_id(proof.fd) != mount_id(directory.fd)
                        or os.path.lexists(directory.path / ('.' + PROOF_FILE + '.pending'))
                        or proof.body != encoded(proof_record(record))):
                    _fail()
                proof.verify()
        except (OSError, ValueError):
            _fail()

    def _write_identity(self, profile):
        self._bootstrap_idle()
        encoded = json.dumps(profile, sort_keys=True, separators=(',', ':'))
        key = self._db.execute('SELECT origin FROM recovery_keys WHERE active=1').fetchone()
        if key and key['origin'] != profile['origin']:
            _fail()
        known = self._db.execute('SELECT profile, active FROM identities WHERE revision=?', (profile['revision'],)).fetchone()
        if known:
            if known['profile'] != encoded or known['active'] != 1:
                _fail()
            return False
        if self._db.execute('SELECT count(*) FROM identities').fetchone()[0] >= 1024:
            _fail()
        self._db.execute('UPDATE identities SET active=0')
        self._db.execute('DELETE FROM main_passkey_challenges')
        self._db.execute('INSERT INTO identities VALUES (?,?,1)', (profile['revision'], encoded))
        for table in ('challenges', 'sessions'):
            self._db.execute('DELETE FROM ' + table + " WHERE method!='recovery-key'")
        self._db.executemany('INSERT INTO counters VALUES (?,?) ON CONFLICT(credential) DO UPDATE SET counter=MAX(counter,excluded.counter)',
                             profile['credentials'].items())
        return True

    def _operator_enrollment(self):
        row = self._db.execute('SELECT * FROM operator_enrollment WHERE id=1').fetchone()
        if row is None or not _integer(row['generation'], 0, 9_007_199_254_740_990):
            _fail()
        if row['nonce'] is None:
            if row['target'] is not None or row['origin'] is not None:
                _fail()
        elif (type(row['nonce']) is not str or not _HEX.fullmatch(row['nonce'])
              or type(row['target']) is not str or not _HEX.fullmatch(row['target'])):
            _fail()
        else:
            _origin(row['origin'])
        return row

    def _operator_status(self):
        state = self._operator_enrollment()
        rows = self._db.execute('SELECT profile FROM identities WHERE active=1').fetchall()
        if len(rows) > 1 or (state['nonce'] is not None and rows):
            _fail()
        current = _enrollment(json.loads(rows[0]['profile'])) if rows else None
        history = self._db.execute('SELECT count(*) FROM identities').fetchone()[0]
        return {'generation': state['generation'], 'revision': current['revision'] if current else None,
                'state': 'pending' if state['nonce'] is not None else 'enrolled' if current else
                         'revoked' if history or state['generation'] else 'never-enrolled'}

    def operator_status(self):
        """Privileged enrollment status; unavailable storage never means unenrolled."""
        def read():
            self._publication_idle()
            return self._operator_status()
        return self._transaction(read)

    def operator_writer_eligibility(self):
        """Read-only admission before a new Host sync fence is acquired."""
        def read():
            self._publication_idle()
            status = self._operator_status()
            if self._setup is None:
                self._bootstrap_idle()
            return {'schema': 'orbis.sentinel-operator-writer-eligibility.v1',
                    'generation': status['generation'], 'revision': status['revision'],
                    'eligible': self._setup is None and status['state'] == 'enrolled'}
        return self._transaction(read)

    def enroll(self, profile):
        profile = _enrollment(profile)
        def write():
            if self._operator_enrollment()['nonce'] is not None:
                _fail()
            if self._write_identity(profile):
                self._db.execute('UPDATE operator_enrollment SET generation=generation+1 WHERE id=1')
        self._transaction(write)

    def revoke(self):
        def write():
            self._bootstrap_idle()
            self._operator_enrollment()
            self._db.execute('UPDATE identities SET active=0')
            self._db.execute('DELETE FROM main_passkey_challenges')
            self._db.execute("DELETE FROM challenges WHERE method!='recovery-key'")
            self._db.execute("DELETE FROM sessions WHERE method!='recovery-key'")
            self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=NULL,target=NULL,origin=NULL WHERE id=1')
        self._transaction(write)

    def revoke_operator(self, *, expected_generation, expected_revision):
        """Revoke only the supervisor's observed enrollment, preserving the key."""
        if (not _integer(expected_generation) or (expected_revision is not None
                and (type(expected_revision) is not str or not _HEX.fullmatch(expected_revision)))):
            _fail()
        def write():
            self._bootstrap_idle()
            status = self._operator_status()
            if status['generation'] != expected_generation or status['revision'] != expected_revision:
                _fail()
            self._db.execute('UPDATE identities SET active=0')
            self._db.execute('DELETE FROM main_passkey_challenges')
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method!='recovery-key'")
            self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=NULL,target=NULL,origin=NULL WHERE id=1')
            return self._operator_status()
        return self._transaction(write)

    def begin_operator_enrollment(self, *, expected_generation, expected_revision, identity_sha256, origin):
        """Revoke operator authority before a supervised credential mutation.

        Callers must serialize actual account/passkey writers and bind the planned
        protected profile. This nonce fences enrollment, not external DB writes or
        disruptive workers; it grants no host operation or takeover authority.
        """
        return self._begin_operator_enrollment(expected_generation=expected_generation, expected_revision=expected_revision,
                                                identity_sha256=identity_sha256, origin=origin)

    def begin_prepared_operator_enrollment(self, *, expected_generation, expected_revision, identity_sha256, origin, change_token,
                                           _baseline_proof=None, _writer_proof=None):
        """Begin with a supervisor token durably recorded before sending the request.

        Only an exact retry of the still-pending operation is acknowledged. A
        receipt never revives completed or superseded authority. The caller must
        still serialize and verify the real credential mutation independently.
        """
        _token(change_token)
        return self._begin_operator_enrollment(expected_generation=expected_generation, expected_revision=expected_revision,
                                                identity_sha256=identity_sha256, origin=origin, change_token=change_token,
                                                _baseline_proof=_baseline_proof, _writer_proof=_writer_proof)

    def _require_owned_operator_target(self, target, token):
        from .recovery_incarnations import _record, _writer_record
        rows = self._db.execute('SELECT token,record FROM operator_incarnations LIMIT 1025').fetchall()
        writers = self._db.execute('SELECT token,record FROM operator_writer_requests LIMIT 1025').fetchall()
        if len(rows) > 1024 or len(writers) > 1024:
            _fail()
        requests = {row['token']: _writer_record(row['record'], row['token']) for row in writers}
        writer_sources = {request['source'] for request in requests.values()}
        for row in rows:
            issued = _record(row['record'], row['token'])
            if issued['target'] == target:
                if row['token'] != token or (issued['source'] in writer_sources
                        and (token not in requests or requests[token]['source'] != issued['source'])):
                    _fail()
        for request in requests.values():
            # A writer must use its fresh Root-issued target, never bypass the
            # managed baseline by activating its retained raw Main input.
            if request['source'] == target:
                _fail()

    def _begin_operator_enrollment(self, *, expected_generation, expected_revision, identity_sha256, origin, change_token=None,
                                   _baseline_proof=None, _writer_proof=None):
        if (not _integer(expected_generation) or type(identity_sha256) is not str or not _HEX.fullmatch(identity_sha256)
                or (expected_revision is not None and (type(expected_revision) is not str or not _HEX.fullmatch(expected_revision)))):
            _fail()
        origin = _origin(origin)
        prepared = change_token is not None
        if prepared and not _integer(expected_generation, 0, 9_007_199_254_740_988):
            _fail()
        raw = change_token if prepared else secrets.token_urlsafe(32)
        nonce = _token(raw)
        binding = hashlib.sha256(b'orbis.sentinel-prepared-begin.v1\0' + json.dumps(
            [expected_generation, expected_revision, identity_sha256, origin, nonce],
            separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
        def write():
            self._bootstrap_idle()
            status = self._operator_status()
            self._require_owned_operator_target(identity_sha256, nonce)
            incarnation = self._db.execute('SELECT record FROM operator_incarnations WHERE token=?', (nonce,)).fetchone()
            if incarnation is not None:
                from .recovery_incarnations import _record
                issued = _record(incarnation['record'], nonce)
                if (not prepared or issued['target'] != identity_sha256 or issued['origin'] != origin
                        or issued['generation'] != expected_generation or issued['baseline'] != expected_revision):
                    _fail()
            writer = self._db.execute('SELECT record FROM operator_writer_requests WHERE token=?', (nonce,)).fetchone()
            writer_request = None
            if writer is not None:
                from .recovery_incarnations import _writer_record, _WriterRequestProof
                writer_request = _writer_record(writer['record'], nonce)
                if (not prepared or incarnation is None or writer_request['source'] != issued['source']
                        or writer_request['generation'] != expected_generation or writer_request['revision'] != expected_revision
                        or writer_request['origin'] != origin or type(_writer_proof) is not _WriterRequestProof
                        or _writer_proof.owner is not self or _writer_proof.token != nonce
                        or _writer_proof.baseline != writer_request['baseline'] or _writer_proof.source != writer_request['source']):
                    _fail()
            if prepared:
                receipt = self._db.execute('SELECT request,generation FROM operator_prepared_begins WHERE token=?', (nonce,)).fetchone()
                if receipt is not None:
                    state = self._operator_enrollment()
                    if (type(receipt['request']) is not str or not _HEX.fullmatch(receipt['request'])
                            or not _integer(receipt['generation']) or receipt['request'] != binding
                            or status['state'] != 'pending' or receipt['generation'] != expected_generation + 1
                            or state['generation'] != receipt['generation'] or state['target'] != identity_sha256
                            or state['origin'] != origin or state['nonce'] is None
                            or not secrets.compare_digest(state['nonce'], nonce)):
                        _fail()
                    return {'generation': receipt['generation']}
                # Preserve consumed-token evidence instead of silently recycling it.
                if self._db.execute('SELECT count(*) FROM operator_prepared_begins').fetchone()[0] >= 1024:
                    _fail()
            if (status['generation'] != expected_generation or status['revision'] != expected_revision
                    or status['state'] == 'pending'):
                _fail()
            for table in ('identities', 'recovery_keys'):
                rows = self._db.execute('SELECT ' + ('profile' if table == 'identities' else 'origin') + ' FROM ' + table + ' WHERE active=1').fetchall()
                for row in rows:
                    current_origin = _enrollment(json.loads(row['profile']))['origin'] if table == 'identities' else row['origin']
                    if current_origin != origin:
                        _fail()
            if writer_request is not None:
                from .recovery_incarnations import _assert_baseline
                # This comparison shares the exact transaction that revokes old
                # authority. A counter advanced after worker inspection cannot
                # pass an earlier read-only baseline receipt.
                _assert_baseline(self, _baseline_proof, writer_request)
            self._db.execute('UPDATE identities SET active=0')
            self._db.execute('DELETE FROM main_passkey_challenges')
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method!='recovery-key'")
            self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=?,target=?,origin=? WHERE id=1',
                             (nonce, identity_sha256, origin))
            if prepared:
                self._db.execute('INSERT INTO operator_prepared_begins VALUES (?,?,?)', (nonce, binding, expected_generation + 1))
                return {'generation': expected_generation + 1}
            return {'generation': expected_generation + 1, 'changeToken': raw}
        return self._transaction(write)

    def complete_operator_enrollment(self, profile, *, change_token, expected_generation, _source_proof=None):
        """Activate only metadata inspected from the exact planned protected bytes.

        The privileged caller must establish that the corresponding main credential
        mutation and profile custody are complete; a browser cannot supply proof.
        """
        profile = _enrollment(profile)
        digest = _token(change_token)
        if not _integer(expected_generation):
            _fail()
        def write():
            state = self._operator_enrollment()
            if (state['generation'] != expected_generation or state['nonce'] is None
                    or not secrets.compare_digest(state['nonce'], digest)
                    or state['target'] != profile['identitySha256'] or state['origin'] != profile['origin']):
                _fail()
            self._require_owned_operator_target(profile['identitySha256'], digest)
            incarnation = self._db.execute('SELECT record FROM operator_incarnations WHERE token=?', (digest,)).fetchone()
            if incarnation is not None:
                from .recovery_incarnations import _record, _SourceProof
                issued = _record(incarnation['record'], digest)
                if (type(_source_proof) is not _SourceProof or _source_proof.owner is not self
                        or _source_proof.token != digest or _source_proof.source != issued['source']
                        or _source_proof.target != issued['target'] or _source_proof.content != issued['content']
                        or profile['identitySha256'] != issued['target'] or profile['revision'] != issued['revision']
                        or profile['origin'] != issued['origin'] or expected_generation != issued['generation'] + 1):
                    _fail()
            self._write_identity(profile)
            self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=NULL,target=NULL,origin=NULL WHERE id=1')
            return self._operator_status()
        return self._transaction(write)

    def inspect_operator_enrollment(self, *, change_token, expected_generation, inspector, _source_proof=None):
        """Inspect the planned protected profile before activating its metadata.

        inspector(digest) is a privileged, bounded worker callback with verified
        cleanup, never a browser response or main application's assertion.
        """
        digest = _token(change_token)
        if not _integer(expected_generation) or not callable(inspector):
            _fail()
        with self._borrow():
            def planned():
                self._publication_idle()
                state = self._operator_enrollment()
                if (state['generation'] != expected_generation or state['nonce'] is None
                        or not secrets.compare_digest(state['nonce'], digest)):
                    _fail()
                return state['target']
            target = self._transaction(planned)
            description = inspector(target)
            fields = {'schema', 'identitySha256', 'revision', 'accountId', 'origin', 'totpEnabled', 'requireTotpAfterPasskey', 'credentials'}
            if (type(description) is not dict or set(description) != fields
                    or description['schema'] != 'orbis.sentinel-identity-description.v1'):
                _fail()
            profile = {key: value for key, value in description.items() if key != 'schema'}
            return self.complete_operator_enrollment(profile, change_token=change_token, expected_generation=expected_generation,
                                                     _source_proof=_source_proof)

    def prepare_recovery_key(self, *, origin, expected_revision):
        """Privileged preparation; return the new 256-bit key exactly once.

        The existing key remains valid until explicit activation verifies possession
        of the replacement. No HTTP handler exposes preparation or activation.
        """
        origin = _origin(origin)
        if expected_revision is not None and (type(expected_revision) is not str or not _HEX.fullmatch(expected_revision)):
            _fail()
        raw, revision = 'orbis-recovery-' + secrets.token_urlsafe(32), secrets.token_hex(32)
        def write():
            self._bootstrap_idle()
            rows = self._db.execute('SELECT revision FROM recovery_keys WHERE active=1').fetchall()
            if len(rows) > 1 or (rows[0]['revision'] if rows else None) != expected_revision:
                _fail()
            identities = self._db.execute('SELECT profile FROM identities WHERE active=1').fetchall()
            if len(identities) > 1 or (identities and _enrollment(json.loads(identities[0]['profile']))['origin'] != origin):
                _fail()
            if self._db.execute('SELECT count(*) FROM recovery_keys').fetchone()[0] >= 1024:
                _fail()
            now = self._now()
            self._db.execute('INSERT INTO recovery_keys VALUES (?,?,?,-1,?,?)',
                             (revision, _recovery_key_digest(raw), origin, expected_revision, now))
            return {'recoveryKey': raw, 'revision': revision, 'expiresAtMs': now + 600_000}
        return self._transaction(write)

    def activate_recovery_key(self, *, revision, recovery_key, expected_revision):
        if type(revision) is not str or not _HEX.fullmatch(revision):
            _fail()
        if expected_revision is not None and (type(expected_revision) is not str or not _HEX.fullmatch(expected_revision)):
            _fail()
        digest = _recovery_key_digest(recovery_key)
        def write():
            self._bootstrap_idle()
            rows = self._db.execute('SELECT revision FROM recovery_keys WHERE active=1').fetchall()
            pending = self._db.execute('SELECT * FROM recovery_keys WHERE revision=? AND active=-1', (revision,)).fetchone()
            if (len(rows) > 1 or (rows[0]['revision'] if rows else None) != expected_revision or pending is None
                    or pending['previous_revision'] != expected_revision
                    or not 0 <= self._now() - pending['created'] <= 600_000
                    or not secrets.compare_digest(digest, pending['digest'])):
                _fail()
            identities = self._db.execute('SELECT profile FROM identities WHERE active=1').fetchall()
            if len(identities) > 1 or (identities and _enrollment(json.loads(identities[0]['profile']))['origin'] != pending['origin']):
                _fail()
            self._db.execute('UPDATE recovery_keys SET active=0')
            self._db.execute('UPDATE recovery_keys SET active=1 WHERE revision=?', (revision,))
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method='recovery-key'")
        return self._transaction(write)

    def revoke_recovery_key(self, *, expected_revision):
        if type(expected_revision) is not str or not _HEX.fullmatch(expected_revision):
            _fail()
        def write():
            self._bootstrap_idle()
            if self._identity('recovery-key')['revision'] != expected_revision:
                _fail()
            self._db.execute('UPDATE recovery_keys SET active=0')
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method='recovery-key'")
        self._transaction(write)

    def _bootstrap_activation_receipt(self, operation, plan, ack):
        from .recovery_bootstrap import _record
        row = self._db.execute('SELECT record FROM bootstrap_operations WHERE operation=?', (operation,)).fetchone()
        if row is None:
            _fail()
        value = _record(row['record'])
        receipt = value['activation']
        if (value['phase'] != 'active' or value['planSha256'] != plan or value['key']['ack'] != ack
                or type(receipt) is not dict or set(receipt) != {'phase', 'operationId', 'planSha256', 'identitySha256', 'revision', 'generation', 'keyRevision', 'sourceSha256'}
                or receipt['phase'] != 'active' or receipt['operationId'] != operation or receipt['planSha256'] != plan
                or receipt['sourceSha256'] != value['sourceSha256'] or receipt['identitySha256'] != value['candidate']['target']
                or receipt['revision'] != value['candidate']['revision'] or receipt['keyRevision'] != value['key']['revision']
                or not _integer(receipt['generation']) or receipt['generation'] != value['pendingGeneration'] + 1
                or self._operator_status() != {'generation': receipt['generation'], 'revision': receipt['revision'], 'state': 'enrolled'}
                or self._identity()['identitySha256'] != receipt['identitySha256']
                or self._identity('recovery-key')['revision'] != receipt['keyRevision']):
            _fail()
        return dict(receipt)

    def _held_bootstrap_rows(self, record):
        held, candidate = record['heldActivation'], record['candidate']
        if (record['phase'] not in ('activation-committed', 'publication-ready')
                or record['activation']['requestId'] != held['requestId']
                or self._operator_status() != {'generation': record['pendingGeneration'], 'revision': None, 'state': 'pending'}):
            _fail()
        state = self._operator_enrollment()
        if (state['nonce'] != hashlib.sha256(record['operationId'].encode('ascii')).hexdigest()
                or state['target'] != candidate['target'] or state['origin'] != record['origin']):
            _fail()
        self._paired_credential_rows(record, published=False)

    def _paired_credential_rows(self, record, *, published):
        key, candidate = record['key'], record['candidate']
        identities = self._db.execute('SELECT revision,profile,active FROM identities LIMIT 2').fetchall()
        keys = self._db.execute('SELECT * FROM recovery_keys LIMIT 2').fetchall()
        if (len(identities) != 1 or identities[0]['active'] != int(published) or identities[0]['revision'] != candidate['revision']
                or _enrollment(json.loads(identities[0]['profile'])) != candidate['profile']
                or len(keys) != 1 or keys[0]['active'] != (1 if published else -1) or keys[0]['revision'] != key['revision']
                or keys[0]['previous_revision'] is not None or keys[0]['origin'] != record['origin']
                or keys[0]['created'] != key['created'] or not _HEX.fullmatch(keys[0]['digest'])):
            _fail()
        counters = dict(self._db.execute('SELECT credential,counter FROM counters').fetchall())
        expected = candidate['profile']['credentials']
        if counters.keys() != expected.keys():
            _fail()
        if published:
            if any(not _integer(counters[credential], minimum, 0xffffffff) for credential, minimum in expected.items()):
                _fail()
        elif counters != expected:
            _fail()
        ack = hashlib.sha256(json.dumps([record['operationId'], record['planSha256'], key['epoch'], key['revision'],
                                         keys[0]['digest']], separators=(',', ':')).encode('ascii')).hexdigest()
        if not secrets.compare_digest(ack, key['ack']):
            _fail()

    def _paired_published_rows(self, record):
        if (record['phase'] != 'paired-published' or self._operator_status() != {
                'generation': record['activation']['generation'], 'revision': record['activation']['revision'],
                'state': 'enrolled'}):
            _fail()
        self._paired_credential_rows(record, published=True)

    def _publish_paired_rows(self, record):
        if not self._db.in_transaction:
            _fail()
        self._held_bootstrap_rows(record)
        if (self._db.execute('UPDATE identities SET active=1 WHERE revision=? AND active=0',
                            (record['activation']['revision'],)).rowcount != 1
                or self._db.execute('UPDATE recovery_keys SET active=1 WHERE revision=? AND active=-1',
                                    (record['key']['revision'],)).rowcount != 1
                or self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=NULL,target=NULL,origin=NULL '
                                    'WHERE id=1 AND generation=?', (record['pendingGeneration'],)).rowcount != 1):
            _fail()
        # A published identity starts with no challenge or session from an earlier state.
        for table in ('challenges', 'sessions', 'main_passkey_challenges', 'controller_return_approvals'):
            self._db.execute('DELETE FROM ' + table)

    def _commit_held_bootstrap(self, expected, core, proof, verify):
        """Own the private receipt and inactive credential rows in one transaction."""
        from .collector_execution import HeldStageProof
        from .recovery_bootstrap import _record
        if type(proof) is not HeldStageProof or proof.phase != 'activation' or not callable(verify):
            _fail()

        def write():
            row = self._db.execute('SELECT record FROM bootstrap_operations WHERE operation=?', (proof.offer['operationId'],)).fetchone()
            if row is None:
                _fail()
            current = _record(row['record'])
            if current != expected or current['phase'] != 'activation-pending':
                _fail()
            for table in ('identities', 'counters', 'factors', 'operator_incarnations', 'operator_prepared_begins', 'operator_writer_requests'):
                if self._db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                    _fail()
            verify()
            metadata = _enrollment(current['candidate']['profile'])
            self._db.execute('INSERT INTO identities VALUES (?,?,0)',
                             (metadata['revision'], json.dumps(metadata, sort_keys=True, separators=(',', ':'))))
            self._db.executemany('INSERT INTO counters VALUES (?,?)', metadata['credentials'].items())
            current.update(phase='activation-committed', activation=core)
            body = json.dumps(current, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
            self._held_bootstrap_rows(_record(body))
            self._db.execute('UPDATE bootstrap_operations SET record=? WHERE operation=?', (body, current['operationId']))

        self._transaction(write)

    def _activate_initial_bootstrap(self, proof):
        """Internal compound commit; public bootstrap requires its live collector gate."""
        from .recovery_bootstrap import _BootstrapActivationProof, _record
        if (type(proof) is not _BootstrapActivationProof or proof.owner is not self
                or not _integer(proof.pending_generation, 1)
                or any(type(getattr(proof, key)) is not str or not _HEX.fullmatch(getattr(proof, key))
                       for key in ('operation', 'plan', 'source', 'target', 'content', 'descriptor', 'key_revision', 'ack', 'request', 'key_digest', 'writer_floor', 'managed_intent'))):
            _fail()
        def write():
            row = self._db.execute('SELECT record FROM bootstrap_operations WHERE operation=?', (proof.operation,)).fetchone()
            if row is None:
                _fail()
            record = _record(row['record'])
            if record['phase'] == 'active':
                return self._bootstrap_activation_receipt(proof.operation, proof.plan, proof.ack)
            candidate, key = record['candidate'], record['key']
            state = self._operator_enrollment()
            challenge = record['challenges'].get(proof.request)
            if (record['phase'] != 'acknowledged' or record['planSha256'] != proof.plan or record['sourceSha256'] != proof.source
                    or candidate is None or key is None or candidate['target'] != proof.target or candidate['content'] != proof.content
                    or candidate['profile'] is None or key['revision'] != proof.key_revision or key['ack'] != proof.ack
                    or record['pendingGeneration'] != proof.pending_generation or not key['created'] <= self._now() <= key['expires']
                    or not _HEX.fullmatch(proof.writer_floor) or not _HEX.fullmatch(proof.managed_intent)
                    or record['writerFloor'] != proof.writer_floor or record['managedIntent'] != proof.managed_intent
                    or challenge is None or challenge['phase'] != 'activation' or challenge['consumed'] is not True
                    or challenge['descriptor'] != proof.descriptor or not challenge['created'] <= self._now() <= challenge['expires']
                    or self._operator_status() != {'generation': proof.pending_generation, 'revision': None, 'state': 'pending'}
                    or state['nonce'] != hashlib.sha256(proof.operation.encode('ascii')).hexdigest()
                    or state['target'] != proof.target or state['origin'] != record['origin']):
                _fail()
            metadata = _enrollment(candidate['profile'])
            keys = self._db.execute('SELECT * FROM recovery_keys').fetchall()
            if (len(keys) != 1 or keys[0]['revision'] != proof.key_revision or keys[0]['active'] != -1
                    or keys[0]['previous_revision'] is not None or keys[0]['origin'] != record['origin']
                    or keys[0]['created'] != key['created'] or not secrets.compare_digest(keys[0]['digest'], proof.key_digest)):
                _fail()
            expected_ack = hashlib.sha256(json.dumps([proof.operation, proof.plan, key['epoch'], key['revision'], proof.key_digest],
                sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            if not secrets.compare_digest(expected_ack, proof.ack):
                _fail()
            for table in ('identities', 'counters', 'factors', 'operator_incarnations', 'operator_prepared_begins', 'operator_writer_requests'):
                if self._db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone():
                    _fail()
            self._db.execute('INSERT INTO identities VALUES (?,?,1)', (metadata['revision'], json.dumps(metadata, sort_keys=True, separators=(',', ':'))))
            self._db.executemany('INSERT INTO counters VALUES (?,?)', metadata['credentials'].items())
            self._db.execute('UPDATE recovery_keys SET active=1 WHERE revision=?', (proof.key_revision,))
            self._db.execute('UPDATE operator_enrollment SET generation=generation+1,nonce=NULL,target=NULL,origin=NULL WHERE id=1')
            receipt = {'phase': 'active', 'operationId': proof.operation, 'planSha256': proof.plan, 'identitySha256': proof.target,
                       'revision': metadata['revision'], 'generation': proof.pending_generation + 1, 'keyRevision': proof.key_revision,
                       'sourceSha256': proof.source}
            record['phase'], record['activation'] = 'active', receipt
            record['activationBinding'] = hashlib.sha256(json.dumps([proof.operation, proof.plan, proof.request, challenge['nonce'], proof.ack],
                sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')).hexdigest()
            self._db.execute('UPDATE bootstrap_operations SET record=? WHERE operation=?',
                (json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True), proof.operation))
            return self._bootstrap_activation_receipt(proof.operation, proof.plan, proof.ack)
        return self._transaction(write)

    def challenge(self, *, method, origin, browser_binding):
        binding = _token(browser_binding)
        if method not in ('password', 'passkey', 'recovery-key'):
            _fail()
        raw = secrets.token_urlsafe(32)
        def write():
            now = self._now()
            identity = self._identity(method)
            if origin != identity['origin'] or (method == 'passkey' and not identity['credentials']):
                _fail()
            self._db.execute('DELETE FROM challenges WHERE created<?', (now - _CHALLENGE_MS,))
            emergency = method == 'recovery-key'
            count = self._db.execute("SELECT count(*) FROM challenges WHERE (method='recovery-key')=?", (emergency,)).fetchone()[0]
            if count >= (8 if emergency else 32):
                _fail()
            self._db.execute('INSERT INTO challenges VALUES (?,?,?,?,?)', (_token(raw), binding, method, now, identity['revision']))
            return {'challenge': raw, 'expiresAtMs': now + _CHALLENGE_MS}
        return self._transaction(write)

    def _consume_challenge(self, challenge, browser_binding, origin, methods):
        digest, binding = _token(challenge), _token(browser_binding)
        def consume():
            now = self._now()
            row = self._db.execute('SELECT * FROM challenges WHERE digest=?', (digest,)).fetchone()
            if row is None or row['method'] not in methods:
                _fail()
            identity = self._identity(row['method'])
            if (not secrets.compare_digest(row['binding'], binding) or origin != identity['origin']
                    or row['revision'] != identity['revision'] or not 0 <= now - row['created'] <= _CHALLENGE_MS):
                _fail()
            table = 'key_attempts' if row['method'] == 'recovery-key' else 'attempts'
            rate = self._db.execute('SELECT start, count FROM ' + table + ' WHERE id=1').fetchone()
            if rate is not None and (now < rate['start'] or (now - rate['start'] < 60_000 and rate['count'] >= 10)):
                _fail()
            start, count = (rate['start'], rate['count'] + 1) if rate and now - rate['start'] < 60_000 else (now, 1)
            self._db.execute('INSERT OR REPLACE INTO ' + table + ' VALUES (1,?,?)', (start, count))
            self._db.execute('DELETE FROM challenges WHERE digest=?', (digest,))
            return identity, dict(row)
        return self._transaction(consume)

    def _create_session(self, identity, method, now):
        self._publication_idle()
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._db.execute('DELETE FROM sessions WHERE created<? OR touched<?', (now - _SESSION_MS, now - _IDLE_MS))
        emergency = method == 'recovery-key'
        count = self._db.execute("SELECT count(*) FROM sessions WHERE (method='recovery-key')=?", (emergency,)).fetchone()[0]
        if count >= (4 if emergency else 16):
            _fail()
        self._db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?)', (_token(token), _token(csrf), identity['revision'], method, now, now))
        live = {row[0] for row in self._db.execute('SELECT digest FROM sessions')}
        self._return_sessions = {key: value for key, value in self._return_sessions.items() if key in live}
        self._return_sessions[_token(token)] = self._return_now(wall=now)[1]
        return {'token': token, 'csrfToken': csrf, 'accountId': identity.get('accountId'), 'expiresAtMs': now + _IDLE_MS}

    def complete_recovery_key(self, *, challenge, browser_binding, origin, recovery_key):
        with self._mutex:
            identity, pending = self._consume_challenge(challenge, browser_binding, origin, ('recovery-key',))
            # Commit consumption before checking the secret, including malformed keys.
            if not secrets.compare_digest(_recovery_key_digest(recovery_key), identity['digest']):
                _fail()
            def finish():
                now = self._now()
                if self._identity('recovery-key') != identity or not 0 <= now - pending['created'] <= _CHALLENGE_MS:
                    _fail()
                return self._create_session(identity, 'recovery-key', now)
            return self._transaction(finish)

    def complete(self, *, challenge, browser_binding, origin, verifier):
        if not callable(verifier):
            _fail()
        with self._borrow():
            identity, pending = self._consume_challenge(challenge, browser_binding, origin, ('password', 'passkey'))
            # Persist the attempt before invoking native crypto; crashes cannot replay it.
            proof = verifier(identity['identitySha256'], challenge)
            def finish():
                now = self._now()
                if self._identity() != identity or not 0 <= now - pending['created'] <= _CHALLENGE_MS:
                    _fail()
                keys = {'schema', 'verified', 'accountId', 'revision', 'identitySha256', 'challenge', 'method', 'verifiedAtMs', 'totpStep', 'credential'}
                if (type(proof) is not dict or set(proof) != keys or proof['schema'] != 'orbis.sentinel-authentication.v1'
                        or proof['verified'] is not True or proof['accountId'] != identity['accountId'] or type(proof['accountId']) is not int
                        or proof['revision'] != identity['revision'] or proof['identitySha256'] != identity['identitySha256']
                        or proof['challenge'] != challenge or proof['method'] != pending['method']
                        or not _integer(proof['verifiedAtMs'], pending['created'], now) or now - proof['verifiedAtMs'] > 5000):
                    _fail()
                required = identity['totpEnabled'] and (pending['method'] == 'password' or identity['requireTotpAfterPasskey'])
                step = proof['totpStep']
                if required:
                    previous = self._db.execute('SELECT last_step FROM factors WHERE id=1').fetchone()
                    if not _integer(step) or step != proof['verifiedAtMs'] // 30_000 or (previous and step <= previous['last_step']):
                        _fail()
                    self._db.execute('INSERT OR REPLACE INTO factors VALUES (1,?)', (step,))
                elif step is not None:
                    _fail()
                key = proof['credential']
                if pending['method'] == 'password':
                    if key is not None:
                        _fail()
                else:
                    if type(key) is not dict or set(key) != {'id', 'previousCounter', 'newCounter'} or type(key['id']) is not str:
                        _fail()
                    counter = self._db.execute('SELECT counter FROM counters WHERE credential=?', (key['id'],)).fetchone()
                    if (counter is None or key['id'] not in identity['credentials']
                            or not _integer(key['previousCounter'], 0, 0xffffffff) or not _integer(key['newCounter'], 0, 0xffffffff)
                            or key['previousCounter'] != identity['credentials'][key['id']]
                            or (counter['counter'] != 0 or key['newCounter'] != 0) and key['newCounter'] <= counter['counter']):
                        _fail()
                    self._db.execute('UPDATE counters SET counter=? WHERE credential=?', (key['newCounter'], key['id']))
                return self._create_session(identity, pending['method'], now)
            return self._transaction(finish)

    def authentication_options(self):
        def read():
            self._publication_idle()
            identities = self._db.execute('SELECT profile FROM identities WHERE active=1').fetchall()
            keys = self._db.execute('SELECT origin FROM recovery_keys WHERE active=1').fetchall()
            if len(identities) > 1 or len(keys) > 1 or not (identities or keys):
                _fail()
            identity = _enrollment(json.loads(identities[0]['profile'])) if identities else None
            origin = identity['origin'] if identity else self._identity('recovery-key')['origin']
            if keys and keys[0]['origin'] != origin:
                _fail()
            return {'origin': origin, 'rpId': urlsplit(origin).hostname,
                    'password': identity is not None, 'recoveryKey': bool(keys),
                    'credentialIds': list(identity['credentials']) if identity else [],
                    'totp': {'password': bool(identity and identity['totpEnabled']),
                             'passkey': bool(identity and identity['totpEnabled'] and identity['requireTotpAfterPasskey'])}}
        return self._transaction(read)

    def _session_record(self, digest, *, origin, csrf_digest=None, fresh=False, touch=True, now=None):
        """Validate within the caller's existing store transaction."""
        now = self._now() if now is None else now
        row = self._db.execute('SELECT * FROM sessions WHERE digest=?', (digest,)).fetchone()
        if row is None:
            _fail()
        identity = self._identity(row['method'])
        if (row['revision'] != identity['revision'] or origin != identity['origin']
                or not 0 <= now - row['created'] <= _SESSION_MS or not 0 <= now - row['touched'] <= _IDLE_MS
                or (csrf_digest is not None and not secrets.compare_digest(csrf_digest, row['csrf']))
                or (fresh and (csrf_digest is None or now - row['created'] > _FRESH_MS))):
            _fail()
        if touch:
            self._db.execute('UPDATE sessions SET touched=? WHERE digest=?', (now, digest))
        return {'accountId': identity.get('accountId'), 'principal': 'recovery-key' if row['method'] == 'recovery-key' else 'orbis-operator',
                'revision': identity['revision'], 'method': row['method'],
                'fresh': now - row['created'] <= _FRESH_MS,
                'expiresAtMs': min((now if touch else row['touched']) + _IDLE_MS, row['created'] + _SESSION_MS)}

    def session(self, *, token, origin, csrf=None, fresh=False, touch=True):
        digest = _token(token)
        csrf_digest = _token(csrf) if csrf is not None else None
        return self._transaction(lambda: self._session_record(digest, origin=origin, csrf_digest=csrf_digest,
                                                              fresh=fresh, touch=touch))

    def logout(self, *, token, origin, csrf):
        digest = _token(token)
        def write():
            self._publication_idle()
            row = self._db.execute('SELECT csrf, revision, method FROM sessions WHERE digest=?', (digest,)).fetchone()
            if row is None:
                return
            identity = self._identity(row['method'])
            if (origin != identity['origin'] or row['revision'] != identity['revision']
                    or not secrets.compare_digest(_token(csrf), row['csrf'])):
                _fail()
            self._db.execute('DELETE FROM sessions WHERE digest=?', (digest,))
        self._transaction(write)

    def close(self):
        with self._mutex:
            if self._closed:
                return
            if self._borrowers.get(threading.get_ident()):
                _fail()
            self._closing = True
            self._idle.notify_all()
            while self._borrowers:
                self._idle.wait()
            if self._closed:
                return
            self._closed = True
            self._return_sessions.clear()
            self._return_deadlines.clear()
            if self._db is not None:
                self._db.close()
                self._db = None
            if self._setup_reservation is not None:
                self._setup_reservation.close()
                self._setup_reservation = None
            for _, fd, _ in reversed(self._files + self._directories):
                os.close(fd)
            self._files.clear()
            self._directories.clear()
