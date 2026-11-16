"""Root-owned recovery sessions; these records never authorize host operations."""

import base64
import fcntl
import hashlib
import json
import os
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
    """One privileged owner; verifier callbacks run only after durable consumption.

    Enrollment is an internal supervisor action, never browser input. Its digest,
    factors and counters must describe the same protected profile passed to the
    credential worker. The gateway still enforces TLS, Host/Origin and cookie policy.
    """

    def __init__(self, directory, *, clock=None):
        self._clock = clock or (lambda: time.time_ns() // 1_000_000)
        self._pid = os.getpid()
        self._mutex = threading.RLock()
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
            ''')
            # No pre-restart browser authority survives a new owner instance.
            self._transaction(lambda: (self._db.execute('DELETE FROM challenges'), self._db.execute('DELETE FROM sessions')))
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

    def _verify(self):
        if self._closed or os.getpid() != self._pid:
            _fail()
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

    def _identity(self, method='password'):
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

    def enroll(self, profile):
        profile = _enrollment(profile)
        encoded = json.dumps(profile, sort_keys=True, separators=(',', ':'))
        def write():
            key = self._db.execute('SELECT origin FROM recovery_keys WHERE active=1').fetchone()
            if key and key['origin'] != profile['origin']:
                _fail()
            known = self._db.execute('SELECT profile, active FROM identities WHERE revision=?', (profile['revision'],)).fetchone()
            if known:
                if known['profile'] != encoded or known['active'] != 1:
                    _fail()
                return
            if self._db.execute('SELECT count(*) FROM identities').fetchone()[0] >= 1024:
                _fail()
            self._db.execute('UPDATE identities SET active=0')
            self._db.execute('INSERT INTO identities VALUES (?,?,1)', (profile['revision'], encoded))
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method!='recovery-key'")
            self._db.executemany('INSERT INTO counters VALUES (?,?) ON CONFLICT(credential) DO UPDATE SET counter=MAX(counter,excluded.counter)',
                                 profile['credentials'].items())
        self._transaction(write)

    def revoke(self):
        def write():
            self._db.execute('UPDATE identities SET active=0')
            self._db.execute("DELETE FROM challenges WHERE method!='recovery-key'")
            self._db.execute("DELETE FROM sessions WHERE method!='recovery-key'")
        self._transaction(write)

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
            if self._identity('recovery-key')['revision'] != expected_revision:
                _fail()
            self._db.execute('UPDATE recovery_keys SET active=0')
            for table in ('challenges', 'sessions'):
                self._db.execute('DELETE FROM ' + table + " WHERE method='recovery-key'")
        self._transaction(write)

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
            if self._db.execute('SELECT count(*) FROM challenges').fetchone()[0] >= 32:
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
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._db.execute('DELETE FROM sessions WHERE created<? OR touched<?', (now - _SESSION_MS, now - _IDLE_MS))
        if self._db.execute('SELECT count(*) FROM sessions').fetchone()[0] >= 16:
            _fail()
        self._db.execute('INSERT INTO sessions VALUES (?,?,?,?,?,?)', (_token(token), _token(csrf), identity['revision'], method, now, now))
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
        with self._mutex:
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

    def session(self, *, token, origin, csrf=None, fresh=False, touch=True):
        digest = _token(token)
        csrf_digest = _token(csrf) if csrf is not None else None
        def read():
            now = self._now()
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
        return self._transaction(read)

    def logout(self, *, token, origin, csrf):
        digest = _token(token)
        def write():
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
            self._closed = True
            if self._db is not None:
                self._db.close()
                self._db = None
            for _, fd, _ in reversed(self._files + self._directories):
                os.close(fd)
            self._files.clear()
            self._directories.clear()
