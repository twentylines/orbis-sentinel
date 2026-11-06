"""Durable job records, not an execution lock for external recovery helpers.

A supervisor must hold a separate, shared cross-owner operation lock before
executing work. This store's lock only excludes other instances of this store.
The configured directory must be an existing canonical root-owned 0700 directory.
"""

import fcntl
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import time
import uuid

from .contracts import APPLICATIONS, OPERATIONS, Phase, TERMINAL_PHASES, TRANSITIONS

_OWNER_UID = 0
_MAX_TEXT = 4096
_MAX_METADATA = 8192
_MAX_REPLAY = 500


class StoreError(RuntimeError):
    pass


def _check_file(fd, path):
    opened = os.fstat(fd)
    current = os.lstat(path)
    if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != _OWNER_UID
            or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
        raise StoreError("unsafe or replaced store file")


def _open_private(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        _check_file(fd, path)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _text(value):
    if type(value) is not str or not value or len(value.encode('utf-8')) > _MAX_TEXT or '\x00' in value:
        raise ValueError("event text must be a nonempty string of at most 4096 bytes")
    return value


def _metadata(value):
    if type(value) is not dict or len(value) > 32:
        raise ValueError("metadata must be a dictionary with at most 32 entries")
    for key, item in value.items():
        if (type(key) is not str or not key or len(key.encode('utf-8')) > 128
                or '\x00' in key or type(item) is not str
                or len(item.encode('utf-8')) > 1024 or '\x00' in item):
            raise ValueError("metadata keys and values must be bounded strings")
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(encoded.encode('ascii')) > _MAX_METADATA:
        raise ValueError("metadata is too large")
    return encoded


class JobStore:
    """Exclusive-lifetime store; capabilities are valid only in the issuing instance."""

    def __init__(self, directory):
        directory = os.fspath(directory)
        if not os.path.isabs(directory) or os.path.realpath(directory) != directory:
            raise StoreError("store directory must be canonical")
        info = os.lstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER_UID
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise StoreError("store directory must be root-owned and mode 0700")
        self._directory = directory
        self._pid = os.getpid()
        self._directory_identity = (info.st_dev, info.st_ino)
        self._lock_path = os.path.join(directory, 'jobs.lock')
        self._db_path = os.path.join(directory, 'jobs.sqlite3')
        self._lock_fd = _open_private(self._lock_path)
        self._db_fd = None
        self._db = None
        self._capabilities = {}
        self._mutex = threading.RLock()
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._db_fd = _open_private(self._db_path)
            self._db = sqlite3.connect(self._db_path, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._verify()
            self._db.execute('PRAGMA journal_mode=DELETE')
            self._db.execute('PRAGMA synchronous=EXTRA')
            if self._db.execute('PRAGMA journal_mode').fetchone()[0] != 'delete' or self._db.execute('PRAGMA synchronous').fetchone()[0] != 3:
                raise StoreError('durable journal synchronization is unavailable')
            self._db.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, application TEXT NOT NULL, operation TEXT NOT NULL,
                    metadata TEXT NOT NULL, phase TEXT NOT NULL, claim_hash TEXT,
                    created_ns INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    job_id TEXT NOT NULL REFERENCES jobs(id), seq INTEGER NOT NULL,
                    phase TEXT NOT NULL, text TEXT NOT NULL, created_ns INTEGER NOT NULL,
                    PRIMARY KEY(job_id, seq)
                );
            ''')
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(parent)
                if (info.st_dev, info.st_ino) != self._directory_identity:
                    raise StoreError('store directory changed before synchronization')
                os.fsync(parent)
                self._verify()
            finally:
                os.close(parent)
        except BaseException:
            self.close()
            raise

    def _verify(self):
        if os.getpid() != self._pid:
            raise StoreError('store cannot be used by a forked worker')
        _check_file(self._lock_fd, self._lock_path)
        _check_file(self._db_fd, self._db_path)
        info = os.lstat(self._directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _OWNER_UID
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != self._directory_identity):
            raise StoreError('unsafe store directory')

    def close(self):
        self._capabilities.clear()
        if self._db is not None:
            self._db.close()
            self._db = None
        if self._db_fd is not None:
            os.close(self._db_fd)
            self._db_fd = None
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

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

    def create(self, application, operation, metadata):
        if application not in APPLICATIONS or operation not in OPERATIONS:
            raise ValueError('invalid application or operation')
        data = _metadata(metadata)
        def insert():
            terminal = tuple(p.value for p in TERMINAL_PHASES)
            if self._db.execute('SELECT 1 FROM jobs WHERE phase NOT IN (?,?,?,?) LIMIT 1', terminal).fetchone():
                raise StoreError('an active job already exists')
            job_id = uuid.uuid4().hex
            self._db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)',
                             (job_id, application, operation, data, Phase.QUEUED.value, None, time.time_ns()))
            return job_id
        return self._transaction(insert)

    def claim(self, job_id):
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode('ascii')).hexdigest()
        def update():
            cursor = self._db.execute('UPDATE jobs SET claim_hash=? WHERE id=? AND phase=? AND claim_hash IS NULL',
                                      (digest, job_id, Phase.QUEUED.value))
            if cursor.rowcount != 1:
                raise StoreError('job cannot be claimed')
        with self._mutex:
            self._transaction(update)
            self._capabilities[job_id] = token
            return token

    def _authorize(self, job_id, token):
        known = self._capabilities.get(job_id)
        if type(token) is not str or known is None or not secrets.compare_digest(token, known):
            raise StoreError('invalid capability')
        row = self._db.execute('SELECT phase, claim_hash FROM jobs WHERE id=?', (job_id,)).fetchone()
        if row is None or not secrets.compare_digest(row['claim_hash'] or '', hashlib.sha256(token.encode('ascii')).hexdigest()):
            raise StoreError('invalid capability')
        return Phase(row['phase'])

    def transition(self, job_id, token, phase, text):
        phase = Phase(phase)
        _text(text)
        def update():
            current = self._authorize(job_id, token)
            if phase not in TRANSITIONS.get(current, ()):
                raise StoreError('invalid transition')
            self._db.execute('UPDATE jobs SET phase=? WHERE id=?', (phase.value, job_id))
            self._append(job_id, text)
        self._transaction(update)

    def _append(self, job_id, text):
        self._db.execute('''INSERT INTO events
                            SELECT ?, COALESCE(MAX(seq),0)+1,
                                   (SELECT phase FROM jobs WHERE id=?), ?, ?
                            FROM events WHERE job_id=?''',
                         (job_id, job_id, text, time.time_ns(), job_id))

    def append(self, job_id, token, text):
        _text(text)
        def insert():
            if self._authorize(job_id, token) in TERMINAL_PHASES:
                raise StoreError('terminal job')
            self._append(job_id, text)
        self._transaction(insert)

    def get(self, job_id):
        with self._mutex:
            self._verify()
            row = self._db.execute('SELECT id, application, operation, metadata, phase, created_ns, claim_hash IS NOT NULL AS claimed FROM jobs WHERE id=?', (job_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result['metadata'] = json.loads(result['metadata'])
            result['claimed'] = bool(result['claimed'])
            result['interrupted'] = result['claimed'] and result['phase'] not in {p.value for p in TERMINAL_PHASES} and job_id not in self._capabilities
            return result

    def events(self, job_id, after=0, limit=100):
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= _MAX_REPLAY:
            raise ValueError('invalid replay bounds')
        with self._mutex:
            self._verify()
            return [dict(row) for row in self._db.execute('SELECT seq, phase, text, created_ns FROM events WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?', (job_id, after, limit))]

    def active(self):
        """Discover the pending record after restart without reclaiming its work."""
        with self._mutex:
            self._verify()
            terminal = tuple(p.value for p in TERMINAL_PHASES)
            rows = self._db.execute('SELECT id FROM jobs WHERE phase NOT IN (?,?,?,?) LIMIT 2', terminal).fetchall()
            if len(rows) > 1:
                raise StoreError('multiple active jobs need recovery review')
            return self.get(rows[0]['id']) if rows else None
