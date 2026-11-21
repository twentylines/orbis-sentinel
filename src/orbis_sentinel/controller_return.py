"""Session-owned approval for returning one parked controller, never an effect."""

import json
import re
import secrets

from .recovery_sessions import RecoverySessions, _FRESH_MS, _origin, _token, _fail

_UUID = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}')
_HASH = re.compile(r'[a-f0-9]{64}')
_TTL_MS = 60000
_MAX_APPROVALS = 128


def return_scope(value):
    if (type(value) is not dict or set(value) != {'planId', 'installationId', 'handoffSha256'}
            or type(value['planId']) is not str or not _UUID.fullmatch(value['planId'])
            or any(type(value[key]) is not str or not _HASH.fullmatch(value[key])
                   for key in ('installationId', 'handoffSha256'))):
        _fail()
    return dict(value)


def _identifier(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        _fail()
    return value


class ControllerReturnApprovals:
    """Use the sole Sessions transaction and identity owner; open no new store.

    Browser approval requires a fresh session and CSRF. Only a paired Root
    control consumer may claim it, and must separately validate the live held
    controller before accepting or executing any return. An approval ID alone
    is not a Host operation capability.
    """

    def __init__(self, sessions, *, origin):
        if type(sessions) is not RecoverySessions:
            raise ValueError('Controller return requires the existing Sessions owner.')
        _origin(origin)
        self.sessions, self.origin = sessions, origin

    def _session(self, digest, wall, policy, *, csrf_digest=None):
        born = self.sessions._return_sessions.get(digest)
        if born is None or not 0 <= policy - born < _FRESH_MS:
            _fail()
        session = self.sessions._session_record(digest, origin=self.origin,
            csrf_digest=csrf_digest, fresh=csrf_digest is not None, touch=False, now=wall)
        if not session['fresh']:
            _fail()
        return session, _FRESH_MS - (policy - born)

    def _expiry(self, row, wall, policy):
        deadline = self.sessions._return_deadlines.get(row['id'])
        if deadline is not None and wall >= row['expires']:
            # Remember observed expiration even if the surrounding transaction
            # rejects and rolls back, or the wall clock subsequently moves back.
            self.sessions._return_deadlines[row['id']] = min(deadline, policy)
            _fail()
        if deadline is None or not row['created'] <= wall < row['expires'] or policy >= deadline:
            _fail()
        return min(row['expires'], wall + deadline - policy)

    def readiness(self):
        """Read the same enrolled identities and approval table without issuing a grant."""
        def read():
            if any(self.sessions._identity(method)['origin'] != self.origin
                   for method in ('password', 'recovery-key')):
                _fail()
            self.sessions._db.execute(
                'SELECT id, scope, session, created, expires, claim FROM controller_return_approvals LIMIT 0')

        self.sessions._transaction(read)

    def approve(self, *, token, csrf, origin, scope, check=None):
        if origin != self.origin:
            _fail()
        scope = return_scope(scope)
        encoded = json.dumps(scope, sort_keys=True, separators=(',', ':'))
        session_digest, csrf_digest = _token(token), _token(csrf)

        def issue():
            if check is not None:
                check()
            now, policy = self.sessions._return_now()
            session, remaining = self._session(session_digest, now, policy, csrf_digest=csrf_digest)
            row = self.sessions._db.execute('SELECT created FROM sessions WHERE digest=?', (session_digest,)).fetchone()
            expires = min(now + _TTL_MS, now + remaining, session['expiresAtMs'], row['created'] + _FRESH_MS)
            if expires <= now:
                _fail()
            self.sessions._db.execute('DELETE FROM controller_return_approvals WHERE expires<=?', (now,))
            expired = [(key,) for key, deadline in self.sessions._return_deadlines.items() if deadline <= policy]
            self.sessions._db.executemany('DELETE FROM controller_return_approvals WHERE id=?', expired)
            live = {item[0] for item in self.sessions._db.execute('SELECT id FROM controller_return_approvals')}
            self.sessions._return_deadlines = {key: value for key, value in self.sessions._return_deadlines.items() if key in live}
            existing = self.sessions._db.execute(
                'SELECT * FROM controller_return_approvals WHERE scope=? AND session=?',
                (encoded, session_digest)).fetchall()
            if len(existing) > 1:
                _fail()
            if existing:
                expiry = self._expiry(existing[0], now, policy)
                if check is not None:
                    check()
                return {'approvalId': existing[0]['id'], 'scope': scope, 'expiresAtMs': expiry}
            if self.sessions._db.execute('SELECT count(*) FROM controller_return_approvals').fetchone()[0] >= _MAX_APPROVALS:
                _fail()
            identifier = secrets.token_hex(32)
            if check is not None:
                check()
            self.sessions._db.execute('INSERT INTO controller_return_approvals VALUES (?,?,?,?,?,NULL)',
                                     (identifier, encoded, session_digest, now, expires))
            self.sessions._return_deadlines[identifier] = policy + expires - now
            return {'approvalId': identifier, 'scope': scope, 'expiresAtMs': expires}

        return self.sessions._transaction(issue)

    def authorize(self, *, token, csrf, origin, scope, approval_id, check=None):
        """Confirm the dispatching browser owns this approval without claiming it."""
        if origin != self.origin:
            _fail()
        encoded = json.dumps(return_scope(scope), sort_keys=True, separators=(',', ':'))
        approval_id, session_digest, csrf_digest = _identifier(approval_id), _token(token), _token(csrf)

        def read():
            if check is not None:
                check()
            now, policy = self.sessions._return_now()
            self._session(session_digest, now, policy, csrf_digest=csrf_digest)
            row = self.sessions._db.execute('SELECT * FROM controller_return_approvals WHERE id=?', (approval_id,)).fetchone()
            if row is None or row['scope'] != encoded or row['session'] != session_digest:
                _fail()
            self._expiry(row, now, policy)
            if check is not None:
                check()

        self.sessions._transaction(read)

    def claim(self, *, approval_id, scope, claim_id):
        """Fixed Root IPC decision, replayable only for the identical claim."""
        approval_id, claim_id = _identifier(approval_id), _identifier(claim_id)
        scope = return_scope(scope)
        encoded = json.dumps(scope, sort_keys=True, separators=(',', ':'))

        def consume():
            now, policy = self.sessions._return_now()
            row = self.sessions._db.execute('SELECT * FROM controller_return_approvals WHERE id=?', (approval_id,)).fetchone()
            if row is None or row['scope'] != encoded or row['claim'] not in (None, claim_id):
                _fail()
            expires = self._expiry(row, now, policy)
            session, _ = self._session(row['session'], now, policy)
            if row['claim'] is None:
                self.sessions._db.execute('UPDATE controller_return_approvals SET claim=? WHERE id=?', (claim_id, approval_id))
            return {'approved': True, 'approvalId': approval_id, 'scope': scope, 'claimId': claim_id,
                    'expiresAtMs': expires, 'principal': session['principal'],
                    'method': session['method'], 'revision': session['revision']}

        return self.sessions._transaction(consume)
