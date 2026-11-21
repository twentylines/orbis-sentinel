"""Main-only WebAuthn counter proofs; never recovery sessions or action grants."""
import hashlib
import json
import secrets
from urllib.parse import urlsplit

from . import recovery_sessions as sessions
from .recovery_config import _pairs

_CHALLENGE_SCHEMA = 'orbis.sentinel-main-passkey-challenge.v1'
_COUNTER_SCHEMA = 'orbis.sentinel-main-passkey-counter.v1'
_PROOF_SCHEMA = 'orbis.sentinel-passkey-counter.v1'
_LIMIT = 32
_RECEIPTS = 128
_TTL = 120_000


def _fail():
    raise ValueError('Main passkey verification could not be completed.') from None


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _hash(value):
    return type(value) is str and sessions._HEX.fullmatch(value) is not None


def _binding(admission, purpose, ceremony):
    if not _hash(admission) or purpose not in ('login', 'sensitive') or not _hash(ceremony):
        _fail()
    return {'admissionBinding': admission, 'purpose': purpose, 'ceremonyBinding': ceremony}


def _record(body, *, receipt=False):
    if type(body) is not str or not 1 <= len(body) <= 8192:
        _fail()
    value = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    fields = {'admissionBinding', 'purpose', 'ceremonyBinding', 'generation', 'revision', 'identitySha256',
              'accountId', 'origin', 'created'}
    if receipt:
        fields |= {'requestSha256', 'result'}
    if (type(value) is not dict or set(value) != fields
            or not sessions._integer(value['generation']) or not _hash(value['revision'])
            or not _hash(value['identitySha256']) or not sessions._integer(value['accountId'], 1)
            or not sessions._integer(value['created'], 1)):
        _fail()
    _binding(value['admissionBinding'], value['purpose'], value['ceremonyBinding'])
    sessions._origin(value['origin'])
    if receipt and (not _hash(value['requestSha256']) or type(value['result']) is not dict):
        _fail()
    return value


class RecoveryMainPasskeys:
    def __init__(self, store, profiles, *, origin):
        if profiles._store is not store:
            _fail()
        self.store, self.profiles, self.origin = store, profiles, sessions._origin(origin)

    def _current(self):
        self.store._publication_idle()
        status = self.store._operator_status()
        if status['state'] != 'enrolled':
            _fail()
        identity = self.store._identity()
        if identity['origin'] != self.origin or identity['revision'] != status['revision']:
            _fail()
        return status, identity

    def _matches(self, record):
        status, identity = self._current()
        if (status['generation'] != record['generation'] or status['revision'] != record['revision']
                or identity['identitySha256'] != record['identitySha256'] or identity['accountId'] != record['accountId']
                or identity['origin'] != record['origin']):
            _fail()
        return identity

    def _prune(self, now):
        # Completed nonce evidence is needed only during the challenge lifetime.
        # An expired, deleted nonce cannot be replayed as a new challenge.
        for table, receipt in (('main_passkey_challenges', False), ('main_passkey_receipts', True)):
            for row in self.store._db.execute('SELECT digest,record FROM ' + table).fetchall():
                value = _record(row['record'], receipt=receipt)
                if now - value['created'] > _TTL:
                    self.store._db.execute('DELETE FROM ' + table + ' WHERE digest=?', (row['digest'],))

    def challenge(self, *, admission_binding, purpose, ceremony_binding):
        binding = _binding(admission_binding, purpose, ceremony_binding)
        raw = secrets.token_urlsafe(32)
        def write():
            now = self.store._now()
            status, identity = self._current()
            if not identity['credentials']:
                _fail()
            self._prune(now)
            if self.store._db.execute('SELECT count(*) FROM main_passkey_challenges').fetchone()[0] >= _LIMIT:
                _fail()
            record = {**binding, 'generation': status['generation'], 'revision': status['revision'],
                      'identitySha256': identity['identitySha256'], 'accountId': identity['accountId'],
                      'origin': self.origin, 'created': now}
            self.store._db.execute('INSERT INTO main_passkey_challenges VALUES (?,?)', (sessions._token(raw), _encoded(record)))
            return {'schema': _CHALLENGE_SCHEMA, 'challenge': raw, 'expiresAtMs': now + _TTL,
                    'generation': status['generation'], 'revision': status['revision'], 'accountId': identity['accountId'],
                    'rpID': urlsplit(self.origin).hostname, 'credentialIds': sorted(identity['credentials'])}
        return self.store._transaction(write)

    def complete(self, *, challenge, admission_binding, purpose, ceremony_binding, response):
        binding = _binding(admission_binding, purpose, ceremony_binding)
        nonce = sessions._token(challenge)
        if type(response) is not dict:
            _fail()
        try:
            request = _encoded({'challenge': challenge, **binding, 'response': response}).encode('ascii')
        except Exception:
            _fail()
        if not 1 <= len(request) <= 32768:
            _fail()
        request_sha = hashlib.sha256(request).hexdigest()
        with self.store._borrow():
            def consume():
                self.store._publication_idle()
                now = self.store._now()
                self._prune(now)
                known = self.store._db.execute('SELECT record FROM main_passkey_receipts WHERE digest=?', (nonce,)).fetchone()
                if known is not None:
                    record = _record(known['record'], receipt=True)
                    if (any(record[key] != value for key, value in binding.items()) or record['requestSha256'] != request_sha
                            or not 0 <= now - record['created'] <= _TTL):
                        _fail()
                    identity = self._matches(record)
                    result = self._receipt(record, challenge, identity)
                    return record, identity, result
                row = self.store._db.execute('SELECT record FROM main_passkey_challenges WHERE digest=?', (nonce,)).fetchone()
                if row is None:
                    _fail()
                record = _record(row['record'])
                if any(record[key] != value for key, value in binding.items()) or not 0 <= now - record['created'] <= _TTL:
                    _fail()
                identity = self._matches(record)
                rate = self.store._db.execute('SELECT start,count FROM main_passkey_attempts WHERE id=1').fetchone()
                if rate is not None and (now < rate['start'] or now - rate['start'] < 60000 and rate['count'] >= 10):
                    _fail()
                start, count = (rate['start'], rate['count'] + 1) if rate and now - rate['start'] < 60000 else (now, 1)
                self.store._db.execute('INSERT OR REPLACE INTO main_passkey_attempts VALUES (1,?,?)', (start, count))
                self.store._db.execute('DELETE FROM main_passkey_challenges WHERE digest=?', (nonce,))
                return record, identity, None
            record, identity, repeated = self.store._transaction(consume)
            if repeated is not None:
                return repeated
            # Consumption is committed before the independently retained worker runs.
            proof = self.profiles.verify_counter(identity['identitySha256'], challenge, response)
            def finish():
                now = self.store._now()
                if not 0 <= now - record['created'] <= _TTL or self._matches(record) != identity:
                    _fail()
                fields = {'schema', 'verified', 'accountId', 'revision', 'identitySha256', 'challenge', 'verifiedAtMs', 'credential'}
                if (type(proof) is not dict or set(proof) != fields or proof['schema'] != _PROOF_SCHEMA
                        or proof['verified'] is not True or type(proof['accountId']) is not int
                        or proof['accountId'] != identity['accountId'] or proof['revision'] != identity['revision']
                        or proof['identitySha256'] != identity['identitySha256'] or proof['challenge'] != challenge
                        or not sessions._integer(proof['verifiedAtMs'], record['created'], now) or now - proof['verifiedAtMs'] > 5000):
                    _fail()
                credential = proof['credential']
                if (type(credential) is not dict or set(credential) != {'id', 'previousCounter', 'newCounter'}
                        or type(credential['id']) is not str or credential['id'] not in identity['credentials']
                        or not sessions._integer(credential['previousCounter'], 0, 0xffffffff)
                        or credential['previousCounter'] != identity['credentials'][credential['id']]
                        or not sessions._integer(credential['newCounter'], 0, 0xffffffff)):
                    _fail()
                floor = self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (credential['id'],)).fetchone()
                if (floor is None or not sessions._integer(floor['counter'], credential['previousCounter'], 0xffffffff)
                        or (floor['counter'] != 0 or credential['newCounter'] != 0) and credential['newCounter'] <= floor['counter']):
                    _fail()
                if self.store._db.execute('SELECT count(*) FROM main_passkey_receipts').fetchone()[0] >= _RECEIPTS:
                    _fail()
                self.store._db.execute('UPDATE counters SET counter=? WHERE credential=?', (credential['newCounter'], credential['id']))
                result = {'schema': _COUNTER_SCHEMA, 'challenge': challenge, 'generation': record['generation'],
                          'revision': record['revision'], 'accountId': identity['accountId'], 'credentialId': credential['id'],
                          'previousCounter': floor['counter'], 'newCounter': credential['newCounter'],
                          'expiresAtMs': record['created'] + _TTL}
                saved = {**record, 'requestSha256': request_sha, 'result': result}
                self.store._db.execute('INSERT INTO main_passkey_receipts VALUES (?,?)', (nonce, _encoded(saved)))
                return result
            return self.store._transaction(finish)

    def _receipt(self, record, challenge, identity):
        result = record['result']
        fields = {'schema', 'challenge', 'generation', 'revision', 'accountId', 'credentialId',
                  'previousCounter', 'newCounter', 'expiresAtMs'}
        if (set(result) != fields or result['schema'] != _COUNTER_SCHEMA or result['challenge'] != challenge
                or not sessions._integer(result['generation']) or result['generation'] != record['generation']
                or result['revision'] != record['revision']
                or not sessions._integer(result['accountId'], 1) or result['accountId'] != record['accountId']
                or type(result['credentialId']) is not str
                or result['credentialId'] not in identity['credentials']
                or not sessions._integer(result['previousCounter'], identity['credentials'][result['credentialId']], 0xffffffff)
                or not sessions._integer(result['newCounter'], 0, 0xffffffff)
                or (result['previousCounter'] != 0 or result['newCounter'] != 0) and result['newCounter'] <= result['previousCounter']
                or not sessions._integer(result['expiresAtMs'], 1) or result['expiresAtMs'] != record['created'] + _TTL):
            _fail()
        floor = self.store._db.execute('SELECT counter FROM counters WHERE credential=?', (result['credentialId'],)).fetchone()
        if floor is None or not sessions._integer(floor['counter'], result['newCounter'], 0xffffffff):
            _fail()
        return dict(result)
