"""Root-issued revision changes with independent, full-content worker proof.

This does not serialize Main writers or prove where a supplied source was read.
The installation supervisor must journal its token before IPC and collect the
planned and postcommit Main snapshots under its separate writer exclusion.
"""

from dataclasses import dataclass
import hashlib
import json
import secrets

from . import recovery_sessions as sessions
from .recovery_config import _pairs
from .recovery_profiles import RecoveryProfileError

_SCHEMA = 'orbis.sentinel-identity-content.v1'
_MAX = 1024


def _fail():
    raise RecoveryProfileError('The protected recovery incarnation is unavailable.') from None


def _hash(value):
    return type(value) is str and sessions._HEX.fullmatch(value) is not None


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _revision(source, nonce):
    return hashlib.sha256(b'orbis.sentinel-incarnation.v1\0' + _encoded([source, nonce]).encode('ascii')).hexdigest()


def _request(token, source, content, origin, generation, baseline):
    return hashlib.sha256(b'orbis.sentinel-incarnation-request.v1\0' +
                          _encoded([token, source, content, origin, generation, baseline]).encode('ascii')).hexdigest()


def _record(body, token):
    if type(body) is not str or not 1 <= len(body) <= 4096:
        _fail()
    value = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    fields = {'source', 'sourceRevision', 'content', 'origin', 'generation', 'baseline', 'nonce', 'revision', 'target', 'request'}
    if (type(value) is not dict or set(value) != fields or not _hash(token)
            or not all(_hash(value[key]) for key in ('source', 'sourceRevision', 'content', 'nonce', 'revision', 'target', 'request'))
            or not sessions._integer(value['generation'], 0, 9_007_199_254_740_988)
            or (value['baseline'] is not None and not _hash(value['baseline']))):
        _fail()
    sessions._origin(value['origin'])
    if (value['revision'] != _revision(value['source'], value['nonce'])
            or value['request'] != _request(token, value['source'], value['content'], value['origin'],
                                            value['generation'], value['baseline'])):
        _fail()
    return value


@dataclass(frozen=True)
class _SourceProof:
    owner: object
    token: str
    source: str
    target: str
    content: str


@dataclass(frozen=True)
class _BaselineProof:
    owner: object
    source: str
    content: str
    snapshot: str


@dataclass(frozen=True)
class _WriterRequestProof:
    owner: object
    token: str
    baseline: str
    source: str


def _writer_request(token, baseline, source, generation, revision, origin):
    return hashlib.sha256(b'orbis.sentinel-writer-request.v1\0' +
                          _encoded([token, baseline, source, generation, revision, origin]).encode('ascii')).hexdigest()


def _writer_record(body, token):
    if type(body) is not str or not 1 <= len(body) <= 2048 or not _hash(token):
        _fail()
    value = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    fields = {'baseline', 'source', 'generation', 'revision', 'origin', 'request'}
    if (type(value) is not dict or set(value) != fields
            or not all(_hash(value[key]) for key in ('baseline', 'source', 'revision', 'request'))
            or not sessions._integer(value['generation'], 0, 9_007_199_254_740_988)):
        _fail()
    sessions._origin(value['origin'])
    if value['request'] != _writer_request(token, value['baseline'], value['source'], value['generation'], value['revision'], value['origin']):
        _fail()
    return value


def _baseline_snapshot(store, origin, generation, revision):
    store._publication_idle()
    status = store._operator_status()
    if status['state'] != 'enrolled' or status['generation'] != generation or status['revision'] != revision:
        _fail()
    identity = store._identity()
    if identity['revision'] != revision or identity['origin'] != origin:
        _fail()
    counters = {}
    for credential, counter in identity['credentials'].items():
        row = store._db.execute('SELECT counter FROM counters WHERE credential=?', (credential,)).fetchone()
        if row is None or not sessions._integer(row['counter'], counter, 0xffffffff):
            _fail()
        counters[credential] = row['counter']
    return {'status': status, 'identity': identity, 'counters': counters}


def _assert_baseline(store, proof, request):
    if (type(proof) is not _BaselineProof or proof.owner is not store or proof.source != request['baseline']
            or not _hash(proof.content) or type(proof.snapshot) is not str):
        _fail()
    current = _baseline_snapshot(store, request['origin'], request['generation'], request['revision'])
    if _encoded(current) != proof.snapshot:
        _fail()


class RecoveryIncarnations:
    def __init__(self, store, profiles, *, inspect, origin, inspect_effective=None):
        if (profiles._store is not store or not callable(inspect)
                or inspect_effective is not None and not callable(inspect_effective)):
            _fail()
        self.store, self.profiles, self.inspect = store, profiles, inspect
        self.inspect_effective = inspect_effective
        self.origin = sessions._origin(origin)

    def _content(self, prepared):
        def inspect(directory, digest):
            value = self.inspect(directory, digest)
            if (type(value) is not dict or set(value) != {'schema', 'identitySha256', 'contentSha256', 'description'}
                    or value['schema'] != _SCHEMA or value['identitySha256'] != digest or not _hash(value['contentSha256'])
                    or type(value['description']) is not dict
                    or value['description'].get('schema') != 'orbis.sentinel-identity-description.v1'):
                _fail()
            metadata = sessions._enrollment({key: item for key, item in value['description'].items() if key != 'schema'})
            if (_encoded(metadata) != prepared._metadata or metadata['identitySha256'] != digest
                    or metadata['origin'] != self.origin):
                _fail()
            return value['contentSha256']
        return self.profiles._run(self.profiles._prepared(prepared), inspect, durable=True)

    def _effective_content(self, prepared, counters):
        metadata = json.loads(prepared._metadata)
        if (type(counters) is not dict or set(counters) != set(metadata['credentials'])
                or any(not sessions._integer(value, metadata['credentials'][key], 0xffffffff)
                       for key, value in counters.items())):
            _fail()
        if counters == metadata['credentials']:
            return self._content(prepared)
        if self.inspect_effective is None:
            _fail()
        def inspect(directory, digest):
            value = self.inspect_effective(directory, digest, dict(counters))
            if (type(value) is not dict or set(value) != {'schema', 'identitySha256', 'contentSha256', 'description'}
                    or value['schema'] != 'orbis.sentinel-effective-identity-content.v1'
                    or value['identitySha256'] != digest or not _hash(value['contentSha256'])
                    or type(value['description']) is not dict
                    or value['description'].get('schema') != 'orbis.sentinel-identity-description.v1'):
                _fail()
            original = sessions._enrollment({key: item for key, item in value['description'].items() if key != 'schema'})
            if _encoded(original) != prepared._metadata or original['origin'] != self.origin:
                _fail()
            return value['contentSha256']
        return self.profiles._run(self.profiles._prepared(prepared), inspect, durable=True)

    @staticmethod
    def _rewrite(body, revision):
        value = json.loads(body.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
        if type(value) is not dict or not _hash(value.get('revision')):
            _fail()
        value['revision'] = revision
        result = json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
        if not 1 <= len(result) <= 65536:
            _fail()
        return result

    def _current(self, record, token):
        self.store._publication_idle()
        status = self.store._operator_status()
        if status['state'] == 'pending':
            state = self.store._operator_enrollment()
            if (state['generation'] != record['generation'] + 1 or state['nonce'] != token
                    or state['target'] != record['target'] or state['origin'] != record['origin']):
                _fail()
        elif status['generation'] != record['generation'] or status['revision'] != record['baseline']:
            _fail()
        for table in ('identities', 'recovery_keys'):
            column = 'profile' if table == 'identities' else 'origin'
            for row in self.store._db.execute('SELECT ' + column + ' FROM ' + table + ' WHERE active=1'):
                origin = sessions._enrollment(json.loads(row['profile']))['origin'] if table == 'identities' else row['origin']
                if origin != self.origin:
                    _fail()

    def _load(self, token):
        row = self.store._db.execute('SELECT record FROM operator_incarnations WHERE token=?', (token,)).fetchone()
        if row is None:
            _fail()
        record = _record(row['record'], token)
        if record['origin'] != self.origin:
            _fail()
        self._current(record, token)
        return record

    def _retained(self, record):
        source = self.profiles.inspect_retained(record['source'])
        target = self.profiles.inspect_retained(record['target'])
        source_metadata, target_metadata = json.loads(source._metadata), json.loads(target._metadata)
        if (source_metadata['revision'] != record['sourceRevision'] or target_metadata['revision'] != record['revision']
                or {k: v for k, v in source_metadata.items() if k not in ('revision', 'identitySha256')}
                != {k: v for k, v in target_metadata.items() if k not in ('revision', 'identitySha256')}
                or self._content(source) != record['content'] or self._content(target) != record['content']):
            _fail()
        return target

    def check_source(self, identity_bytes, *, expected_generation, expected_revision):
        """Compare a fenced Main baseline with the current protected authority.

        This grants no mutation permission and does not prove where Main's bytes
        were collected. The host must independently admit that producer/fence.
        Root counter floors are part of the same atomic baseline proof. Main
        must first catch up to them; a stale or future vector is not equivalent.
        """
        with self.profiles._operation():
            proof = self._baseline(identity_bytes, expected_generation, expected_revision)
            return {'sourceSha256': proof.source, 'contentSha256': proof.content,
                    'generation': expected_generation, 'revision': expected_revision}

    def _baseline(self, identity_bytes, generation, revision):
        if not sessions._integer(generation) or not _hash(revision):
            _fail()
        def current():
            return _baseline_snapshot(self.store, self.origin, generation, revision)
        baseline = self.store._transaction(current)
        source = self.profiles.prepare(identity_bytes)
        active = self.profiles.inspect_retained(baseline['identity']['identitySha256'])
        source_metadata, active_metadata = json.loads(source._metadata), json.loads(active._metadata)
        content = self._content(source)
        if (active_metadata != baseline['identity'] or source_metadata['credentials'] != baseline['counters']
                or {k: v for k, v in source_metadata.items() if k not in ('revision', 'identitySha256', 'credentials')}
                != {k: v for k, v in active_metadata.items() if k not in ('revision', 'identitySha256', 'credentials')}
                or self._effective_content(active, baseline['counters']) != content):
            _fail()
        if self.store._transaction(current) != baseline:
            _fail()
        return _BaselineProof(self.store, source.digest, content, _encoded(baseline))

    def counter_floors(self, identity_bytes, *, expected_generation, expected_revision):
        """Read an exact bound monotonic catch-up vector, granting no write/session."""
        if not sessions._integer(expected_generation) or not _hash(expected_revision):
            _fail()
        with self.profiles._operation():
            def current():
                return _baseline_snapshot(self.store, self.origin, expected_generation, expected_revision)
            baseline = self.store._transaction(current)
            source = self.profiles.prepare(identity_bytes)
            active = self.profiles.inspect_retained(baseline['identity']['identitySha256'])
            source_metadata, active_metadata = json.loads(source._metadata), json.loads(active._metadata)
            floors = baseline['counters']
            if (active_metadata != baseline['identity'] or set(source_metadata['credentials']) != set(floors)
                    or any(source_metadata['credentials'][key] > floor for key, floor in floors.items())
                    or {k: v for k, v in source_metadata.items() if k not in ('revision', 'identitySha256', 'credentials')}
                    != {k: v for k, v in active_metadata.items() if k not in ('revision', 'identitySha256', 'credentials')}
                    or self._effective_content(source, floors) != self._effective_content(active, floors)
                    or self.store._transaction(current) != baseline):
                _fail()
            return {'sourceSha256': source.digest, 'generation': expected_generation,
                    'revision': expected_revision, 'counters': dict(floors)}

    @staticmethod
    def _surviving_counters(baseline_bytes, planned_bytes):
        def counters(body):
            value = json.loads(body.decode('utf-8'), object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
            keys = value.get('credentials') if type(value) is dict else None
            if type(keys) is not list or len(keys) > 10:
                _fail()
            result = {}
            for key in keys:
                if (type(key) is not dict or type(key.get('id')) is not str or not key['id']
                        or key['id'] in result or not sessions._integer(key.get('counter'), 0, 0xffffffff)):
                    _fail()
                result[key['id']] = key['counter']
            return result
        # Both exact bodies were independently admitted by the worker first.
        before, after = counters(baseline_bytes), counters(planned_bytes)
        if any(after[key] != before[key] for key in before.keys() & after.keys()):
            _fail()

    def prepare_writer(self, baseline_bytes, identity_bytes, *, expected_generation, expected_revision, change_token):
        """Reserve and revoke only an inspected, current managed baseline.

        Authority changes cannot advance/reset surviving credential counters;
        their separate floor protocol must synchronize them before this call.
        """
        token = sessions._token(change_token)
        if (not sessions._integer(expected_generation, 0, 9_007_199_254_740_988) or not _hash(expected_revision)
                or any(type(body) is not bytes or not 1 <= len(body) <= 65536 for body in (baseline_bytes, identity_bytes))):
            _fail()
        baseline_digest = hashlib.sha256(baseline_bytes).hexdigest()
        source_digest = hashlib.sha256(identity_bytes).hexdigest()
        request = {'baseline': baseline_digest, 'source': source_digest, 'generation': expected_generation,
                   'revision': expected_revision, 'origin': self.origin,
                   'request': _writer_request(token, baseline_digest, source_digest, expected_generation, expected_revision, self.origin)}
        with self.profiles._operation():
            def prior():
                self.store._publication_idle()
                row = self.store._db.execute('SELECT record FROM operator_writer_requests WHERE token=?', (token,)).fetchone()
                if row is not None and _writer_record(row['record'], token) != request:
                    _fail()
                return row is not None, self.store._operator_status()
            known, status = self.store._transaction(prior)
            pending = status['state'] == 'pending'
            proof = None
            if pending:
                if not known:
                    _fail()
                baseline = self.profiles.inspect_retained(baseline_digest)
                self._content(baseline)
            else:
                proof = self._baseline(baseline_bytes, expected_generation, expected_revision)
                baseline = self.profiles.inspect_retained(baseline_digest)
            planned = self.profiles.prepare(identity_bytes)
            self._content(planned)
            before_metadata, after_metadata = json.loads(baseline._metadata), json.loads(planned._metadata)
            if before_metadata['accountId'] != after_metadata['accountId']:
                _fail()
            self._surviving_counters(baseline_bytes, identity_bytes)

            def reserve():
                self.store._publication_idle()
                row = self.store._db.execute('SELECT record FROM operator_writer_requests WHERE token=?', (token,)).fetchone()
                if row is not None:
                    if _writer_record(row['record'], token) != request:
                        _fail()
                    return
                if (proof is None or self.store._db.execute('SELECT count(*) FROM operator_writer_requests').fetchone()[0] >= _MAX
                        or self.store._db.execute('SELECT 1 FROM operator_prepared_begins WHERE token=?', (token,)).fetchone()
                        or self.store._db.execute('SELECT 1 FROM operator_incarnations WHERE token=?', (token,)).fetchone()):
                    _fail()
                _assert_baseline(self.store, proof, request)
                self.store._db.execute('INSERT INTO operator_writer_requests VALUES (?,?)', (token, _encoded(request)))
            self.store._transaction(reserve)
            staged = self.stage(identity_bytes, expected_generation=expected_generation,
                                expected_revision=expected_revision, change_token=change_token)
            if not pending:
                proof = self._baseline(baseline_bytes, expected_generation, expected_revision)
            witness = _WriterRequestProof(self.store, token, baseline_digest, source_digest)
            target = self.profiles.inspect_retained(staged['identitySha256'])
            begun = self.profiles.begin(target, expected_generation=expected_generation, expected_revision=expected_revision,
                                        change_token=change_token, _baseline_proof=proof, _writer_proof=witness)
            return {'baselineSha256': baseline_digest, **staged, 'generation': begun['generation']}

    def stage(self, identity_bytes, *, expected_generation, expected_revision, change_token):
        token = sessions._token(change_token)
        if (not sessions._integer(expected_generation, 0, 9_007_199_254_740_988)
                or (expected_revision is not None and not _hash(expected_revision))):
            _fail()
        with self.profiles._operation():
            self.store._transaction(self.store._publication_idle)
            source = self.profiles.prepare(identity_bytes)
            content = self._content(source)
            request = _request(token, source.digest, content, self.origin, expected_generation, expected_revision)
            def reserve():
                writers = self.store._db.execute('SELECT token,record FROM operator_writer_requests LIMIT 1025').fetchall()
                if len(writers) > _MAX:
                    _fail()
                requests = {row['token']: _writer_record(row['record'], row['token']) for row in writers}
                if any(value['source'] == source.digest for value in requests.values()):
                    owned = requests.get(token)
                    if (owned is None or owned['source'] != source.digest or owned['generation'] != expected_generation
                            or owned['revision'] != expected_revision or owned['origin'] != self.origin):
                        _fail()
                row = self.store._db.execute('SELECT record FROM operator_incarnations WHERE token=?', (token,)).fetchone()
                if row is not None:
                    record = _record(row['record'], token)
                    if record['request'] != request:
                        _fail()
                    self._current(record, token)
                    return record
                if (self.store._db.execute('SELECT count(*) FROM operator_incarnations').fetchone()[0] >= _MAX
                        or self.store._db.execute('SELECT 1 FROM operator_prepared_begins WHERE token=?', (token,)).fetchone()):
                    _fail()
                nonce = secrets.token_hex(32)
                revision = _revision(source.digest, nonce)
                if self.store._db.execute('SELECT 1 FROM identities WHERE revision=?', (revision,)).fetchone():
                    _fail()
                body = self._rewrite(identity_bytes, revision)
                record = {'source': source.digest, 'sourceRevision': json.loads(source._metadata)['revision'], 'content': content,
                          'origin': self.origin, 'generation': expected_generation, 'baseline': expected_revision,
                          'nonce': nonce, 'revision': revision, 'target': hashlib.sha256(body).hexdigest(), 'request': request}
                self._current(record, token)
                self.store._db.execute('INSERT INTO operator_incarnations VALUES (?,?)', (token, _encoded(record)))
                return record
            record = self.store._transaction(reserve)
            # The immutable operation mapping is committed before any candidate file.
            target = self.profiles.prepare(self._rewrite(identity_bytes, record['revision']))
            if target.digest != record['target']:
                _fail()
            self._retained(record)
            self.store._transaction(lambda: self._load(token))
            return {'sourceSha256': record['source'], 'identitySha256': record['target'], 'revision': record['revision'],
                    'contentSha256': record['content']}

    def begin(self, *, change_token):
        token = sessions._token(change_token)
        with self.profiles._operation():
            record = self.store._transaction(lambda: self._load(token))
            target = self._retained(record)
            return self.profiles.begin(target, expected_generation=record['generation'], expected_revision=record['baseline'],
                                       change_token=change_token)

    def complete(self, identity_bytes, *, change_token, expected_generation):
        token = sessions._token(change_token)
        with self.profiles._operation():
            record = self.store._transaction(lambda: self._load(token))
            if expected_generation != record['generation'] + 1 or type(expected_generation) is not int:
                _fail()
            fresh = self.profiles.prepare(identity_bytes)
            if fresh.digest != record['source'] or self._content(fresh) != record['content']:
                _fail()
            target = self._retained(record)
            proof = _SourceProof(self.store, token, fresh.digest, target.digest, record['content'])
            return self.profiles.complete(target, change_token=change_token, expected_generation=expected_generation,
                                          _source_proof=proof)
