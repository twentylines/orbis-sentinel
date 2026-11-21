"""Owned source review/staging flow; no key, activation or publication authority.

The existing RecoveryBootstrap remains the sole Root store/engine owner. This
source-only coordinator consumes real inventory-execution custody, which is not
publisher, SQL-activation or writer-floor admission. Interrupted terminal proof
is retained as a hold, never converted to a successful receipt from journal JSON.
"""
from contextlib import ExitStack, closing, contextmanager
import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import warnings

from . import credential_floor, recovery_sessions as sessions
from .bootstrap_source import (HELD_PLAN, PrivateDirectory, PrivateFile, create_file, decode, digest,
                               encoded, hash_value, held_review)
from .recovery_bootstrap import RecoveryBootstrap
from .writer_journal import seal, mount_id


_SCHEMA = 'orbis.sentinel-bootstrap-supervisor.v1'
_MAXIMUM = 65536
_PHASES = ('review-intent', 'review-captured', 'review-complete', 'stage-intent',
           'stage-captured', 'root-staged', 'stage-complete', 'held')


class BootstrapSupervisorError(ValueError):
    def __init__(self):
        super().__init__('The owned bootstrap source operation requires reconciliation.')


def fail():
    raise BootstrapSupervisorError() from None


def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        fail()


def _read(directory, name, maximum=16384):
    with PrivateFile(directory, name, maximum) as source:
        return source.body


class BootstrapSupervisor:
    def __init__(self, bootstrap, execution):
        from .collector_execution import CollectorExecutionInventory
        if type(bootstrap) is not RecoveryBootstrap or type(execution) is not CollectorExecutionInventory:
            fail()
        self.bootstrap, self.store, self.execution = bootstrap, bootstrap.store, execution
        self._owner = secrets.token_hex(32)

    @contextmanager
    def _operation(self, operation, review_sha256):
        if not hash_value(operation) or not hash_value(review_sha256):
            fail()
        with self.store._borrow(), PrivateDirectory(self.bootstrap.sources.operation_path(operation)) as directory, \
                PrivateFile(directory, 'review-plan.json', 16384) as review, \
                PrivateFile(directory, 'review-approval.json', 16384) as consent:
            body = review.body
            value = decode(body)
            exact(value, ('schema', 'operationId', 'root', 'context', 'installationId', 'origin',
                          'captureRoot', 'collector', 'hostHistorySha256'))
            if (value['schema'] != 'orbis.sentinel-bootstrap-review.v1' or value['operationId'] != operation
                    or digest(body) != review_sha256 or not hash_value(value['installationId'])
                    or value['origin'] != self.bootstrap.origin
                    or type(value['root']) is not str or not Path(value['root']).is_absolute()
                    or value['root'] != os.path.realpath(value['root'])
                    or type(value['context']) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value['context']) is None
                    or value['hostHistorySha256'] is not None and not hash_value(value['hostHistorySha256'])):
                fail()
            namespace = credential_floor.STATE_ROOT / 'installations' / digest(os.fsencode(value['root']))
            if (value['captureRoot'] != str(namespace / 'bootstrap-sources')
                    or namespace.is_relative_to(value['root']) or Path(value['root']).is_relative_to(namespace)):
                fail()
            collector = value['collector']
            exact(collector, ('protocol', 'programSha256', 'imageId', 'inventorySha256'))
            if (collector['protocol'] != 'orbis.stopped-main-source.v1'
                    or not hash_value(collector['programSha256']) or not credential_floor.image(collector['imageId'])
                    or collector['inventorySha256'] != self.execution.inventory_sha256
                    or collector['programSha256'] != digest(self.execution.bodies['orbis-host-recovery-source.py'])):
                fail()
            approval = decode(consent.body)
            exact(approval, ('schema', 'operationId', 'reviewSha256', 'installationId', 'approvalId'))
            if approval != {'schema': 'orbis.sentinel-bootstrap-review-approval.v1', 'operationId': operation,
                    'reviewSha256': review_sha256, 'installationId': value['installationId'], 'approvalId': approval['approvalId']} or not hash_value(approval['approvalId']):
                fail()
            self.execution.verify()
            # Never infer virgin state from absent Main users/history. Review
            # eligibility reads the actual sole Root store before starting work.
            journal = self._load(directory, missing=True)
            if journal is None:
                self.store._transaction(self.bootstrap._virgin)
            fd = os.open('supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory.fd)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size):
                    fail()
                identity, mounted = seal(info), mount_id(fd)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                if os.path.lexists(directory.path / 'supervisor.pending.json'):
                    fail()
                self._history(value)
                yield value, directory, (review, consent)
                self._check_scope(value, (review, consent))
                if seal(os.fstat(fd)) != identity or seal(os.stat('supervisor.lock', dir_fd=directory.fd, follow_symlinks=False)) != identity or mount_id(fd) != mounted:
                    fail()
            finally:
                os.close(fd)

    def _check_scope(self, scope, pins):
        for source in pins:
            source.verify()
        self.execution.verify()
        self._history(scope)

    def _history(self, scope):
        with PrivateDirectory(Path(scope['captureRoot']).parent) as namespace:
            try:
                body = _read(namespace, 'recovery-admission-history.json')
            except FileNotFoundError:
                if scope['hostHistorySha256'] is not None:
                    fail()
            else:
                value = decode(body)
                if (digest(body) != scope['hostHistorySha256'] or value.get('schema') != 'orbis.recovery-admission-history.v1'
                        or value.get('managedEver') is not False or value.get('mode') != 'unmanaged'
                        or value.get('installationId') != scope['installationId']):
                    fail()

    def _load(self, directory, *, missing=False):
        try:
            value = decode(_read(directory, 'supervisor.json', _MAXIMUM))
        except FileNotFoundError:
            if missing:
                return None
            raise
        exact(value, ('schema', 'operationId', 'reviewSha256', 'holdBinding', 'owner', 'phase',
                      'reviewNonce', 'reviewEvidence', 'planSha256', 'requestId', 'stageNonce', 'stageEvidence', 'rootReceipt', 'reason'))
        if (value['schema'] != _SCHEMA or value['phase'] not in _PHASES
                or not all(hash_value(value[k]) for k in ('operationId', 'reviewSha256', 'holdBinding', 'owner'))
                or value['holdBinding'] != value['reviewSha256']
                or any(value[k] is not None and not hash_value(value[k]) for k in ('planSha256', 'requestId'))
                or any(value[k] is not None and type(value[k]) is not dict for k in ('reviewEvidence', 'stageEvidence', 'rootReceipt'))
                or value['reason'] not in (None, 'review-interrupted', 'stage-interrupted')):
            fail()
        sessions._token(value['reviewNonce'])
        if value['stageNonce'] is not None:
            sessions._token(value['stageNonce'])
        if value['phase'] != 'held':
            phase = value['phase']
            if phase == 'review-intent' and value['reviewEvidence'] is not None:
                fail()
            if phase != 'review-intent' and value['reviewEvidence'] is None:
                fail()
            if phase in ('review-complete', 'stage-intent', 'stage-captured', 'root-staged', 'stage-complete') and value['reviewEvidence'].get('phase') != 'complete':
                fail()
            if phase.startswith('review-') and any(value[key] is not None for key in ('planSha256', 'requestId', 'stageNonce', 'stageEvidence', 'rootReceipt')):
                fail()
            if phase in ('stage-intent', 'stage-captured', 'root-staged', 'stage-complete') and (value['planSha256'] is None or value['requestId'] is None):
                fail()
            if phase in ('stage-captured', 'root-staged', 'stage-complete') and (value['stageNonce'] is None or value['stageEvidence'] is None):
                fail()
            if phase in ('root-staged', 'stage-complete') and value['rootReceipt'] is None:
                fail()
            if phase == 'stage-complete' and value['stageEvidence'].get('phase') != 'complete':
                fail()
        return value

    def _save(self, directory, value):
        # Fixed operation journal only; no generic write/configuration API.
        body = encoded(value)
        if len(body) > _MAXIMUM:
            fail()
        current = self._load(directory, missing=True)
        if current is not None and (current['operationId'] != value['operationId'] or current['reviewSha256'] != value['reviewSha256']):
            fail()
        create_file(directory, 'supervisor.pending.json', body)
        os.replace('supervisor.pending.json', 'supervisor.json', src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
        os.fsync(directory.fd)
        directory.verify()

    def _bind(self, journal, scope, review_sha256):
        if journal['operationId'] != scope['operationId'] or journal['reviewSha256'] != review_sha256:
            fail()
        for name, plan, nonce in (('reviewEvidence', review_sha256, journal['reviewNonce']),
                                  ('stageEvidence', journal['planSha256'], journal['stageNonce'])):
            evidence = journal[name]
            if evidence is not None:
                if plan is None or nonce is None or evidence.get('phase') not in ('captured', 'complete'):
                    fail()
                self._evidence_value(evidence, scope, self._request(scope, plan, nonce), review_sha256,
                                     terminal=evidence['phase'] == 'complete')
        if (journal['stageEvidence'] is not None and (journal['reviewEvidence'] is None
                or journal['stageEvidence']['sourceSha256'] != journal['reviewEvidence']['sourceSha256'])):
            fail()

    def _request(self, scope, plan, nonce):
        return {'operationId': scope['operationId'], 'planSha256': plan, 'phase': 'proposal',
                'collectionNonce': nonce, 'origin': scope['origin']}

    def _evidence(self, lease, scope, request, binding, *, terminal=False):
        from .collector_execution import ExecutionLease
        if type(lease) is not ExecutionLease:
            fail()
        lease.require_inventory(self.execution)
        value = lease.finish() if terminal else lease.check()
        return self._evidence_value(value, scope, request, binding, terminal=terminal)

    def _evidence_value(self, value, scope, request, binding, *, terminal=False):
        names = {'schema', 'phase', 'request', 'installationId', 'sourceSha256', 'descriptorSha256',
                 'inventorySha256', 'executionSha256', 'process', 'capsuleSha256', 'root', 'context', 'holdBinding', 'authority'}
        exact(value, names | ({'exitCode'} if terminal else set()))
        if (value['schema'] != 'orbis.collector-execution-custody.v1'
                or value['phase'] != ('complete' if terminal else 'captured')
                or value['request'] != request or value['installationId'] != scope['installationId']
                or value['inventorySha256'] != self.execution.inventory_sha256
                or value['root'] != scope['root'] or value['context'] != scope['context'] or value['holdBinding'] != binding
                or value['authority'] != 'inventory-execution-custody-only'
                or any(not hash_value(value[k]) for k in ('sourceSha256', 'descriptorSha256', 'executionSha256', 'capsuleSha256'))
                or terminal and (type(value['exitCode']) is not int or value['exitCode'] != 0)):
            fail()
        exact(value['process'], ('pid', 'startTicks', 'executable'))
        if (not sessions._integer(value['process']['pid'], 1) or not sessions._integer(value['process']['startTicks'], 1)
                or type(value['process']['executable']) is not list or len(value['process']['executable']) != 2
                or any(not sessions._integer(item) for item in value['process']['executable'])):
            fail()
        return value

    def _capture(self, scope, request, binding):
        return self.execution.capture(root=scope['root'], context=scope['context'], request=request, hold_binding=binding)

    def review(self, *, operation_id, review_sha256):
        with self._operation(operation_id, review_sha256) as (scope, directory, pins):
            journal = self._load(directory, missing=True)
            if journal is None:
                journal = {'schema': _SCHEMA, 'operationId': operation_id, 'reviewSha256': review_sha256,
                    'holdBinding': review_sha256, 'owner': self._owner, 'phase': 'review-intent',
                    'reviewNonce': secrets.token_urlsafe(32), 'reviewEvidence': None, 'planSha256': None,
                    'requestId': None, 'stageNonce': None, 'stageEvidence': None, 'rootReceipt': None, 'reason': None}
                self._save(directory, journal)
            self._bind(journal, scope, review_sha256)
            if journal['phase'] in ('review-complete', 'stage-complete'):
                return self._review_result(journal)
            if journal['phase'] != 'review-intent' or journal['owner'] != self._owner:
                fail()
            request = self._request(scope, review_sha256, journal['reviewNonce'])
            lease = None
            try:
                self._check_scope(scope, pins)
                self.store._transaction(self.bootstrap._virgin)
                lease = self._capture(scope, request, review_sha256)
                evidence = self._evidence(lease, scope, request, review_sha256)
                journal['reviewEvidence'], journal['phase'] = evidence, 'review-captured'
                self._save(directory, journal)
                terminal = self._evidence(lease, scope, request, review_sha256, terminal=True)
                self._same_terminal(evidence, terminal)
                self._check_scope(scope, pins)
                self.store._transaction(self.bootstrap._virgin)
                journal['reviewEvidence'], journal['phase'] = terminal, 'review-complete'
                self._save(directory, journal)
                return self._review_result(journal)
            except BaseException:
                journal['phase'], journal['reason'] = 'held', 'review-interrupted'
                self._save(directory, journal)
                raise
            finally:
                if lease is not None:
                    lease.close()

    @staticmethod
    def _same_terminal(captured, terminal):
        if {**captured, 'phase': 'complete', 'exitCode': 0} != terminal:
            fail()

    @staticmethod
    def _review_result(journal):
        evidence = journal['reviewEvidence']
        if evidence is None or evidence.get('phase') != 'complete' or evidence.get('exitCode') != 0:
            fail()
        return {'operationId': journal['operationId'], 'reviewSha256': journal['reviewSha256'],
                'holdBinding': journal['holdBinding'], 'phase': 'review-complete',
                'sourceSha256': evidence['sourceSha256'], 'authority': 'inventory-execution-custody-only'}

    def prepare_plan(self, *, operation_id, review_sha256):
        with self._operation(operation_id, review_sha256) as (scope, directory, pins):
            journal = self._load(directory)
            self._bind(journal, scope, review_sha256)
            if journal['phase'] != 'review-complete':
                fail()
            self.store._transaction(self.bootstrap._virgin)
            source = self._review_result(journal)
            plan = {'schema': 'orbis.sentinel-bootstrap-plan.v1', 'operationId': operation_id,
                'installationId': scope['installationId'], 'origin': scope['origin'], 'sourceSha256': source['sourceSha256'],
                'captureRoot': scope['captureRoot'], 'collector': {k: scope['collector'][k] for k in ('protocol', 'programSha256', 'imageId')},
                'hostHistorySha256': scope['hostHistorySha256']}
            body = encoded(plan)
            self._check_scope(scope, pins)
            try:
                current = _read(directory, 'plan.json')
            except FileNotFoundError:
                create_file(directory, 'plan.json', body)
            else:
                if current != body:
                    fail()
            # Approval remains an independent concrete Root action.
            return {'operationId': operation_id, 'planSha256': digest(body), 'sourceSha256': source['sourceSha256'],
                    'phase': 'plan-awaits-approval', 'authority': 'inventory-execution-custody-only'}

    def _root_receipt(self, journal, plan):
        def read():
            value = self.bootstrap._load(journal['operationId'])
            binding = digest(encoded([journal['operationId'], journal['planSha256'], journal['requestId'], journal['stageNonce']]))
            challenge = value['challenges'].get(journal['requestId'])
            if (value['planSha256'] != journal['planSha256'] or value['sourceSha256'] != plan['sourceSha256']
                    or journal['stageEvidence']['sourceSha256'] != plan['sourceSha256']
                    or value['stageBinding'] != binding or value['phase'] != 'staged' or value['key'] is not None
                    or value['activation'] is not None or challenge is None or challenge['nonce'] != journal['stageNonce']
                    or challenge['consumed'] is not True or challenge['descriptor'] != journal['stageEvidence']['descriptorSha256']):
                fail()
            self.bootstrap._pending(value)
            candidate = value['candidate']
            return {'operationId': value['operationId'], 'planSha256': value['planSha256'], 'phase': value['phase'],
                'sourceSha256': value['sourceSha256'], 'identitySha256': candidate['target'], 'revision': candidate['revision'],
                'generation': value['pendingGeneration'], 'keyRevision': None, 'deliveryEpoch': None,
                'expiresAtMs': None, 'ackReceiptId': None}
        return self.store._transaction(read)

    def stage(self, *, operation_id, review_sha256, plan_sha256, request_id):
        if not hash_value(plan_sha256) or not hash_value(request_id):
            fail()
        with self._operation(operation_id, review_sha256) as (scope, directory, pins):
            with self.bootstrap.sources.plan(operation_id, plan_sha256) as (plan, _):
                journal = self._load(directory)
                self._bind(journal, scope, review_sha256)
                if plan['sourceSha256'] != self._review_result(journal)['sourceSha256'] or plan['installationId'] != scope['installationId']:
                    fail()
                if journal['phase'] == 'stage-complete':
                    if journal['planSha256'] != plan_sha256 or journal['requestId'] != request_id:
                        fail()
                    if self._root_receipt(journal, plan) != journal['rootReceipt']:
                        fail()
                    return self._stage_result(journal)
                if journal['phase'] != 'review-complete':
                    fail()
                journal.update(phase='stage-intent', planSha256=plan_sha256, requestId=request_id, owner=self._owner)
                self._save(directory, journal)
                lease = None
                try:
                    self._check_scope(scope, pins)
                    reply, lost_reply = None, False
                    try:
                        reply = self.bootstrap.source_challenge(operation_id=operation_id, plan_sha256=plan_sha256,
                                                               phase='proposal', request_id=request_id)
                    except ConnectionError:
                        # A dropped reply is resolved only from the actual Root
                        # ledger, never a caller/journal nonce claim.
                        lost_reply = True
                    def known():
                        value = self.bootstrap._load(operation_id)
                        item = value['challenges'].get(request_id)
                        if (value['planSha256'] != plan_sha256 or value['sourceSha256'] != plan['sourceSha256']
                                or value['phase'] != 'collecting' or item is None or item['phase'] != 'proposal' or item['consumed']
                                or not item['created'] <= self.store._now() <= item['expires']):
                            fail()
                        self.bootstrap._virgin(operation=operation_id)
                        return {'collectionNonce': item['nonce'], 'expiresAtMs': item['expires'], 'consumed': False}
                    challenge = self.store._transaction(known)
                    if not lost_reply and reply != challenge:
                        fail()
                    journal['stageNonce'] = challenge['collectionNonce']
                    self._save(directory, journal)
                    request = self._request(scope, plan_sha256, journal['stageNonce'])
                    self._check_scope(scope, pins)
                    lease = self._capture(scope, request, review_sha256)
                    evidence = self._evidence(lease, scope, request, review_sha256)
                    if evidence['sourceSha256'] != plan['sourceSha256']:
                        fail()
                    journal['stageEvidence'], journal['phase'] = evidence, 'stage-captured'
                    self._save(directory, journal)
                    self._check_scope(scope, pins)
                    try:
                        self.bootstrap.stage(operation_id=operation_id, plan_sha256=plan_sha256,
                                             request_id=request_id, collection_nonce=journal['stageNonce'])
                    except ConnectionError:
                        self._root_receipt(journal, plan)
                    journal['rootReceipt'], journal['phase'] = self._root_receipt(journal, plan), 'root-staged'
                    self._save(directory, journal)
                    terminal = self._evidence(lease, scope, request, review_sha256, terminal=True)
                    self._same_terminal(evidence, terminal)
                    self._check_scope(scope, pins)
                    journal['stageEvidence'], journal['phase'] = terminal, 'stage-complete'
                    self._save(directory, journal)
                    return self._stage_result(journal)
                except BaseException:
                    journal['phase'], journal['reason'] = 'held', 'stage-interrupted'
                    self._save(directory, journal)
                    raise
                finally:
                    if lease is not None:
                        lease.close()

    def _stage_result(self, journal):
        evidence = journal['stageEvidence']
        if journal['phase'] != 'stage-complete' or evidence is None or evidence.get('phase') != 'complete' or evidence.get('exitCode') != 0:
            fail()
        return {'operationId': journal['operationId'], 'planSha256': journal['planSha256'], 'phase': 'source-staged-no-admission',
                'sourceSha256': evidence['sourceSha256'], 'identitySha256': journal['rootReceipt']['identitySha256'],
                'authority': 'inventory-execution-custody-only'}


class PublishedBootstrapSupervisor:
    """Visible Root coordinator. Never owns or opens the RecoverySessions store."""

    def __init__(self):
        from .bootstrap_control import RootBootstrapControlClient
        self.directory = credential_floor.RECOVERY_ROOT
        self.client = RootBootstrapControlClient(str(self.directory / 'bootstrap-control.sock'))

    @contextmanager
    def _published(self, operation, review_sha256):
        from .collector_execution import CollectorExecutionInventory, _root
        from .host_source_publication import read_completed_for_bootstrap_review
        from .recovery_listener_install import read_setup_receipt
        _root()
        if not hash_value(operation) or not hash_value(review_sha256):
            fail()
        with ExitStack() as resources:
            directory = resources.enter_context(PrivateDirectory(self.directory / 'bootstrap' / operation))
            fd = os.open('held-coordinator.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         0o600, dir_fd=directory.fd)
            resources.callback(os.close, fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != sessions._OWNER_UID or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size or mount_id(fd) != mount_id(directory.fd)):
                fail()
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            review = resources.enter_context(held_review(directory, operation, review_sha256))
            root = credential_floor._InstallationDirectory(Path(review['root']))
            resources.callback(root.close)
            expected_root = digest(encoded({'root': review['root'], 'context': review['context'],
                                            'daemon': review['daemon'], 'rootIdentity': root.identity}))
            if expected_root != review['installationId']:
                fail()
            publication = review['publisher']
            host = {key: review['host'][key] for key in ('inventorySha256', 'unitSha256', 'environmentSha256')}
            evidence = resources.enter_context(read_completed_for_bootstrap_review(publication['operationId'],
                root=root.path, context=review['context'], current={'main': review['main'], 'host': host},
                root_identity=root.identity, receipt_sha256=publication['receiptSha256']))
            execution = resources.enter_context(CollectorExecutionInventory.open_installed(
                evidence.observation['copy']['inventory']))
            if (execution.inventory_sha256 != review['collector']['inventorySha256']
                    or digest(execution.bodies['orbis-host-recovery-source.py']) != review['collector']['programSha256']):
                fail()

            # Join the built-in terminal only after the independent retained
            # publication and installed collector bytes have been selected.
            listener = read_setup_receipt(self.directory,review)

            def recheck():
                root.verify()
                directory.verify()
                execution.verify()
                evidence.recheck()
                if read_setup_receipt(self.directory, review) != listener:
                    fail()
                if (seal(os.fstat(fd)) != seal(info)
                        or seal(os.stat('held-coordinator.lock', dir_fd=directory.fd, follow_symlinks=False)) != seal(info)):
                    fail()
            recheck()
            yield review, directory, execution, recheck
            recheck()

    @staticmethod
    def _binding(review, request, observation):
        if (observation['request'] != request or observation['installationId'] != review['installationId']
                or observation['inventorySha256'] != review['collector']['inventorySha256']
                or observation['root'] != review['root'] or observation['context'] != review['context']):
            fail()
        path = Path(review['captureRoot']) / request['operationId'] / (request['phase'] + '-' + digest(request['collectionNonce'].encode()))
        with (PrivateDirectory(path) as directory, PrivateFile(directory, 'source.json', 65536) as source,
              PrivateFile(directory, 'witness.json', 32768) as witness):
            document = decode(witness.body)
            original = document.get('descriptor')
            if (digest(source.body) != observation['sourceSha256'] or type(original) is not dict
                    or document.get('descriptorSha256') != observation['descriptorSha256']
                    or digest(encoded(original)) != observation['descriptorSha256']
                    or any(document.get(key) != request[key] for key in ('operationId', 'planSha256', 'phase', 'collectionNonce'))
                    or original.get('installationId') != review['installationId']
                    or original.get('daemon') != review['daemon'] or original.get('layoutSha256') != review['layoutSha256']
                    or type(original.get('main')) is not dict
                    or any(original['main'].get(key) != review['main'][key] for key in
                           ('id', 'imageId', 'publicationSha256', 'definitionSha256'))):
                fail()
            source.verify()
            witness.verify()

    def prepare_plan(self, *, operation_id, review_sha256):
        with self._published(operation_id, review_sha256) as (review, directory, execution, recheck):
            if os.path.lexists(directory.path / 'held-review-intent.json'):
                with PrivateFile(directory, 'held-review-terminal.json', 16384) as source:
                    terminal = decode(source.body)
                    with PrivateFile(directory, 'held-review-intent.json', 4096) as intent:
                        record = decode(intent.body)
                if (record != {'reviewSha256': review_sha256, 'collectionNonce': record.get('collectionNonce')}
                        or terminal['phase'] != 'complete' or terminal.get('exitCode') != 0):
                    fail()
                nonce = record['collectionNonce']
            else:
                readiness = self.client.call('bootstrap-held-review', {'operationId': operation_id, 'reviewSha256': review_sha256})
                if readiness != {'operationId': operation_id, 'reviewSha256': review_sha256, 'phase': 'review-capture-ready'}:
                    fail()
                nonce = secrets.token_urlsafe(32)
                create_file(directory, 'held-review-intent.json', encoded({'reviewSha256': review_sha256, 'collectionNonce': nonce}))
                request = {'operationId': operation_id, 'planSha256': review_sha256, 'phase': 'proposal',
                           'collectionNonce': nonce, 'origin': review['origin']}
                with execution.capture(root=review['root'], context=review['context'], request=request,
                                       hold_binding=review_sha256) as lease:
                    captured = lease.check()
                    self._binding(review, request, captured)
                    terminal = lease.finish()
                    BootstrapSupervisor._same_terminal(captured, terminal)
                create_file(directory, 'held-review-terminal.json', encoded(terminal))
            request = {'operationId': operation_id, 'planSha256': review_sha256, 'phase': 'proposal',
                       'collectionNonce': nonce, 'origin': review['origin']}
            self._binding(review, request, terminal)
            collector = {key: review['collector'][key] for key in ('protocol', 'programSha256', 'imageId')}
            plan = {'schema': HELD_PLAN, 'operationId': operation_id, 'reviewSha256': review_sha256,
                    'sourceSha256': terminal['sourceSha256'], 'collector': collector,
                    **{key: review[key] for key in ('installationId', 'origin', 'captureRoot', 'hostHistorySha256')}}
            body = encoded(plan)
            recheck()
            try:
                current = _read(directory, 'plan.json')
            except FileNotFoundError:
                create_file(directory, 'plan.json', body)
            else:
                if current != body:
                    fail()
            return {'operationId': operation_id, 'planSha256': digest(body), 'phase': 'plan-awaits-approval'}

    def stage(self, *, operation_id, review_sha256, plan_sha256, request_id):
        if not hash_value(plan_sha256) or not hash_value(request_id):
            fail()
        with self._published(operation_id, review_sha256) as (review, directory, execution, recheck):
            with PrivateFile(directory, 'plan.json', 16384) as plan_file:
                plan = decode(plan_file.body)
                if (digest(plan_file.body) != plan_sha256 or plan.get('schema') != HELD_PLAN
                        or plan.get('reviewSha256') != review_sha256 or plan.get('operationId') != operation_id):
                    fail()
                intent = encoded({'operationId': operation_id, 'reviewSha256': review_sha256,
                                  'planSha256': plan_sha256, 'requestId': request_id})
                if os.path.lexists(directory.path / 'held-stage-intent.json'):
                    if _read(directory, 'held-stage-intent.json', 4096) != intent:
                        fail()
                    return self._completed_stage(directory, operation_id, plan_sha256, request_id)
                reply = self.client.call('bootstrap-source-challenge', {'operationId': operation_id, 'planSha256': plan_sha256,
                                         'phase': 'proposal', 'requestId': request_id})
                if set(reply) != {'collectionNonce', 'expiresAtMs', 'consumed'} or reply['consumed'] is not False:
                    fail()
                create_file(directory, 'held-stage-intent.json', intent)
                request = {'operationId': operation_id, 'planSha256': plan_sha256, 'phase': 'proposal',
                           'collectionNonce': reply['collectionNonce'], 'origin': review['origin']}
                with execution.capture(root=review['root'], context=review['context'], request=request,
                                       hold_binding=review_sha256, held_stage=True) as lease:
                    captured = lease.observation
                    self._binding(review, request, captured)
                    plan_file.verify()
                    recheck()
                    if captured['sourceSha256'] != plan['sourceSha256']:
                        fail()
                    self.client.stage_held(lease, directory, review_sha256=review_sha256, request_id=request_id)
                return self._completed_stage(directory, operation_id, plan_sha256, request_id)

    def _completed_stage(self, directory, operation, plan, request):
        result = self.client.call('bootstrap-status', {'operationId': operation})
        if (result['operationId'] != operation or result['planSha256'] != plan or result.get('requestId') != request
                or result['phase'] not in ('held-stage-complete', 'key-prepared', 'acknowledged')
                or result.get('terminalReceiptSha256') != digest(_read(directory, 'held-stage-terminal.json'))):
            fail()
        return result

    def activate_held(self, *, operation_id, review_sha256, plan_sha256, packet_sha256):
        """Advance a preapproved Host intent to private completion only."""
        from .bootstrap_source import activation_intent, activation_packet
        if not hash_value(plan_sha256) or not hash_value(packet_sha256):
            fail()
        args = {'operationId': operation_id, 'planSha256': plan_sha256, 'packetSha256': packet_sha256}
        with (self._published(operation_id, review_sha256) as (review, directory, execution, recheck),
              PrivateFile(directory, 'plan.json', 16384) as source):
            plan = decode(source.body)
            if digest(source.body) != plan_sha256:
                fail()
            with activation_packet(directory, plan, review, packet_sha256) as (packet, approval, verify):
                name = 'held-activation-terminal.json'
                request_id = packet['activationRequestId']
                delivered = None
                if not os.path.lexists(directory.path / name):
                    challenge = self.client.call('bootstrap-held-activation-challenge', {**args, 'requestId': request_id})
                    if set(challenge) != {'collectionNonce', 'issuedAtMs', 'expiresAtMs'}:
                        fail()
                    item = {'nonce': challenge['collectionNonce'], 'created': challenge['issuedAtMs'],
                            'expires': challenge['expiresAtMs']}
                    request = {'operationId': operation_id, 'planSha256': plan_sha256, 'phase': 'activation',
                               'collectionNonce': item['nonce'], 'origin': review['origin']}
                    with activation_intent(review, packet, packet_sha256, approval, item) as (intent, check_intent):
                        with execution.capture(root=review['root'], context=review['context'], request=request,
                                               hold_binding=review_sha256, held_stage=True) as lease:
                            captured = lease.observation
                            self._binding(review, request, captured)
                            if captured['sourceSha256'] != packet['stage']['sourceSha256']:
                                fail()
                            source.verify()
                            verify()
                            check_intent()
                            recheck()
                            delivered = self.client.activate_held(lease, directory, review_sha256=review_sha256,
                                request_id=request_id, packet_sha256=packet_sha256, intent_sha256=intent)
                result = self.client.call('bootstrap-held-activation-receipt', args)
                if ({key: result.get(key) for key in args} != args or result.get('phase') != 'activation-committed'
                        or result.get('requestId') != request_id
                        or result.get('commitSha256') != packet['candidate']['projectedCommitSha256']
                        or result.get('terminalReceiptSha256') != digest(_read(directory, name))
                        or delivered is not None and result != delivered['receipt']):
                    fail()
                return result

    @contextmanager
    def _operation_plan(self, operation, review_sha, plan_sha):
        if not hash_value(plan_sha):
            fail()
        with self._published(operation, review_sha) as (review, directory, _, recheck):
            with PrivateFile(directory, 'plan.json', 16384) as source:
                plan = decode(source.body)
                if (digest(source.body) != plan_sha or plan.get('schema') != HELD_PLAN
                        or plan.get('reviewSha256') != review_sha or plan.get('operationId') != operation
                        or plan.get('installationId') != review['installationId']):
                    fail()

                def check():
                    source.verify()
                    recheck()

                check()
                yield review, directory, check
                check()

    def status(self, *, operation_id, review_sha256, plan_sha256):
        with self._operation_plan(operation_id, review_sha256, plan_sha256):
            result = self.client.call('bootstrap-status', {'operationId': operation_id})
            if result.get('operationId') != operation_id or result.get('planSha256') != plan_sha256:
                fail()
            return result

    def _key_status(self, operation, plan):
        result = self.client.call('bootstrap-held-key-status', {'operationId': operation, 'planSha256': plan})
        if (result.get('operationId') != operation or result.get('planSha256') != plan
                or result.get('phase') not in ('key-prepared', 'acknowledged')
                or any(not hash_value(result.get(key)) for key in
                       ('keyRevision', 'deliveryEpoch', 'deliverySha256', 'terminalReceiptSha256'))):
            fail()
        return result

    def prepare_key(self, *, operation_id, review_sha256, plan_sha256):
        with self._operation_plan(operation_id, review_sha256, plan_sha256) as (_, _, check):
            check()
            result = self.client.call('bootstrap-key-prepare', {'operationId': operation_id, 'planSha256': plan_sha256})
            if self._key_status(operation_id, plan_sha256) != result:
                fail()
            return result

    def save_key(self, *, operation_id, review_sha256, plan_sha256, destination):
        with self._operation_plan(operation_id, review_sha256, plan_sha256) as (review, directory, check):
            state = self._key_status(operation_id, plan_sha256)
            path = Path(destination)
            protected = (self.directory.parent, credential_floor.STATE_ROOT, Path(review['root']), Path('/opt/orbis-sentinel'))
            if (not path.is_absolute() or str(path) != destination or not path.name
                    or any(ord(char) < 32 or ord(char) == 127 for char in destination)
                    or any(path.is_relative_to(root) for root in protected)):
                fail()
            with PrivateFile(directory, 'delivery.json', 4096) as delivery, PrivateDirectory(path.parent) as output:
                value = decode(delivery.body)
                if (digest(delivery.body) != state['deliverySha256'] or value.get('revision') != state['keyRevision']
                        or value.get('epoch') != state['deliveryEpoch'] or value.get('operationId') != operation_id
                        or value.get('planSha256') != plan_sha256 or value.get('expires') != state['expiresAtMs']):
                    fail()
                secret = value.get('recoveryKey')
                sessions._recovery_key_digest(secret)
                saved_bytes = secret.encode('ascii') + b'\n'
                check()
                delivery.verify()
                if self._key_status(operation_id, plan_sha256) != state:
                    fail()
                try:
                    create_file(output, path.name, saved_bytes)
                except FileExistsError:
                    pass
                with PrivateFile(output, path.name, len(saved_bytes)) as saved:
                    if (saved.body != saved_bytes or mount_id(saved.fd) != mount_id(output.fd)):
                        fail()
                    os.fsync(saved.fd)
                    os.fsync(output.fd)
                    if self._key_status(operation_id, plan_sha256) != state:
                        fail()
                    delivery.verify()
                    saved.verify()
            return {'operationId': operation_id, 'phase': 'key-saved', 'keyRevision': state['keyRevision']}

    def acknowledge_key(self, *, operation_id, review_sha256, plan_sha256):
        with self._operation_plan(operation_id, review_sha256, plan_sha256):
            prepared = self._key_status(operation_id, plan_sha256)
        entered = _read_saved_key()
        with self._operation_plan(operation_id, review_sha256, plan_sha256) as (_, _, check):
            if self._key_status(operation_id, plan_sha256) != prepared:
                fail()
            check()
            result = self.client.call('bootstrap-ack', {'operationId': operation_id, 'planSha256': plan_sha256,
                'deliveryEpoch': prepared['deliveryEpoch'], 'recoveryKey': entered})
            if (set(result) != {'ackReceiptId', 'keyRevision'} or result['keyRevision'] != prepared['keyRevision']
                    or not hash_value(result['ackReceiptId'])):
                fail()
            return result

    def browser_handoff(self, action, *, operation_id, review_sha256, plan_sha256):
        if action not in ('authorize', 'revoke'):
            fail()
        with self._operation_plan(operation_id, review_sha256, plan_sha256) as (_, _, check):
            state = self._key_status(operation_id, plan_sha256)
            binding = {'operationId': operation_id, 'reviewSha256': review_sha256, 'planSha256': plan_sha256,
                       'keyRevision': state['keyRevision'], 'deliveryEpoch': state['deliveryEpoch']}
            check()
            result = self.client.call('bootstrap-browser-' + action, binding)
            if action == 'revoke':
                if result != {'state': 'revoked'}:
                    fail()
                return result
            if (set(result) != {'state', 'handoff', 'expiresAtMs'} or result['state'] != 'authorized'
                    or not sessions._integer(result['expiresAtMs'], 1)):
                fail()
            sessions._token(result['handoff'])
            return {**binding, 'handoff': result['handoff']}


def _read_saved_key():
    with open('/dev/tty', 'r+', encoding='utf-8') as terminal, warnings.catch_warnings():
        if not terminal.isatty():
            fail()
        warnings.simplefilter('error', getpass.GetPassWarning)
        entered = getpass.getpass('Enter the recovery key from your saved copy: ', stream=terminal)
    sessions._recovery_key_digest(entered)
    return entered


def run_published_bootstrap(action, operation, review, plan, *, request=None, destination=None):
    from .collector_execution import _root
    from .host_source_publication import _Pins, _activation_lock, _producer
    try:
        _root()
        if action == 'authorize-browser' and not sys.stdout.isatty():
            fail()
        kwargs = {'operation_id': operation, 'review_sha256': review}
        if action != 'prepare-plan':
            kwargs['plan_sha256'] = plan
        if action == 'stage':
            kwargs['request_id'] = request
        if action == 'save-key':
            kwargs['destination'] = destination
        with closing(_Pins()) as pins:
            _activation_lock(pins)
            _producer(pins)
            supervisor = PublishedBootstrapSupervisor()
            actions = {'prepare-plan': supervisor.prepare_plan, 'stage': supervisor.stage, 'status': supervisor.status,
                       'prepare-key': supervisor.prepare_key, 'save-key': supervisor.save_key,
                       'acknowledge-key': supervisor.acknowledge_key}
            if action in ('authorize-browser', 'revoke-browser'):
                result = supervisor.browser_handoff(action.removesuffix('-browser'), **kwargs)
            else:
                result = actions[action](**kwargs)
            pins.verify()
        if action == 'authorize-browser':
            print(json.dumps(result))
            return 0
        if action == 'revoke-browser':
            print(json.dumps(result))
            return 0
        fields = {'operationId', 'reviewSha256', 'planSha256', 'requestId', 'phase', 'sourceSha256', 'identitySha256',
                  'revision', 'generation', 'keyRevision', 'deliveryEpoch', 'expiresAtMs', 'ackReceiptId',
                  'terminalReceiptSha256', 'deliverySha256'}
        print(json.dumps({key: value for key, value in result.items() if key in fields}))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, EOFError, getpass.GetPassWarning, KeyboardInterrupt):
        print('Recovery bootstrap did not complete. Preserve the existing protected operation for reconciliation.', file=sys.stderr)
        return 1
