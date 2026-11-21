"""Paired publication with protected files and real SQLite, without a listener."""

import os
import socket
import subprocess
import unittest
from unittest import mock

from orbis_sentinel import bootstrap_control, bootstrap_host_transition, bootstrap_publication as publication
from orbis_sentinel import bootstrap_source as source, credential_floor as floor, credential_storage as storage
from orbis_sentinel import recovery_listener_install as listener, recovery_sessions
from orbis_sentinel.recovery_backend_tls import ListenerPeer, MODE
from orbis_sentinel.recovery_bootstrap import RecoveryBootstrap
from orbis_sentinel.recovery_incarnations import RecoveryIncarnations
from orbis_sentinel.recovery_profiles import RecoveryProfiles

import test_recovery_bootstrap


class PairedPublicationTests(unittest.TestCase):
    def setUp(self):
        for module, name in ((socket, 'socket'), (socket, 'socketpair'), (subprocess, 'Popen')):
            blocked = mock.patch.object(module, name, side_effect=AssertionError(f'{name} is outside the fixture scope'))
            guard = blocked.start()
            self.addCleanup(blocked.stop)
            self.addCleanup(guard.assert_not_called)
        class HeldFiles(test_recovery_bootstrap.BootstrapFixture):
            def open(self):
                pass

        self.fixture = f = HeldFiles()
        f.setUp()
        self.addCleanup(f.doCleanups)
        for module, key, value in ((floor, 'RECOVERY_ROOT', f.root), (source, 'HOST_STATE', f.base)):
            patch = mock.patch.object(module, key, value)
            patch.start()
            self.addCleanup(patch.stop)
        config = {'origin': f.origin}
        self.binding = listener.SetupBinding(config, source.encoded({
            'schema': listener.BUILTIN_MARKER, 'operationId': 'e' * 64, 'installationId': f.installation,
            'origin': f.origin, 'configSha256': source.digest(source.encoded(config)),
            'transport': {'mode': MODE, 'pairId': 'f' * 64}}), lambda: None,
            backend=ListenerPeer(None, '3' * 64, lambda: None, pair_sha256='4' * 64))
        # BootstrapFixture builds these synthetic inputs before it calls open().
        # Reserve a genuinely new paired store before moving its inputs in.
        bootstrap = f.operation.parent
        staging = f.base / 'fixture-bootstrap'
        bootstrap.rename(staging)
        self.reopen()
        staging.rename(bootstrap)
        self.prepare_artifacts()

    def reopen(self):
        f = self.fixture
        if hasattr(f, 'store'):
            f.profiles.close()
            f.store.close()
        f.store = recovery_sessions.RecoverySessions(f.root, clock=lambda: f.now, setup=self.binding)
        self.addCleanup(f.store.close)
        self.unexpected_worker = mock.Mock(side_effect=AssertionError('No worker is allowed in the fixture'))
        f.profiles = RecoveryProfiles(f.store, inspect=self.unexpected_worker, verify=self.unexpected_worker)
        self.addCleanup(f.profiles.close)
        incarnations = RecoveryIncarnations(f.store, f.profiles, inspect=self.unexpected_worker, origin=f.origin)
        f.engine = RecoveryBootstrap(f.store, f.profiles, incarnations, origin=f.origin, require_held_setup=True)
        self.control = bootstrap_control.RootBootstrapControl(f.engine)

    def prepare_artifacts(self):
        f = self.fixture
        main = f.base / 'main'
        self.namespace = f.base / 'installations' / source.digest(os.fsencode(main))
        f.captures = self.namespace / 'bootstrap-sources'
        f.captures.mkdir(mode=0o700, parents=True)
        self.namespace.chmod(0o700)
        self.namespace.parent.chmod(0o700)
        prior_config = source.encoded({'mode': 'unmanaged', 'origin': f.origin}) + b'\n'
        prior = source.encoded({'schema': 'orbis.recovery-admission-history.v1', 'mode': 'unmanaged', 'managedEver': False,
            'installationId': f.installation, 'generation': 7, 'configSha256': source.digest(prior_config),
            'planSha256': '5' * 64, 'sentinelVersion': '1.0.0', 'writerProtocol': 1}) + b'\n'
        roles = {'installation': main, 'namespace': self.namespace, 'journal': self.namespace / 'credential-journal',
                 'recovery': f.root}
        self.review = review = {'schema': 'orbis.sentinel-bootstrap-review.v2', 'operationId': f.op,
            'root': str(main), 'context': 'local', 'daemon': 'fixture-daemon', 'installationId': f.installation, 'origin': f.origin,
            'captureRoot': str(f.captures), 'hostHistorySha256': source.digest(prior), 'previousGeneration': 7,
            'previousAdmissionSha256': source.digest(prior_config), 'previousSentinelVersion': '1.0.0', 'previousWriterProtocol': 1,
            'layoutSha256': '6' * 64,
            'main': {'id': '7' * 64, 'imageId': f.plan['collector']['imageId'], 'publicationSha256': '8' * 64, 'definitionSha256': '9' * 64},
            'host': {'inventorySha256': 'a' * 64, 'unitSha256': 'b' * 64, 'environmentSha256': 'c' * 64, 'effectiveSha256': 'd' * 64},
            'collector': {**f.plan['collector'], 'inventorySha256': 'a' * 64},
            'publisher': {'operationId': '8' * 64, 'receiptSha256': '9' * 64},
            'runtime': {'version': '1.0.0', 'inventorySha256': 'a' * 64, 'runtimeDirectory': '/fixed/sentinel',
                        'runtimeFiles': dict.fromkeys(('__init__.py', 'writer_broker.py', 'writer_control.py', 'writer_journal.py',
                                                       'recovery_sessions.py', 'recovery_config.py'), 'd' * 64)},
            'recovery': {'process': {}, 'configSha256': '4' * 64, 'environmentSha256': '5' * 64, 'unitSha256': '6' * 64,
                         'effectiveSha256': '7' * 64},
            'storage': {key: {'path': str(path), 'filesystem': 'ext4', 'uuid': 'a' * 32,
                         'handle': f'{index:016x}', 'owner': [0, 0, 0o40700], 'filesystemPath': str(path),
                         'mountPoint': '/', 'mountRoot': '/'} for index, (key, path) in enumerate(roles.items(), 1)}, 'journal': {}}
        review_sha = self.write_document(f.operation / 'review-plan.json', review)
        self.write_document(f.operation / 'review-approval.json', {'schema': 'orbis.sentinel-bootstrap-review-approval.v2',
            'operationId': f.op, 'reviewSha256': review_sha, 'installationId': f.installation, 'approvalId': 'b' * 64})
        f.plan.update(schema=source.HELD_PLAN, reviewSha256=review_sha, captureRoot=str(f.captures),
                      hostHistorySha256=source.digest(prior))
        f.plan_sha = self.write_document(f.operation / 'plan.json', f.plan)
        f.approval.update(schema='orbis.sentinel-bootstrap-approval.v2', planSha256=f.plan_sha)
        self.write_document(f.operation / 'approval.json', f.approval)

        proposal, activation = '7' * 64, '8' * 64
        origin, source_sha = f.origin, f.plan['sourceSha256']
        nonce = 'A' * 43
        offer, challenge, capability = 'c' * 64, 'B' * 42 + 'A', 'd' * 64

        def enrich(witness):
            descriptor = witness['descriptor']
            descriptor.update(daemon=review['daemon'], layoutSha256=review['layoutSha256'], main=review['main'])
            descriptor['exporter']['capabilitySha256'] = capability
            witness['descriptorSha256'] = source.digest(source.encoded(descriptor))

        _, staged = f.capture('proposal', {'collectionNonce': nonce}, change=enrich)
        _, fresh = f.capture('activation', {'collectionNonce': nonce}, change=enrich)
        terminal = self.write_document(f.operation / 'held-stage-terminal.json', {
            'schema': 'orbis.sentinel-bootstrap-held-terminal.v1', 'offerSha256': offer, 'terminalChallenge': challenge,
            'receipt': {'phase': 'complete', 'exitCode': 0, 'installationId': f.installation, 'sourceSha256': source_sha,
                        'descriptorSha256': staged['descriptorSha256'], 'process': {'pid': 1, 'startTicks': 1},
                        'root': str(main), 'context': review['context'], 'holdBinding': review_sha,
                        'inventorySha256': review['collector']['inventorySha256'],
                        'request': {'operationId': f.op, 'planSha256': f.plan_sha, 'phase': 'proposal',
                                    'collectionNonce': nonce, 'origin': origin}}})
        incarnation = '1' * 64
        revision = source.digest(b'orbis.sentinel-bootstrap-incarnation.v1\0' + source.encoded([source_sha, incarnation]))
        target = '2' * 64
        profile = {'identitySha256': target, 'revision': revision, 'accountId': 1, 'origin': origin,
                   'totpEnabled': False, 'requireTotpAfterPasskey': False, 'credentials': {f.credential: 3}}
        key = {'revision': '3' * 64, 'deliverySha256': '4' * 64, 'epoch': '5' * 64, 'created': f.now - 1_000_000}
        key['expires'] = key['created'] + 600000
        key_digest = '6' * 64
        key['ack'] = source.digest(source.encoded([f.op, f.plan_sha, key['epoch'], key['revision'], key_digest]))
        record = {'schema': 'orbis.sentinel-bootstrap-operation.v1', 'operationId': f.op, 'planSha256': f.plan_sha,
            'installationId': f.installation, 'origin': origin, 'sourceSha256': source_sha, 'phase': 'activation-committed',
            'challenges': {request: {'phase': phase, 'nonce': nonce, 'created': f.now - 1, 'expires': f.now + 119999,
                                     'consumed': True, 'descriptor': witness['descriptorSha256']}
                           for request, phase, witness in ((proposal, 'proposal', staged), (activation, 'activation', fresh))},
            'candidate': {'nonce': incarnation, 'target': target, 'revision': revision, 'content': '7' * 64, 'profile': profile},
            'pendingGeneration': 1, 'key': key, 'writerFloor': None, 'managedIntent': None,
            'stageBinding': source.digest(source.encoded([f.op, f.plan_sha, proposal, nonce])), 'activationBinding': None,
            'heldStage': {'offerSha256': offer, 'terminalChallenge': challenge, 'requestId': proposal, 'terminalReceiptSha256': terminal},
            'keyPreparation': key['deliverySha256']}
        core = f.engine._activation_core(record, activation)
        record['activation'] = core
        commit = source.digest(source.encoded(core))
        terminal_sha = self.write_document(f.operation / 'held-activation-terminal.json', {
            'schema': source.ACTIVATION_TERMINAL, 'offerSha256': offer, 'terminalChallenge': challenge,
            'commitSha256': commit, 'receipt': {'phase': 'complete', 'exitCode': 0,
                'installationId': f.installation, 'sourceSha256': source_sha,
                'descriptorSha256': fresh['descriptorSha256'], 'process': {'pid': 1, 'startTicks': 1},
                'root': str(main), 'context': review['context'], 'holdBinding': review_sha,
                'inventorySha256': review['collector']['inventorySha256'],
                'request': {'operationId': f.op, 'planSha256': f.plan_sha, 'phase': 'activation',
                            'collectionNonce': nonce, 'origin': origin}}})
        projection = {'stage': {'terminalReceiptSha256': terminal, 'sourceSha256': source_sha, 'identitySha256': target,
                                'revision': revision, 'contentSha256': record['candidate']['content'], 'pendingGeneration': 1},
                      'key': {'revision': key['revision'], 'ackReceiptId': key['ack']}, 'projectedCommitSha256': commit,
                      'exporterCapabilitySha256': capability}
        worker = {'imageId': review['main']['imageId'], 'anchorSha256': '8' * 64, 'capabilitiesSha256': '9' * 64}
        bodies = bootstrap_host_transition.HostActivation._candidate(
            review, f.plan_sha, prior, prior_config, activation, projection, worker, capability)
        for name, body in bodies.items():
            f.write(f.operation / name, body)
        self.history = bodies['activation-history.json']
        packet_sha = source.digest(bodies['activation-packet.json'])
        self.packet = source.decode(bodies['activation-packet.json'])
        approval_sha = self.write_document(f.operation / 'activation-approval.json', {
            'schema': 'orbis.sentinel-bootstrap-activation-approval.v1', 'operationId': f.op,
            'installationId': f.installation, 'packetSha256': packet_sha, 'activationRequestId': activation, 'approvalId': '9' * 64})
        issued = record['challenges'][activation]
        intent_sha = self.write_document(self.namespace / publication.INTENT, {
            'schema': 'orbis.host.credential-bootstrap-intent.v1', **{key: self.packet[key] for key in (
                'operationId', 'installationId', 'reviewSha256', 'planSha256', 'activationRequestId')},
            'packetSha256': packet_sha, 'approvalSha256': approval_sha, 'nonceSha256': source.digest(nonce.encode('ascii')),
            'issuedAtMs': issued['created'], 'expiresAtMs': issued['expires']})
        f.write(self.namespace / publication.FENCE, publication._fence(self.packet))
        record['heldActivation'] = {'packetSha256': packet_sha, 'requestId': activation, 'offerSha256': offer,
            'terminalChallenge': challenge, 'intentSha256': intent_sha, 'descriptorSha256': fresh['descriptorSha256'],
            'terminalReceiptSha256': terminal_sha}

        def seed():
            db = f.store._db
            db.execute('INSERT INTO identities VALUES (?,?,0)', (revision, source.encoded(profile).decode('ascii')))
            db.execute('INSERT INTO counters VALUES (?,3)', (f.credential,))
            db.execute('INSERT INTO recovery_keys VALUES (?,?,?,-1,NULL,?)', (key['revision'], key_digest, f.origin, key['created']))
            db.execute('UPDATE operator_enrollment SET generation=1,nonce=?,target=?,origin=?',
                       (source.digest(f.op.encode('ascii')), target, f.origin))
            f.engine._save(record)

        f.store._transaction(seed)
        self.initial = record
        self.arguments = {'operationId': f.op, 'planSha256': f.plan_sha, 'packetSha256': packet_sha}
        self.completion = source.activation_completion(self.packet, packet_sha, intent_sha, {
            'commitSha256': commit, 'terminalReceiptSha256': terminal_sha})
        self.progress = source.activation_progress('complete', packet_sha, approval_sha, self.completion)
        self.write_document(self.namespace / source.ACTIVATION_COMPLETE, self.completion)
        f.write(self.namespace / source.ACTIVATION_PROGRESS, self.progress)
        f.write(f.base / 'credential-admission.json', bodies['activation-config.json'])
        f.write(self.namespace / floor.HISTORY, self.history)
        for folder, body in ((floor.ARCHIVE, prior), (source.CONFIG_ARCHIVE, prior_config),
                             (storage.BRIDGE_DIRECTORY, bodies['activation-bridge.json'])):
            path = self.namespace / folder
            path.mkdir(mode=0o700)
            f.write(path / (source.digest(body) + '.json'), body)
        pair = self.write_document(f.root / listener.PAIRED_FILE, {
            'schema': listener.PAIRED, 'operationId': self.binding.operation, 'installationId': f.installation,
            'markerSha256': self.binding.sha256, 'pairSha256': self.binding.backend.pair_sha256})
        self.write_document(f.root / listener.RECEIPT_FILE, {
            'schema': listener.BUILTIN_RECEIPT, **listener._review_binding(review), 'operationId': self.binding.operation,
            'markerSha256': self.binding.sha256, 'pairedSha256': pair})
        observed = publication.qualification_evidence(review, self.packet, self.completion,
            self.binding.sha256, self.binding.backend.pair_sha256,
            f.engine._activation_readback(record, terminal=terminal_sha), self.history,
            bodies['activation-config.json'], (f.operation / 'held-activation-terminal.json').read_bytes(), {
                'listenerReceiptSha256': source.digest((f.root / listener.RECEIPT_FILE).read_bytes()),
                'pairedReceiptSha256': source.digest((f.root / listener.PAIRED_FILE).read_bytes()),
                'storeReservationSha256': source.digest((f.root / recovery_sessions._LISTENER_SETUP_STORE).read_bytes())})
        self.qualification = publication.qualification_record(observed, self.completion, review,
            self.binding.sha256, self.binding.backend.pair_sha256)
        self.qualification_evidence_file = self.namespace / publication.QUALIFICATION_EVIDENCE_FILE
        self.write_document(self.qualification_evidence_file, observed)
        self.qualification_file = self.namespace / publication.QUALIFICATION_FILE
        self.write_document(self.qualification_file, self.qualification)
        self.proof_file = f.operation / publication.PROOF_FILE

    def write_document(self, path, value):
        body = source.encoded(value)
        self.fixture.write(path, body)
        return source.digest(body)

    def root(self, action, *, args=None, ok=True):
        reply = self.control.handle({'schema': bootstrap_control._SCHEMA, 'operation': 'bootstrap-paired-publication-' + action,
                                     'arguments': self.arguments if args is None else args})
        self.assertEqual(reply['ok'], ok, reply)
        return reply.get('result')

    def retire(self, ready):
        for live, retired in ((publication.FENCE, publication.RETIRED_FENCE), (publication.INTENT, publication.RETIRED_INTENT)):
            (self.namespace / live).rename(self.namespace / retired)
        self.write_document(self.namespace / publication.RELEASE_FILE, publication._release(ready, self.packet, self.completion))

    def reader(self, **overrides):
        return publication.read_published(self.namespace, **{
            'recovery_directory': self.fixture.root, 'root': self.review['root'], 'context': self.review['context'],
            'daemon': self.review['daemon'], 'history_body': self.history, **overrides})

    def rows(self):
        store = self.fixture.store
        return tuple(tuple(store._db.execute(sql).fetchone()) for sql in (
            'SELECT rowid,revision,profile,active FROM identities',
            'SELECT rowid,revision,digest,active FROM recovery_keys',
            'SELECT generation,nonce,target,origin FROM operator_enrollment'))

    def assert_closed(self):
        f = self.fixture
        with self.assertRaises(recovery_sessions.RecoverySessionError):
            f.store.authentication_options()
        with self.assertRaises(recovery_sessions.RecoverySessionError):
            f.store.challenge(method='recovery-key', origin=f.origin, browser_binding='A' * 43)

    def test_ready_holds_and_release_activates_same_rows_after_restart(self):
        f = self.fixture
        original = self.rows()
        ready = self.root('ready')
        self.assertEqual(self.root('ready'), ready)
        self.assertEqual(self.rows(), original)
        self.assert_closed()
        self.assertEqual(f.engine.enrollment_state()['stage'], 'activation-pending')
        self.assertFalse(self.proof_file.exists())
        self.reopen()
        self.assertEqual(self.root('ready'), ready)
        self.retire(ready)
        self.assert_closed()
        published = self.root('publish')
        self.assertEqual(self.root('publish'), published)
        self.reopen()
        self.assertEqual(self.root('publish'), published)
        updated = self.rows()
        for before, after in zip(original[:2], updated[:2]):
            self.assertEqual(before[:-1], after[:-1])
            self.assertEqual(after[-1], 1)
        self.assertEqual(updated[-1], (2, None, None, None))
        current = f.store._transaction(lambda: f.engine._load(f.op))
        for key in ('activation', 'heldStage', 'heldActivation', 'key', 'candidate', 'pendingGeneration'):
            self.assertEqual(current[key], self.initial[key])
        self.assertIs(f.store._setup, self.binding)
        self.assertEqual(f.engine.enrollment_state()['stage'], 'activated')
        self.assertTrue(f.store.authentication_options()['recoveryKey'])
        with self.reader() as witness:
            self.assertEqual((witness.host_generation, witness.sessions_generation), (8, 2))
            self.assertEqual(witness.receipt_sha256, source.digest(source.encoded(published)))
        with self.assertRaises(recovery_sessions.RecoverySessionError):
            f.store.revoke()
        self.unexpected_worker.assert_not_called()

    def test_crossed_requests_and_config_prefix_do_not_change_rows(self):
        original = self.rows()
        for field in self.arguments:
            with self.subTest(field=field):
                self.root('ready', args={**self.arguments, field: '0' * 64}, ok=False)
        self.root('ready', args={**self.arguments, 'qualification': True}, ok=False)
        self.root('publish', ok=False)
        progress = self.namespace / source.ACTIVATION_PROGRESS
        progress.unlink()
        self.root('ready', ok=False)
        self.fixture.write(progress, self.progress)
        self.qualification_file.unlink()
        self.root('ready', ok=False)
        self.assertEqual(self.rows(), original)
        self.assert_closed()

    def test_release_needs_both_exact_retirements_and_unchanged_qualification(self):
        original = self.rows()
        ready = self.root('ready')
        fence = self.namespace / publication.FENCE
        intent = self.namespace / publication.INTENT
        fence_body, intent_body = fence.read_bytes(), intent.read_bytes()
        fence.unlink()
        intent.unlink()
        self.root('publish', ok=False)
        self.fixture.write(fence, fence_body)
        self.fixture.write(intent, intent_body)
        self.retire(ready)
        retired = self.namespace / publication.RETIRED_INTENT
        self.fixture.write(retired, intent_body + b'\n')
        self.root('publish', ok=False)
        self.fixture.write(retired, intent_body)
        self.write_document(self.qualification_file, {**self.qualification,
            'consumers': {**self.qualification['consumers'], 'host': 'f' * 64}})
        self.root('publish', ok=False)
        self.assertEqual(self.rows(), original)
        self.assert_closed()

    def test_missing_post_commit_proof_leaves_gate_held_and_replays_without_increment(self):
        f = self.fixture
        self.retire(self.root('ready'))
        with mock.patch.object(listener, '_new_file', side_effect=OSError('synthetic lost write')):
            self.root('publish', ok=False)
        self.assertEqual(self.rows()[-1], (2, None, None, None))
        self.assert_closed()
        self.assertFalse(self.proof_file.exists())
        with self.assertRaises(FileNotFoundError), self.reader():
            self.fail('Unpublished fixture admitted')
        self.reopen()
        self.assert_closed()
        self.root('publish')
        self.assertTrue(f.store.authentication_options()['password'])
        self.assertEqual(self.rows()[-1], (2, None, None, None))

    def test_transaction_failure_rolls_back_both_rows_and_has_no_proof(self):
        f = self.fixture
        self.retire(self.root('ready'))
        original = self.rows()
        f.store._db.execute("CREATE TRIGGER reject_publish BEFORE UPDATE ON recovery_keys BEGIN SELECT RAISE(ABORT,'fixture'); END")
        self.root('publish', ok=False)
        self.assertEqual(self.rows(), original)
        self.assertFalse(self.proof_file.exists())
        self.assert_closed()
        f.store._db.execute('DROP TRIGGER reject_publish')
        self.root('publish')

    def test_terminal_ack_and_pair_are_required_before_ready(self):
        f = self.fixture
        original = self.rows()
        terminal = f.operation / 'held-activation-terminal.json'
        body = terminal.read_bytes()
        f.write(terminal, body + b'\n')
        self.root('ready', ok=False)
        f.write(terminal, body)
        row = f.store._db.execute('SELECT digest FROM recovery_keys').fetchone()
        f.store._db.execute('UPDATE recovery_keys SET digest=?', ('9' * 64,))
        self.root('ready', ok=False)
        f.store._db.execute('UPDATE recovery_keys SET digest=?', (row['digest'],))
        self.assertEqual(self.rows(), original)
        self.write_document(self.qualification_file, {**self.qualification, 'pairSha256': '9' * 64})
        self.root('ready', ok=False)
        self.assert_closed()

    def test_active_flags_cannot_bypass_missing_or_replaced_publication(self):
        f = self.fixture
        self.retire(self.root('ready'))
        self.root('publish')
        f.store._db.execute('UPDATE counters SET counter=4')
        self.assertTrue(f.store.authentication_options()['password'])
        with mock.patch.object(self.binding.backend, 'pair_sha256', '9' * 64):
            self.assert_closed()
        proof = self.proof_file.read_bytes()
        f.write(self.proof_file, proof + b'\n')
        self.assert_closed()
        self.root('publish', ok=False)
        self.assertEqual(self.proof_file.read_bytes(), proof + b'\n')
        self.proof_file.unlink()
        self.assert_closed()
        self.root('publish')
        self.assertEqual(self.proof_file.read_bytes(), proof)

    def test_published_replay_uses_initial_child_after_current_config_moves(self):
        self.retire(self.root('ready'))
        published = self.root('publish')
        # An ordinary lineage walker supplies the archived initial child bytes.
        self.fixture.write(self.fixture.base / 'credential-admission.json', b'fixture later config')
        self.fixture.write(self.namespace / floor.HISTORY, b'fixture later history')
        self.assertEqual(self.root('publish'), published)
        self.assertEqual(self.rows()[-1], (2, None, None, None))

    def test_recheck_and_child_scope_pin_immutable_publication(self):
        self.retire(self.root('ready'))
        self.root('publish')
        for changes in ({'history_body': self.history + b'\n'}, {'root': '/other'},
                        {'context': 'other'}, {'daemon': 'other'}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError), self.reader(**changes):
                self.fail('Crossed lineage admitted')
        release = self.namespace / publication.RELEASE_FILE
        with self.assertRaises(ValueError), self.reader() as witness:
            release.rename(release.with_suffix('.fixture-backup'))
            self.fixture.write(release, source.encoded({'schema': publication.RELEASE}))
            witness.recheck()


if __name__ == '__main__':
    unittest.main()
