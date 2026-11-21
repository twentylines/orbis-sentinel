"""Defensive negative and positive checks on synthetic, project-private state."""

import os
import unittest
from unittest import mock

import test_bootstrap_publication
from orbis_sentinel import bootstrap_publication as publication
from orbis_sentinel import bootstrap_source as source
from orbis_sentinel import credential_floor as floor
from orbis_sentinel import recovery_listener_install as listener
from orbis_sentinel import writer_broker
import test_writer_broker


class PublicationRegressions(unittest.TestCase):
    def setUp(self):
        self.paired = test_bootstrap_publication.PairedPublicationTests('runTest')
        self.addCleanup(self.paired.doCleanups)
        self.paired.setUp()

    def publish(self):
        self.paired.retire(self.paired.root('ready'))
        return self.paired.root('publish')

    def test_retry_repairs_failed_proof_directory_fsync(self):
        paired = self.paired
        paired.retire(paired.root('ready'))
        directory = paired.proof_file.parent.stat()
        identity = (directory.st_dev, directory.st_ino)
        original_fsync = os.fsync
        attempts = []

        def watch_fsync(fd, *, interrupt=False):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == identity and paired.proof_file.is_file():
                attempts.append(True)
                if interrupt:
                    raise OSError('fixture interruption after proof rename')
            original_fsync(fd)

        before = paired.rows()
        with mock.patch.object(os, 'fsync', side_effect=lambda fd: watch_fsync(fd, interrupt=True)):
            paired.root('publish', ok=False)
        self.assertEqual(attempts, [True])
        self.assertTrue(paired.proof_file.is_file())
        self.assertEqual(paired.rows()[-1][0], before[-1][0] + 1)
        attempts.clear()
        with mock.patch.object(os, 'fsync', side_effect=watch_fsync):
            paired.root('publish')
        self.assertEqual(paired.rows()[-1][0], before[-1][0] + 1)
        self.assertTrue(attempts, 'retry reported success without synchronizing the proof directory')

    def test_existing_witness_rechecks_original_pair_receipt(self):
        self.publish()
        with self.assertRaises((OSError, ValueError)), self.paired.reader() as witness:
            witness.recheck()
            (self.paired.fixture.root / listener.PAIRED_FILE).unlink()
            with self.assertRaises((OSError, ValueError)):
                witness.recheck()

    def test_new_witness_requires_store_reservation(self):
        self.publish()
        with self.paired.reader() as witness:
            witness.recheck()
        (self.paired.fixture.root / listener.STORE_BINDING).unlink()
        with self.assertRaises((OSError, ValueError)), self.paired.reader():
            self.fail('historical publication accepted with its setup reservation missing')

    def test_open_witness_rechecks_operation_member_mount(self):
        self.publish()
        with self.paired.reader() as witness:
            witness.recheck()
            member = (self.paired.fixture.operation / 'activation-approval.json').stat()
            identity = (member.st_dev, member.st_ino)
            original = source.mount_id

            def mount(fd):
                info = os.fstat(fd)
                return 'changed mount' if (info.st_dev, info.st_ino) == identity else original(fd)

            with mock.patch.object(source, 'mount_id', side_effect=mount):
                with self.assertRaises(ValueError):
                    witness.recheck()
            witness.recheck()

    def test_paired_eligibility_route_is_closed_before_publication_and_read_only_after(self):
        from orbis_sentinel.recovery_control import RecoveryControl, _SCHEMA
        f = self.paired.fixture
        control = RecoveryControl(sessions=f.store, profiles=f.profiles, origin=f.origin)
        request = {'schema': _SCHEMA, 'operation': 'operator-writer-eligibility', 'arguments': {}}
        self.assertFalse(control.handle(request)['ok'])
        self.publish()
        before = self.paired.rows()
        result = control.handle(request)
        self.assertTrue(result['ok'])
        self.assertEqual(result['result'], {
            'schema': 'orbis.sentinel-operator-writer-eligibility.v1',
            'generation': f.store.operator_status()['generation'],
            'revision': f.store.operator_status()['revision'], 'eligible': False})
        self.assertEqual(self.paired.rows(), before)
        self.assertFalse(control.handle({**request, 'arguments': {'eligible': True}})['ok'])

    def test_publish_rechecks_absence_of_pending_bootstrap_intent(self):
        paired = self.paired
        ready = paired.root('ready')
        paired.retire(ready)
        with publication.host_publication(paired.review, paired.packet, source.digest(
                (paired.fixture.operation / 'activation-approval.json').read_bytes()),
                paired.completion, paired.binding, recovery_directory=paired.fixture.root,
                ready=ready) as held:
            held.recheck()
            transient = paired.namespace / ('.' + publication.INTENT + '.pending')
            paired.fixture.write(transient, b'fixture late pending write')
            try:
                with self.assertRaises(ValueError):
                    held.recheck()
            finally:
                transient.unlink()

    def test_historical_witness_keeps_original_child_through_later_sync_fence(self):
        paired = self.paired
        published = self.publish()
        floor_reader = floor.CredentialFloorReader(
            paired.review['root'], paired.review['context'], paired.review['daemon'],
            host_state_directory=paired.fixture.base)
        with paired.reader() as witness:
            self.assertEqual((witness.host_generation, witness.sessions_generation), (8, 2))
            paired.fixture.write(paired.namespace / publication.FENCE, b'fixture later sync fence')
            witness.recheck()
            self.assertIn(publication.FENCE, floor_reader._pending(paired.namespace))
        self.assertEqual(paired.root('publish'), published)

    def test_packet_members_reject_cross_mount_custody(self):
        paired = self.paired
        self.publish()
        member = (paired.fixture.operation / 'activation-approval.json').stat()
        identity = (member.st_dev, member.st_ino)
        original_mount_id = source.mount_id

        def observe_mount(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == identity:
                return 'fixture different mount'
            return original_mount_id(fd)

        with (mock.patch.object(source, 'mount_id', side_effect=observe_mount),
              mock.patch.object(publication, 'mount_id', side_effect=observe_mount)):
            with self.assertRaises(ValueError), paired.reader():
                self.fail('an activation approval outside its operation mount was accepted')

    def test_unsupported_paired_writer_does_not_leave_later_sync_fence(self):
        paired = self.paired
        self.publish()
        app = paired.fixture
        store = app.store
        writer = test_writer_broker.WriterBrokerTests('runTest')
        self.addCleanup(writer.doCleanups)
        writer.setUp()
        writer.use_lifecycle()
        calls = []

        def fixed_control(operation, args):
            calls.append(operation)
            if operation == 'operator-status':
                status = store.operator_status()
                self.assertEqual(status['state'], 'enrolled')
                return status
            if operation == 'operator-writer-eligibility':
                return store.operator_writer_eligibility()
            self.assertEqual(operation, 'operator-prepare-writer')
            # Reuse the real final Sessions mutation gate. The worker run and
            # authenticated transport that normally precede it are omitted here.
            return store._begin_operator_enrollment(
                expected_generation=args['expectedGeneration'], expected_revision=args['expectedRevision'],
                identity_sha256='e' * 64, origin=app.origin, change_token=args['changeToken'])

        writer.control.call = fixed_control
        with self.assertRaises(writer_broker.WriterBrokerError):
            writer.prepare()
        self.assertEqual(calls, ['operator-status', 'operator-writer-eligibility'])
        state = writer.instance.journal.read()
        self.assertFalse(writer.lifecycle.marker is not None or state['active'] is not None,
                         'a deferred paired mutation must be rejected before acquiring a sync fence')
