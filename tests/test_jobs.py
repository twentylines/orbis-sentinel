import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from orbis_sentinel import jobs
from orbis_sentinel.contracts import Phase


class JobStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = self.temp.name
        self.owner = mock.patch.object(jobs, '_OWNER_UID', os.getuid())
        self.owner.start()
        self.addCleanup(self.owner.stop)

    def store(self):
        store = jobs.JobStore(self.directory)
        self.addCleanup(store.close)
        return store

    def test_lifecycle_persistence_replay_and_global_exclusion(self):
        store = self.store()
        job = store.create('orbis', 'repair', {'reason': 'test'})
        with self.assertRaises(jobs.StoreError):
            store.create('sentinel', 'update', {})
        token = store.claim(job)
        with self.assertRaises(jobs.StoreError):
            store.claim(job)
        store.transition(job, token, Phase.PREPARING, 'preparing')
        store.append(job, token, 'detail')
        store.transition(job, token, Phase.RUNNING, 'running')
        with self.assertRaises(jobs.StoreError):
            store.transition(job, token, Phase.INSTALLING, 'invalid')
        self.assertEqual(store.get(job)['phase'], 'running')
        self.assertEqual([e['seq'] for e in store.events(job, after=1, limit=1)], [2])
        self.assertEqual(len(store.events(job)), 3)
        self.assertEqual([e['phase'] for e in store.events(job)], ['preparing', 'preparing', 'running'])
        with self.assertRaises(ValueError):
            store.events(job, limit=501)
        store.close()
        reopened = self.store()
        self.assertEqual(reopened.active()['id'], job)
        self.assertTrue(reopened.get(job)['interrupted'])
        self.assertEqual(len(reopened.events(job)), 3)
        with self.assertRaises(jobs.StoreError):
            reopened.append(job, token, 'stale')
        with self.assertRaises(jobs.StoreError):
            reopened.claim(job)
        with self.assertRaises(jobs.StoreError):
            reopened.create('sentinel', 'repair', {})

    def test_store_requires_delete_journaling_and_extra_sync(self):
        store = self.store()
        self.assertEqual(store._db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
        self.assertEqual(store._db.execute('PRAGMA synchronous').fetchone()[0], 3)
        self.assertEqual(store._db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')

    def test_failed_directory_sync_closes_the_store_without_borrowing_authority(self):
        with mock.patch.object(jobs.os, 'fsync', side_effect=OSError('injected sync failure')):
            with self.assertRaises(OSError):
                jobs.JobStore(self.directory)
        store = self.store()
        self.assertIsNone(store.active())

    def test_token_forgery_and_terminal_transition(self):
        store = self.store()
        job = store.create('sentinel', 'restart', {})
        token = store.claim(job)
        with self.assertRaises(jobs.StoreError):
            store.transition(job, 'forged', Phase.PREPARING, 'forged')
        self.assertEqual(store.events(job), [])
        store.transition(job, token, Phase.CANCELLED, 'cancelled')
        self.assertIsNone(store.active())
        with self.assertRaises(jobs.StoreError):
            store.append(job, token, 'late')
        self.assertTrue(store.create('orbis', 'backup', {}))
        db = sqlite3.connect(os.path.join(self.directory, 'jobs.sqlite3'))
        self.addCleanup(db.close)
        stored = db.execute('SELECT claim_hash FROM jobs WHERE id=?', (job,)).fetchone()[0]
        self.assertNotEqual(stored, token)
        self.assertNotIn(token, stored)

    def test_exclusive_store_in_process_and_subprocess(self):
        self.store()
        with self.assertRaises(BlockingIOError):
            jobs.JobStore(self.directory)
        script = ("import os,sys; from orbis_sentinel import jobs; "
                  "jobs._OWNER_UID=os.getuid(); "
                  "jobs.JobStore(sys.argv[1])")
        result = subprocess.run([sys.executable, '-c', script, self.directory], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('BlockingIOError', result.stderr)

    def test_invalid_inputs(self):
        store = self.store()
        for meta in ({'x': 1}, {'': 'x'}, {'x': 'a' * 1025}, {'x': '\x00'}, {'x': ['a']}):
            with self.subTest(meta=meta), self.assertRaises(ValueError):
                store.create('orbis', 'repair', meta)
        with self.assertRaises(ValueError):
            store.create('other', 'repair', {})
        job = store.create('orbis', 'repair', {})
        token = store.claim(job)
        for text in ('', '\x00', 'a' * 4097):
            with self.assertRaises(ValueError):
                store.append(job, token, text)
        self.assertEqual(store.events(job), [])

    def test_transition_rolls_back_if_event_insert_fails(self):
        store = self.store()
        job = store.create('orbis', 'repair', {})
        token = store.claim(job)
        with mock.patch.object(store, '_append', side_effect=sqlite3.OperationalError('failed')):
            with self.assertRaises(sqlite3.OperationalError):
                store.transition(job, token, Phase.PREPARING, 'start')
        self.assertEqual(store.get(job)['phase'], 'queued')
        self.assertEqual(store.events(job), [])

    def test_abrupt_process_exit_preserves_claim(self):
        script = ("import os,sys; from orbis_sentinel import jobs; "
                  "jobs._OWNER_UID=os.getuid(); s=jobs.JobStore(sys.argv[1]); "
                  "j=s.create('orbis','repair',{}); s.claim(j); "
                  "print(j,flush=True); os._exit(0)")
        result = subprocess.run([sys.executable, '-c', script, self.directory], capture_output=True, text=True, check=True)
        job = result.stdout.strip()
        store = self.store()
        self.assertTrue(store.get(job)['interrupted'])
        with self.assertRaises(jobs.StoreError):
            store.create('sentinel', 'restore', {})
        with self.assertRaises(jobs.StoreError):
            store.claim(job)

    def test_directory_and_file_safety(self):
        os.chmod(self.directory, 0o755)
        with self.assertRaises(jobs.StoreError):
            jobs.JobStore(self.directory)
        os.chmod(self.directory, 0o700)
        lock = os.path.join(self.directory, 'jobs.lock')
        os.symlink('/dev/null', lock)
        with self.assertRaises(OSError):
            jobs.JobStore(self.directory)
        os.unlink(lock)
        db = os.path.join(self.directory, 'jobs.sqlite3')
        with open(db, 'w'):
            pass
        os.chmod(db, 0o644)
        with self.assertRaises(jobs.StoreError):
            jobs.JobStore(self.directory)
        os.unlink(db)
        os.symlink('/dev/null', db)
        with self.assertRaises(OSError):
            jobs.JobStore(self.directory)

    def test_claimed_queued_job_survives_crash_like_close(self):
        store = self.store()
        job = store.create('orbis', 'restore', {})
        token = store.claim(job)
        store.close()
        store = self.store()
        self.assertEqual(store.get(job)['phase'], 'queued')
        self.assertTrue(store.get(job)['interrupted'])
        with self.assertRaises(jobs.StoreError):
            store.transition(job, token, Phase.CANCELLED, 'stale')
        with self.assertRaises(jobs.StoreError):
            store.create('orbis', 'repair', {})

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
    def test_inherited_store_cannot_authorize_a_forked_worker(self):
        store = self.store()
        job = store.create('orbis', 'repair', {})
        token = store.claim(job)
        pid = os.fork()
        if pid == 0:
            try:
                store.transition(job, token, Phase.PREPARING, 'child')
            except jobs.StoreError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(store.events(job), [])


if __name__ == '__main__':
    unittest.main()
