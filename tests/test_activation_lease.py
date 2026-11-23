"""Real descriptor/flock checks; no services or installation are changed."""
import fcntl
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_activate_release import activate, PACKAGING


class ActivationLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.parent = activate._Parent(self.root)
        self.addCleanup(self.parent.close)
        self.path = self.root / 'activation.lock'

    def open_lock(self):
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def assert_contended(self):
        other = os.open(self.path, os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)

    def test_borrowed_duplicate_does_not_unlock_or_close_parent(self):
        held = self.open_lock()
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        duplicate = activate._activation_lock(self.parent, held)
        self.assertNotEqual(held, duplicate)
        os.close(duplicate)
        self.assert_contended()
        os.fstat(held)

    def test_parent_fd_can_acquire_the_lease_before_later_children(self):
        held = self.open_lock()
        os.close(activate._activation_lock(self.parent, held))
        self.assert_contended()

    def test_default_lock_release_still_allows_next_independent_caller(self):
        owned = activate._activation_lock(self.parent, None, create=True)
        self.assert_contended()
        os.close(owned)
        os.close(activate._activation_lock(self.parent, None))

    def test_descriptor_values_are_strict_and_missing_lock_is_not_created_on_return(self):
        for value in (True, False, -1, 0, 1, 2, '3', 3.0):
            with self.subTest(value=value), self.assertRaises(activate.ActivationError):
                activate._activation_lock(self.parent, value)
        with self.assertRaises(FileNotFoundError):
            activate._activation_lock(self.parent, None)
        self.assertFalse(self.path.exists())

    def test_independent_open_description_cannot_bypass_parent_lock(self):
        held = self.open_lock()
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        other = self.open_lock()
        with self.assertRaises(BlockingIOError):
            activate._activation_lock(self.parent, other)
        os.fstat(other)
        self.assert_contended()

    def test_untrusted_mode_owner_and_hardlink_are_refused(self):
        held = self.open_lock()
        self.path.chmod(0o644)
        with self.assertRaises(activate.ActivationError):
            activate._activation_lock(self.parent, held)
        self.path.chmod(0o600)
        with mock.patch.object(activate.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                activate._activation_lock(self.parent, held)
        os.link(self.path, self.root / 'alias')
        with self.assertRaises(activate.ActivationError):
            activate._activation_lock(self.parent, held)

    def test_readonly_foreign_unlinked_and_symlinked_lock_are_refused(self):
        held = self.open_lock()
        readonly = os.open(self.path, os.O_RDONLY)
        try:
            with self.assertRaises(activate.ActivationError):
                activate._activation_lock(self.parent, readonly)
        finally:
            os.close(readonly)
        self.path.rename(self.root / 'original')
        self.path.symlink_to(self.root / 'original')
        with self.assertRaises(activate.ActivationError):
            activate._activation_lock(self.parent, held)
        self.path.unlink()
        with self.assertRaises(FileNotFoundError):
            activate._activation_lock(self.parent, held)
        self.path.write_bytes(b'')
        self.path.chmod(0o600)
        with self.assertRaises(activate.ActivationError):
            activate._activation_lock(self.parent, held)

    def test_parent_continues_lock_after_real_child_exit_including_failure(self):
        held = self.open_lock()
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        program = '''import os,pathlib,runpy,sys
sys.path.insert(0,sys.argv[1])
api=runpy.run_path(sys.argv[1]+'/activate_release.py')
parent=api['_Parent'](pathlib.Path(sys.argv[2]))
try:
    descriptor=api['_activation_lock'](parent,int(sys.argv[3]))
    os.close(descriptor)
finally:
    parent.close()
sys.exit(int(sys.argv[4]))
'''
        for code in (0, 9):
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(PACKAGING),
                                     str(self.root), str(held), str(code)], pass_fds=(held,),
                                    capture_output=True, timeout=10, cwd=self.root,
                                    env={'PATH': os.defpath, 'TMPDIR': str(self.root),
                                         'PYTHONDONTWRITEBYTECODE': '1'})
            self.assertEqual(result.returncode, code, result.stderr)
            self.assert_contended()

    def test_named_lock_race_after_acquisition_is_refused_and_parent_stays_locked(self):
        held = self.open_lock()
        original = fcntl.flock
        def replace(descriptor, flags):
            original(descriptor, flags)
            self.path.rename(self.root / 'original')
            self.path.write_bytes(b'')
            self.path.chmod(0o600)
        with mock.patch.object(activate.fcntl, 'flock', side_effect=replace):
            with self.assertRaises(activate.ActivationError):
                activate._activation_lock(self.parent, held)
        other = os.open(self.root / 'original', os.O_RDWR)
        try:
            with self.assertRaises(BlockingIOError):
                original(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(other)


if __name__ == '__main__':
    unittest.main()
