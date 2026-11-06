"""Authenticated streaming of an independently published capture file."""

import hashlib
import os
from contextlib import contextmanager

from . import capture_catalog as c
from . import verification as v


class _Reader:
    def __init__(self, fd, info, check):
        self._fd = fd
        self.bytes = info['bytes']
        self.sha256 = info['sha256']
        self._digest = hashlib.sha256()
        self._offset = 0
        self._check = check
        self._done = False
        self._failed = False

    def read(self, size):
        if self._done or self._failed or type(size) is not int or not 1 <= size <= 65536:
            self._failed = True
            c._fail()
        try:
            data = os.pread(self._fd, min(size, self.bytes - self._offset), self._offset)
            if not data and self._offset != self.bytes:
                c._fail()
            self._offset += len(data)
            self._digest.update(data)
            return data
        except Exception:
            self._failed = True
            raise

    def complete(self):
        if self._done or self._failed:
            c._fail()
        try:
            if self._offset != self.bytes or self._digest.hexdigest() != self.sha256:
                c._fail()
            self._check()
            self._done = True
        except Exception:
            self._failed = True
            raise


@contextmanager
def open_published_file(catalog, point_id, *, file_name, publication_sha256,
                        preparation_sha256, source_hold_sha256, terminal_sha256):
    """Yield a bounded reader; the caller must complete before accepting bytes.

    Bytes delivered before complete() are provisional. No lifecycle authority is granted.
    """
    with catalog._operation():
        if (not isinstance(point_id, str) or not v._UUID.fullmatch(point_id)
                or not isinstance(file_name, str) or file_name not in c._ALLOWED
                or any(not isinstance(x, str) or not v._HASH.fullmatch(x) for x in
                       (publication_sha256, preparation_sha256, source_hold_sha256, terminal_sha256))):
            c._fail()
        binding = catalog._record(point_id)
        obj = catalog._object(point_id, binding)
        if hashlib.sha256(v._canonical(obj['publication']).encode()).hexdigest() != publication_sha256:
            c._fail()
        pubs = catalog._children['publications'][0]
        claim_name = point_id + '.json'
        claim_body, _, claim_stat = c._read(pubs, claim_name, c._MAX_RECORD)
        claim = v._json(claim_body)
        fixed = {'schema': 'orbis-sentinel.publication-claim.v1',
                 'bindingSha256': hashlib.sha256(v._canonical(binding).encode()).hexdigest(),
                 'expectation': obj['expectation'], 'preparationSha256': preparation_sha256,
                 'sourceHoldSha256': source_hold_sha256, 'terminalSha256': terminal_sha256}
        if (v._canonical(claim).encode() != claim_body
                or not v._exact(claim, set(fixed) | {'workspace'})
                or v._canonical({k: claim[k] for k in fixed}) != v._canonical(fixed)
                or not isinstance(claim['workspace'], str) or not c._STAGE.fullmatch(claim['workspace'])
                or file_name not in obj['publication']['files']):
            c._fail()
        objects = catalog._children['objects'][0]
        ofd, _ = c._dir(objects, point_id)
        try:
            os_initial = v._seal(os.fstat(ofd))
            record_body, _, record_stat = c._read(ofd, 'record.json', c._MAX_RECORD)
            if v._json(record_body) != obj:
                c._fail()
            pfd, _ = c._dir(ofd, 'point')
            try:
                ps_initial = v._seal(os.fstat(pfd))
                if v._mount_id(ofd) != catalog._mount or v._mount_id(pfd) != catalog._mount:
                    c._fail()
                fd = os.open(file_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd)
                try:
                    info = obj['publication']['files'][file_name]
                    fs = v._seal(c._regular(fd, c._LIMITS[file_name], info['bytes']))
                    if list(fs) != obj['seals'][file_name] or v._seal(os.stat(file_name, dir_fd=pfd, follow_symlinks=False)) != fs:
                        c._fail()
                    def check():
                        catalog._check()
                        if (v._seal(os.fstat(fd)) != fs
                                or v._seal(os.stat(file_name, dir_fd=pfd, follow_symlinks=False)) != fs
                                or v._seal(os.fstat(pfd)) != ps_initial
                                or v._seal(os.stat('point', dir_fd=ofd, follow_symlinks=False)) != ps_initial
                                or v._seal(os.fstat(ofd)) != os_initial
                                or v._seal(os.stat('record.json', dir_fd=ofd, follow_symlinks=False)) != v._seal(record_stat)
                                or c._read(ofd, 'record.json', c._MAX_RECORD)[0] != record_body
                                or v._seal(os.stat(point_id, dir_fd=objects, follow_symlinks=False)) != os_initial
                                or v._seal(os.stat(claim_name, dir_fd=pubs, follow_symlinks=False)) != v._seal(claim_stat)
                                or c._read(pubs, claim_name, c._MAX_RECORD)[0] != claim_body
                                or catalog._record(point_id) != binding
                                or catalog._object(point_id, binding) != obj):
                            c._fail()
                    reader = _Reader(fd, info, check)
                    yield reader
                    if not reader._done or reader._failed:
                        c._fail()
                    check()
                finally:
                    os.close(fd)
            finally:
                os.close(pfd)
        finally:
            os.close(ofd)
