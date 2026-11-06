"""Export only the approved local image IDs; validate archives in an offline worker."""

import http.client
import re
import socket
import os
import selectors
import subprocess
import time
from urllib.parse import quote, urlencode

from . import verification as v


class _Engine(http.client.HTTPConnection):
    def __init__(self):
        super().__init__('localhost', timeout=30)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect('/var/run/docker.sock')


class ImageExporter:
    def _json_get(self, path):
        connection = _Engine()
        try:
            connection.request('GET', path, headers={'Connection': 'close'})
            reply = connection.getresponse()
            body = reply.read(1024 * 1024 + 1)
            if reply.status != 200 or not body or len(body) > 1024 * 1024:
                v._fail()
            return v._json(body)
        finally:
            connection.close()

    def _version(self):
        if not hasattr(self, '_api'):
            value = self._json_get('/version')
            version = value.get('ApiVersion') if isinstance(value, dict) else None
            if not isinstance(version, str) or not re.fullmatch(r'1\.[0-9]{2,3}', version):
                v._fail()
            self._api = min(int(version.split('.')[1]), 51)
        return self._api

    def inspect_image(self, image, platform=None):
        if not isinstance(image, str) or not v._IMAGE.fullmatch(image):
            v._fail()
        version = self._version()
        query = {'manifests': 'true'}
        if platform is not None:
            parts = platform.split('/')
            if version < 49 or not 2 <= len(parts) <= 3 or any(not re.fullmatch('[a-z0-9][a-z0-9._-]{0,63}', p) for p in parts):
                v._fail()
            query = {'platform': v._canonical(dict(zip(('os', 'architecture', 'variant'), parts)))}
        value = self._json_get('/v1.%d/images/%s/json?' % (version, quote(image, safe=':')) + urlencode(query))
        if type(value) is not dict:
            v._fail()
        if version < 48 and value.get('Descriptor') is not None:
            v._fail()
        # Runtime configuration and image environment are not part of this record.
        result = {k: value[k] for k in ('Id', 'RepoDigests', 'Os', 'Architecture', 'Variant')
                  if k in value and value[k] is not None}
        if value.get('Manifests') is not None:
            if type(value['Manifests']) is not list or len(value['Manifests']) > 256:
                v._fail()
            manifests = []
            for item in value['Manifests']:
                if type(item) is not dict or type(item.get('Descriptor')) is not dict:
                    v._fail()
                descriptor = {k: item['Descriptor'][k] for k in ('digest', 'platform') if k in item['Descriptor']}
                def platform_fields(value):
                    if type(value) is not dict:
                        v._fail()
                    return {k: value[k] for k in ('os', 'architecture', 'variant') if k in value}
                if 'platform' in descriptor:
                    descriptor['platform'] = platform_fields(descriptor['platform'])
                row = {k: item[k] for k in ('Kind', 'Available') if k in item}
                row['Descriptor'] = descriptor
                if type(item.get('ImageData')) is dict and 'Platform' in item['ImageData']:
                    row['ImageData'] = {'Platform': platform_fields(item['ImageData']['Platform'])}
                manifests.append(row)
            result['Manifests'] = manifests
        return result

    def save_image(self, image, destination, platform=None):
        args = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'image', 'save']
        if platform is not None:
            args += ['--platform', platform]
        args.append(image)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        child = None
        try:
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'HOME': '/'}, close_fds=True)
            count, error_bytes = 0, 0
            deadline = time.monotonic() + 1800
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ, True)
                selector.register(child.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        v._fail()
                    for key, _ in selector.select(remaining):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        if not key.data:
                            error_bytes += len(block)
                            if error_bytes > 8192:
                                v._fail()
                            continue
                        count += len(block)
                        space = os.fstatvfs(fd)
                        if count > 16 * 1024**3 or space.f_bavail * space.f_frsize < len(block) + 256 * 1024**2:
                            v._fail()
                        view = memoryview(block)
                        while view:
                            written = os.write(fd, view)
                            if written <= 0:
                                v._fail()
                            view = view[written:]
            if child.wait(timeout=max(0.01, deadline - time.monotonic())) != 0 or not count:
                v._fail()
            os.fsync(fd)
            return count
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait()
                child.stdout.close()
                child.stderr.close()
            os.close(fd)

    def export(self, directory, expected):
        ids = sorted(set(expected['images'].values()))
        records, total = [], 0
        for image in ids:
            original = self.inspect_image(image)
            if original.get('Id') != image:
                v._fail()
            platform = expected['compatibility']['os'] + '/' + expected['compatibility']['architecture']
            selected = self.inspect_image(image, platform) if original.get('Manifests') else original
            if selected.get('Os') != expected['compatibility']['os'] or selected.get('Architecture') != expected['compatibility']['architecture']:
                v._fail()
            export_platform = platform + ('/' + selected['Variant'] if selected.get('Variant') else '') if original.get('Manifests') else None
            total += self.save_image(image, os.path.join(directory, 'image-' + image[7:] + '.tar'), export_platform)
            if total > 64 * 1024**3 or self.inspect_image(image) != original:
                v._fail()
            records.append({'imageId': image, 'inspection': original, 'selected': selected})
        body = v._canonical({'schema': 'orbis.core-image-exports.v1', 'images': records}).encode()
        if len(body) > 1024 * 1024:
            v._fail()
        fd = os.open(os.path.join(directory, 'exports.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    v._fail()
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)


class InventoryWorker(v._Docker):
    _WORKER = '/app/core-capture-image-inventory.mjs'

    def create(self, name, nonce, image, data, staging, encoded):
        args = ['create', '--pull=never', '--name', name, '--label', 'orbis.sentinel.verifier=' + nonce,
                '--network', 'none', '--ipc', 'none', '--no-healthcheck', '--restart', 'no', '--cpus', '1',
                '--read-only', '--user', '0:0', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--pids-limit', '128', '--memory', '2g', '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
                '--mount', 'type=bind,src=' + os.path.join(data, 'image-exports') + ',dst=/data/image-exports,readonly',
                '--mount', 'type=bind,src=' + os.path.join(data, 'image-inventory-output') + ',dst=/data/image-inventory-output',
                '--entrypoint', '/usr/local/bin/node', image, self._WORKER, '--build', encoded]
        code, body = self._run(args)
        identity = body.decode('ascii').strip()
        if code or not v._HASH.fullmatch(identity):
            v._fail()
        return identity


def prepare_images(workspace, image_id, expected, *, exporter=None, runner=None):
    data = os.path.join(workspace, 'data')
    exports = os.path.join(data, 'image-exports')
    output = os.path.join(data, 'image-inventory-output')
    os.mkdir(data, 0o700)
    os.mkdir(exports, 0o700)
    os.mkdir(output, 0o700)
    (exporter if exporter is not None else ImageExporter()).export(exports, expected)
    def validate(value):
        if (not v._exact(value, ('schema', 'pointId', 'sourceSha256', 'inventorySha256', 'imageCount', 'totalBytes'))
                or value['schema'] != 'orbis.core-image-inventory-publication.v1'
                or value['pointId'] != expected['pointId'] or value['sourceSha256'] != expected['sourceSha256']
                or type(value['imageCount']) is not int or value['imageCount'] != len(set(expected['images'].values()))
                or not v._integer(value['totalBytes'], 1, 64 * 1024**3)
                or not isinstance(value['inventorySha256'], str) or not v._HASH.fullmatch(value['inventorySha256'])):
            v._fail()
        return value
    result = v._execute_worker(runner if runner is not None else InventoryWorker(), workspace, image_id,
                               v._canonical(expected), validate)
    inventory = os.path.join(output, 'images', 'inventory.json')
    # The worker authenticates archives; bind its durable inventory result too.
    from .capture_catalog import _read
    descriptor = v._open_absolute(os.path.dirname(inventory))
    try:
        _, digest, _ = _read(descriptor, 'inventory.json', 2 * 1024 * 1024)
        if digest != result['inventorySha256']:
            v._fail()
    finally:
        os.close(descriptor)
    return os.path.dirname(inventory), result
