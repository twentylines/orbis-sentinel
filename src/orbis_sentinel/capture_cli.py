"""Private descriptor handoff from the enrolled host capture supervisor."""

import argparse
import os
import sys

from . import verification as v
from .capture_catalog import CaptureCatalog, CatalogError


CAPABILITY = {
    'schema': 'orbis-sentinel.capture-custody.v1', 'version': 1,
    'operations': ['reserve', 'retain-draft'],
    'mutations': 'private-capture-data-only', 'lifecycleAuthority': False,
}
PUBLICATION_CAPABILITY = {
    'schema': 'orbis-sentinel.capture-publication.v1', 'version': 1,
    'operations': ['publish'], 'pointVersion': 3,
    'publicationSchema': 'orbis.core-capture-catalog-publication.v1',
    'lifecycleAuthority': False, 'incompleteReplay': 'forbidden',
}


def _request(operation):
    body = sys.stdin.buffer.read(8193)
    if not body or len(body) > 8192:
        raise ValueError('Invalid capture custody request')
    value = v._json(body)
    common = {'schema', 'catalogDirectory'}
    fields = (common | {'dataDirectory', 'sourceDirectories', 'jobId', 'installationId', 'sourceSha256',
                        'recoveryImageId', 'reservation'} if operation == 'reserve'
              else common | {'pointId', 'preparationSha256', 'sourceHoldSha256'})
    if operation == 'publish':
        fields |= {'expectation', 'terminalSha256'}
    if (not v._exact(value, fields)
            or value['schema'] != 'orbis-sentinel.capture-' + operation + '.v1'
            or v._canonical(value).encode() != body):
        raise ValueError('Invalid capture custody request')
    if operation == 'reserve' and (type(value['sourceDirectories']) is not list
                                   or not 1 <= len(value['sourceDirectories']) <= 64
                                   or any(not isinstance(directory, str) for directory in value['sourceDirectories'])):
        raise ValueError('Invalid capture source directories')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description='Retain private capture data for the host supervisor')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--capability', action='store_true')
    group.add_argument('--reserve', action='store_true')
    group.add_argument('--retain-draft', action='store_true')
    group.add_argument('--publication-capability', action='store_true')
    group.add_argument('--publish', action='store_true')
    parser.add_argument('--key-fd', type=int)
    parser.add_argument('--point-fd', type=int)
    parser.add_argument('--checkpoint-fd', type=int)
    args = parser.parse_args(argv)
    if args.capability or args.publication_capability:
        if any(fd is not None for fd in (args.key_fd, args.point_fd, args.checkpoint_fd)):
            parser.error('Capability does not accept descriptors')
        print(v._canonical(PUBLICATION_CAPABILITY if args.publication_capability else CAPABILITY))
        return 0
    if sys.platform != 'linux' or os.geteuid() != 0:
        print('Capture custody requires the Linux recovery supervisor.', file=sys.stderr)
        return 1
    operation = 'reserve' if args.reserve else 'publish' if args.publish else 'retain-draft'
    descriptor = args.key_fd if args.reserve else args.checkpoint_fd if args.publish else args.point_fd
    if descriptor is None or descriptor < 3 or sum(fd is not None for fd in (args.key_fd, args.point_fd, args.checkpoint_fd)) != 1:
        parser.error('Choose the descriptor for this operation')
    try:
        request = _request(operation)
        with CaptureCatalog(request['catalogDirectory']) as catalog:
            if args.reserve:
                result = catalog.reserve(
                    job_id=request['jobId'], installation_id=request['installationId'],
                    source_sha256=request['sourceSha256'], recovery_image_id=request['recoveryImageId'],
                    reservation=request['reservation'], key_fd=descriptor,
                    data_directory=request['dataDirectory'],
                    additional_data_directories=request['sourceDirectories'],
                )
            elif args.retain_draft:
                result = catalog.retain_draft(
                    request['pointId'], point_fd=descriptor,
                    preparation_sha256=request['preparationSha256'],
                    source_hold_sha256=request['sourceHoldSha256'],
                )
            else:
                result = catalog.publish_prepared(
                    request['pointId'], expectation=request['expectation'], checkpoint_fd=descriptor,
                    preparation_sha256=request['preparationSha256'], source_hold_sha256=request['sourceHoldSha256'],
                    terminal_sha256=request['terminalSha256'],
                )
        print(v._canonical({'schema': 'orbis-sentinel.capture-custody-result.v1',
                            'operation': operation, 'result': result}))
        return 0
    except v.CleanupIndeterminate:
        print('Capture publication stopped. Worker cleanup needs review; recovery information was kept.', file=sys.stderr)
        return 2
    except (OSError, ValueError, CatalogError):
        print('Capture data could not be retained. Existing recovery information was kept.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
