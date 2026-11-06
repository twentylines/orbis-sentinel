"""Private descriptor handoff from the enrolled host capture supervisor."""

import argparse
import os
import sys

from . import verification as v
from .capture_catalog import CaptureCatalog, CatalogError
from .image_preflight import check_publication_image
from .capture_export import open_published_file


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
IMAGE_CHECK_CAPABILITY = {
    'schema': 'orbis-sentinel.capture-image-check-capability.v1', 'version': 1,
    'operations': ['check-publication-image', 'reserve-for-publication'],
    'lifecycleAuthority': False,
}
EXPORT_CAPABILITY = {
    'schema': 'orbis-sentinel.capture-export-capability.v1', 'version': 1,
    'operations': ['export-file'], 'pointVersion': 3,
    'files': ['capture-draft.orbis', 'core.orbis', 'icons.orbis', 'metadata.orbis', 'point.json', 'wallpaper.orbis'],
    'verification': 'delivered-sha256-and-file-seals.v1', 'lifecycleAuthority': False,
}


def _request(operation):
    body = sys.stdin.buffer.read(8193)
    if not body or len(body) > 8192:
        raise ValueError('Invalid capture custody request')
    value = v._json(body)
    common = {'schema', 'catalogDirectory'}
    reserve = operation in {'reserve', 'reserve-for-publication'}
    fields = (common | {'dataDirectory', 'sourceDirectories', 'jobId', 'installationId', 'sourceSha256',
                        'recoveryImageId', 'reservation'} if reserve
              else common | {'pointId', 'preparationSha256', 'sourceHoldSha256'})
    if operation == 'check-publication-image':
        fields = common | {'recoveryImageId'}
    if operation == 'publish':
        fields |= {'expectation', 'terminalSha256'}
    if operation == 'export-file':
        fields |= {'fileName', 'publicationSha256', 'terminalSha256'}
    if (not v._exact(value, fields)
            or value['schema'] != 'orbis-sentinel.capture-' + operation + '.v1'
            or v._canonical(value).encode() != body):
        raise ValueError('Invalid capture custody request')
    if reserve and (type(value['sourceDirectories']) is not list
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
    group.add_argument('--image-check-capability', action='store_true')
    group.add_argument('--check-publication-image', action='store_true')
    group.add_argument('--reserve-for-publication', action='store_true')
    group.add_argument('--export-capability', action='store_true')
    group.add_argument('--export-file', action='store_true')
    parser.add_argument('--key-fd', type=int)
    parser.add_argument('--point-fd', type=int)
    parser.add_argument('--checkpoint-fd', type=int)
    args = parser.parse_args(argv)
    if args.capability or args.publication_capability or args.image_check_capability or args.export_capability:
        if any(fd is not None for fd in (args.key_fd, args.point_fd, args.checkpoint_fd)):
            parser.error('Capability does not accept descriptors')
        print(v._canonical(EXPORT_CAPABILITY if args.export_capability else IMAGE_CHECK_CAPABILITY if args.image_check_capability else
                           PUBLICATION_CAPABILITY if args.publication_capability else CAPABILITY))
        return 0
    if sys.platform != 'linux' or os.geteuid() != 0:
        print('Capture custody requires the Linux recovery supervisor.', file=sys.stderr)
        return 1
    reserve = args.reserve or args.reserve_for_publication
    operation = ('export-file' if args.export_file else 'check-publication-image' if args.check_publication_image else 'reserve-for-publication'
                 if args.reserve_for_publication else 'reserve' if args.reserve else 'publish' if args.publish else 'retain-draft')
    descriptor = args.key_fd if reserve else args.checkpoint_fd if args.publish else args.point_fd
    count = sum(fd is not None for fd in (args.key_fd, args.point_fd, args.checkpoint_fd))
    no_descriptor = args.check_publication_image or args.export_file
    if (no_descriptor and count != 0 or not no_descriptor
            and (descriptor is None or descriptor < 3 or count != 1)):
        parser.error('Choose the descriptor for this operation')
    try:
        request = _request(operation)
        with CaptureCatalog(request['catalogDirectory']) as catalog:
            if args.export_file:
                with open_published_file(catalog, request['pointId'], file_name=request['fileName'],
                        publication_sha256=request['publicationSha256'], preparation_sha256=request['preparationSha256'],
                        source_hold_sha256=request['sourceHoldSha256'], terminal_sha256=request['terminalSha256']) as reader:
                    while block := reader.read(65536):
                        remaining = memoryview(block)
                        while remaining:
                            written = sys.stdout.buffer.write(remaining)
                            if not written:
                                raise OSError('Capture stream ended')
                            remaining = remaining[written:]
                    reader.complete()
            elif args.check_publication_image:
                result = check_publication_image(catalog, request['recoveryImageId'])
            elif reserve:
                # Keep the catalog lock from feature check through key custody.
                preflight = check_publication_image(catalog, request['recoveryImageId']) if args.reserve_for_publication else None
                result = catalog.reserve(
                    job_id=request['jobId'], installation_id=request['installationId'],
                    source_sha256=request['sourceSha256'], recovery_image_id=request['recoveryImageId'],
                    reservation=request['reservation'], key_fd=descriptor,
                    data_directory=request['dataDirectory'],
                    additional_data_directories=request['sourceDirectories'],
                )
                if args.reserve_for_publication:
                    result = {'custody': result, 'imagePreflight': preflight}
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
        if args.export_file:
            sys.stdout.buffer.flush()
        else:
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
