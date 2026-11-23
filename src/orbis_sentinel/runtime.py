"""Read-only local service entry point; privileged operations are separate."""

import argparse
from contextlib import contextmanager
import os
import signal
import socket
import subprocess
import sys
import threading

from . import __version__
from .collector import TelemetryCollector
from .contracts import API_PREFIX, PROTOCOL_VERSION
from .server import SentinelServer
from .status import ComponentStatus, build_status
from .observer import ObserverCollector, unavailable_handoff


def activation_listener():
    """Accept exactly one systemd socket addressed to this process."""
    if (os.environ.get("LISTEN_PID") != str(os.getpid())
            or os.environ.get("LISTEN_FDS") != "1"
            or os.environ.get("LISTEN_FDNAMES") not in (None, "api")):
        raise ValueError("exactly one Sentinel API socket must be supplied")
    listener = socket.socket(fileno=os.dup(3))
    try:
        if (listener.family != socket.AF_UNIX or listener.type != socket.SOCK_STREAM
                or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                or not isinstance(listener.getsockname(), str) or not listener.getsockname().startswith("/")):
            raise ValueError("Sentinel API requires a listening filesystem Unix socket")
    except BaseException:
        listener.close()
        raise
    os.set_inheritable(3, False)
    for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(key, None)
    return listener


_HOST_ACTIVATION_ACTIONS = ('prepare-activation', 'arm-activation', 'collect-activation', 'commit-activation', 'release-activation')



@contextmanager
def _held_recovery_writer(name):
    from contextlib import closing
    from types import ModuleType
    from . import host_source_publication as publication
    from .collector_execution import _root
    if name not in ('bootstrap_host_transition', 'recovery_worker_provision', 'recovery_listener_install',
                    'recovery_https_install'):
        publication.fail()
    _root()
    with closing(publication._Pins()) as pins:
        publication._activation_lock(pins)
        evidence = publication._producer(pins)
        installed = evidence['installation']
        member = f'src/orbis_sentinel/{name}.py'
        entry = installed['files'].get(member)
        if not entry or not 0 < entry['bytes'] <= 262144:
            publication.fail()
        path = publication.ROOT / 'releases' / installed['version'] / member
        body = pins.file(path, entry['bytes'], 0o644)
        if len(body) != entry['bytes'] or publication.sha(body) != entry['sha256']:
            publication.fail()
        pins.verify()
        module = ModuleType(f'orbis_sentinel._held_{name}')
        module.__package__, module.__file__ = 'orbis_sentinel', str(path)
        exec(compile(body, str(path), 'exec', dont_inherit=True), module.__dict__)
        pins.verify()
        yield module, pins.verify
        pins.verify()


def _run_host_activation(action, operation, review, plan, *, request, packet, approval):
    import json
    try:
        with _held_recovery_writer('bootstrap_host_transition') as (module, verify):
            result = module.run(action, operation, review, plan, request=request, packet=packet, approval=approval,
                                verify_package=verify)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, EOFError, KeyboardInterrupt):
        print('Host recovery activation needs reconciliation. Preserve the existing protected hold.', file=sys.stderr)
        return 1


def _run_worker_provision(action, operation, publication_sha, review, approval):
    import json
    try:
        with _held_recovery_writer('recovery_worker_provision') as (module, verify):
            result = module.run(action, operation, publication_sha, review, approval, verify_package=verify)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, EOFError, KeyboardInterrupt):
        print('Retained recovery worker needs reconciliation. Preserve its protected operation.', file=sys.stderr)
        return 1


def _run_listener_install(action, operation, publication_sha, worker_sha, port, review, approval, *, builtin=None):
    import json
    try:
        with _held_recovery_writer('recovery_listener_install') as (module, verify):
            result = module.run(action,operation,publication_sha,worker_sha,port,review,approval,
                                verify_package=verify,builtin=builtin)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, EOFError, subprocess.SubprocessError, KeyboardInterrupt):
        print('Recovery listener setup needs reconciliation. Preserve its protected operation.', file=sys.stderr)
        return 1


def _run_https_install(action, operation, review, approval):
    import json
    try:
        with _held_recovery_writer('recovery_https_install') as (module, verify):
            result = module.run(action, operation, review, approval, verify_package=verify)
        print(json.dumps(result))
        return 0
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, EOFError, subprocess.SubprocessError, KeyboardInterrupt):
        print('Recovery HTTPS setup needs reconciliation. Preserve its protected operation.', file=sys.stderr)
        return 1


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    protected = any(value == '--bootstrap' or value.startswith('--bootstrap=') for value in arguments)

    class Arguments(argparse.ArgumentParser):
        def error(self, message):
            if protected:
                message = 'Invalid bootstrap arguments. Use the hidden prompt to acknowledge a saved key.'
            super().error(message)

    parser = Arguments(description="Orbis Sentinel local status service", allow_abbrev=False)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", help="new socket in an existing private runtime directory")
    source.add_argument("--systemd-socket", action="store_true", help="use the systemd API socket")
    source.add_argument("--recovery-profile", help="use a protected supervisor-enrolled recovery configuration")
    source.add_argument("--verify-host-source", metavar="OPERATION_ID", help="verify a protected Host source publication operation")
    source.add_argument("--review-host-source", metavar="OPERATION_ID", help="stage an exact Host source publication plan for approval")
    source.add_argument("--review-recovery-worker", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--apply-recovery-worker", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--review-recovery-listener", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--apply-builtin-recovery-listener", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--prepare-recovery-listener-backend", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--apply-recovery-listener", metavar="PUBLISHER_OPERATION_ID")
    source.add_argument("--listener-https-probe", action="store_true", help=argparse.SUPPRESS)
    source.add_argument("--recovery-https-edge", action="store_true", help=argparse.SUPPRESS)
    source.add_argument("--review-recovery-https", metavar="OPERATION_ID")
    source.add_argument("--apply-recovery-https", metavar="OPERATION_ID")
    source.add_argument("--export-recovery-https-ca", metavar="OPERATION_ID")
    source.add_argument("--bootstrap", choices=('prepare-plan', 'stage', 'status', 'prepare-key', 'save-key', 'acknowledge-key',
                                               'authorize-browser', 'revoke-browser',
                                               *_HOST_ACTIVATION_ACTIONS),
                        help="run a protected existing-installation recovery bootstrap step")
    parser.add_argument("--bootstrap-operation", metavar="SHA256")
    parser.add_argument("--review-sha256", metavar="SHA256")
    parser.add_argument("--plan-sha256", metavar="SHA256")
    parser.add_argument("--request-id", metavar="SHA256")
    parser.add_argument("--activation-packet-sha256", metavar="SHA256")
    parser.add_argument("--activation-approval-sha256", metavar="SHA256")
    parser.add_argument("--publisher-receipt-sha256", metavar="SHA256")
    parser.add_argument("--worker-review-sha256", metavar="SHA256")
    parser.add_argument("--worker-approval-sha256", metavar="SHA256")
    parser.add_argument("--listener-worker-receipt-sha256", metavar="SHA256")
    parser.add_argument("--listener-loopback-port", type=int, metavar="PORT")
    parser.add_argument("--listener-review-sha256", metavar="SHA256")
    parser.add_argument("--listener-approval-sha256", metavar="SHA256")
    parser.add_argument("--listener-origin-operation", metavar="SHA256")
    parser.add_argument("--listener-origin-receipt-sha256", metavar="SHA256")
    parser.add_argument("--https-review-sha256", metavar="SHA256")
    parser.add_argument("--https-approval-sha256", metavar="SHA256")
    parser.add_argument("--save-key-to", metavar="ABSOLUTE_FILE", help="create a private file in an existing Root-only directory")
    parser.add_argument("--installer-selection", metavar="DIRECTORY", help="protected installer selection for Host source review")
    parser.add_argument("--host-copy-sha256", metavar="SHA256", help="exact installed-copy receipt for Host source review")
    parser.add_argument("--disk-path", action="append", dest="paths", help="filesystem to monitor (repeatable)")
    parser.add_argument("--observer-socket", help="enrolled read-only host progress socket")
    parser.add_argument('--upgrade-observer-socket', help='enrolled independent read-only update progress socket')
    args = parser.parse_args(arguments)
    if (args.upgrade_observer_socket is not None
            and ((args.socket is None and not args.systemd_socket) or not args.observer_socket)):
        parser.error('The independent upgrade observer requires the status service and Host observer.')
    bootstrap_args = (args.bootstrap_operation, args.review_sha256, args.plan_sha256, args.request_id, args.save_key_to,
                      args.activation_packet_sha256, args.activation_approval_sha256)
    worker_inputs = (args.publisher_receipt_sha256, args.worker_review_sha256, args.worker_approval_sha256)
    listener_inputs = (args.listener_worker_receipt_sha256, args.listener_loopback_port,
                       args.listener_review_sha256, args.listener_approval_sha256)
    listener_origin = (args.listener_origin_operation,args.listener_origin_receipt_sha256)
    unrelated = (*bootstrap_args, args.paths, args.observer_socket, args.upgrade_observer_socket,
                 args.installer_selection, args.host_copy_sha256)
    https_inputs = (args.https_review_sha256, args.https_approval_sha256)
    https_operation = args.review_recovery_https or args.apply_recovery_https or args.export_recovery_https_ca
    if args.recovery_https_edge or https_operation is not None:
        if any(value is not None for value in (*unrelated, *worker_inputs, *listener_inputs, *listener_origin)):
            parser.error('Recovery HTTPS requires only its selected operation inputs.')
        if args.recovery_https_edge:
            if any(value is not None for value in https_inputs):
                parser.error('The recovery HTTPS edge takes only its activated socket and credentials.')
            from .recovery_https_edge import main as edge_main
            return edge_main()
        from .bootstrap_source import hash_value
        applying = args.apply_recovery_https is not None
        if (not hash_value(https_operation)
                or (not all(hash_value(value) for value in https_inputs) if applying
                    else any(value is not None for value in https_inputs))):
            parser.error('Recovery HTTPS requires the exact operation and only the selected approval hashes.')
        action = 'apply' if applying else 'export-ca' if args.export_recovery_https_ca is not None else 'review'
        return _run_https_install(action, https_operation, *https_inputs)
    if any(value is not None for value in https_inputs):
        parser.error('Recovery HTTPS hashes require an explicit setup or rotation step.')
    listener_operation = (args.review_recovery_listener or args.apply_recovery_listener
                          or args.prepare_recovery_listener_backend or args.apply_builtin_recovery_listener)
    if args.listener_https_probe:
        if any(value is not None for value in (*unrelated, *worker_inputs, *listener_inputs, *listener_origin)):
            parser.error('The internal HTTPS probe has no inputs.')
        from .recovery_listener_install import https_child
        import json
        try:
            print(json.dumps(https_child()))
            return 0
        except (OSError, ValueError, RuntimeError, KeyError, EOFError, subprocess.SubprocessError):
            return 1
    if listener_operation is not None:
        from .bootstrap_source import hash_value
        preparing = args.prepare_recovery_listener_backend is not None
        applying = args.apply_recovery_listener is not None
        pairing = args.apply_builtin_recovery_listener is not None
        has_origin = any(value is not None for value in listener_origin)
        port = args.listener_loopback_port
        if (any(value is not None for value in (*unrelated, *worker_inputs[1:]))
                or not all(hash_value(value) for value in (listener_operation,worker_inputs[0],listener_inputs[0]))
                or port is None or not 1024 <= port <= 65535
                or (not all(hash_value(value) for value in listener_inputs[2:]) if applying or preparing or pairing
                    else any(value is not None for value in listener_inputs[2:]))
                or (preparing or pairing) and not has_origin or applying and has_origin
                or has_origin and not all(hash_value(value) for value in listener_origin)):
            parser.error('Recovery listener setup requires the exact worker, port and selected binding hashes.')
        action = ('prepare-backend' if preparing else 'apply-builtin' if pairing else 'apply' if applying else 'review')
        origin = {'builtin':listener_origin} if has_origin else {}
        return _run_listener_install(action,listener_operation,worker_inputs[0],*listener_inputs,**origin)
    if any(value is not None for value in (*listener_inputs,*listener_origin)):
        parser.error('Recovery listener options require an explicit setup step.')
    worker_operation = args.review_recovery_worker or args.apply_recovery_worker
    if worker_operation is not None:
        from .bootstrap_source import hash_value
        applying = args.apply_recovery_worker is not None
        if (any(value is not None for value in (*bootstrap_args, args.paths, args.observer_socket, args.installer_selection,
                                                args.host_copy_sha256))
                or not hash_value(worker_operation) or not hash_value(worker_inputs[0])
                or (not all(hash_value(value) for value in worker_inputs[1:]) if applying
                    else any(value is not None for value in worker_inputs[1:]))):
            parser.error('Recovery worker provisioning requires the exact publisher and selected Root approval hashes.')
        return _run_worker_provision('apply' if applying else 'review', worker_operation, *worker_inputs)
    if any(value is not None for value in worker_inputs):
        parser.error('Recovery worker hashes require a provisioning step.')
    if args.bootstrap is not None:
        from .bootstrap_source import hash_value
        host_activation = args.bootstrap in _HOST_ACTIVATION_ACTIONS
        consent_needed = host_activation and args.bootstrap != 'prepare-activation'
        consent_args = (args.activation_packet_sha256, args.activation_approval_sha256)
        if (args.paths is not None or args.observer_socket is not None or args.installer_selection is not None
                or args.host_copy_sha256 is not None
                or not all(hash_value(value) for value in (args.bootstrap_operation, args.review_sha256))
                or (args.plan_sha256 is not None) != (args.bootstrap != 'prepare-plan')
                or args.plan_sha256 is not None and not hash_value(args.plan_sha256)
                or (args.request_id is not None) != (args.bootstrap in ('stage', 'prepare-activation'))
                or args.request_id is not None and not hash_value(args.request_id)
                or (not all(hash_value(value) for value in consent_args) if consent_needed
                    else any(value is not None for value in consent_args))
                or (args.save_key_to is not None) != (args.bootstrap == 'save-key')):
            parser.error('Bootstrap requires exact operation and review hashes and only the selected step options.')
        if host_activation:
            return _run_host_activation(args.bootstrap, args.bootstrap_operation, args.review_sha256,
                args.plan_sha256, request=args.request_id, packet=args.activation_packet_sha256,
                approval=args.activation_approval_sha256)
        from .bootstrap_supervisor import run_published_bootstrap
        return run_published_bootstrap(args.bootstrap, args.bootstrap_operation, args.review_sha256,
            args.plan_sha256, request=args.request_id, destination=args.save_key_to)
    if any(value is not None for value in bootstrap_args):
        parser.error('Bootstrap options require an explicit bootstrap step.')
    if args.review_host_source is not None:
        if (args.paths is not None or args.observer_socket is not None
                or args.installer_selection is None or args.host_copy_sha256 is None):
            parser.error('Host source review requires an installer selection and copy receipt and excludes service options.')
        from .host_source_publication import review as review_host_source
        return review_host_source(args.review_host_source, args.installer_selection, args.host_copy_sha256)
    if args.installer_selection is not None or args.host_copy_sha256 is not None:
        parser.error('Installer selection and copy receipt are only accepted for Host source review.')
    if args.verify_host_source is not None:
        if args.paths is not None or args.observer_socket is not None:
            parser.error('Host source verification cannot be combined with status-service options.')
        from .host_source_publication import main as verify_host_source
        return verify_host_source(args.verify_host_source)
    if args.recovery_profile is not None:
        if args.paths or args.observer_socket:
            parser.error('Recovery configuration cannot be combined with status-service options.')
        from .recovery_cli import main as recovery_main
        return recovery_main(args.recovery_profile)
    stop = threading.Event()
    original = {}
    collector = observer = listener = server = thread = None
    try:
        collector = TelemetryCollector(tuple(args.paths) if args.paths else ("/",))
        if args.observer_socket:
            options = {'upgrade_socket': args.upgrade_observer_socket} if args.upgrade_observer_socket is not None else {}
            observer = ObserverCollector(args.observer_socket, **options)
        if args.systemd_socket:
            listener = activation_listener()
        providers = {
            API_PREFIX + "/health": lambda: {"schema": "orbis-sentinel.health.v1", "state": "ready",
                                            "version": __version__, "protocolVersion": PROTOCOL_VERSION},
            API_PREFIX + "/status": lambda: build_status(observer.component_snapshot() if observer else ComponentStatus(None, None, "unknown"),
                                                          ComponentStatus(__version__, None, "healthy")),
            API_PREFIX + "/telemetry": collector.snapshot,
            API_PREFIX + "/system-readings": collector.system_snapshot,
            API_PREFIX + "/handoff-status": observer.handoff_snapshot if observer else unavailable_handoff,
            API_PREFIX + "/progress": observer.snapshot if observer else lambda: {
                "schema": "orbis-sentinel.progress.v1", "available": False,
                "progress": None, "ageMs": None, "sourceState": "unavailable"},
        }
        server = SentinelServer(listener.getsockname() if listener else args.socket, providers, listener=listener,
            capture_provider=observer.capture_snapshot if observer else None)
        for signum in (signal.SIGTERM, signal.SIGINT):
            original[signum] = signal.signal(signum, lambda *_: stop.set())
        collector.start()
        if observer is not None:
            observer.start()
        thread = threading.Thread(target=server.serve_forever, name="orbis-sentinel-api", daemon=True)
        thread.start()
        while not stop.wait(0.25):
            if not thread.is_alive():
                raise RuntimeError("Sentinel API stopped")
            collector.maintain()
            if observer is not None:
                observer.maintain()
        return 0
    except (OSError, ValueError, RuntimeError):
        print("Orbis Sentinel could not start or continue its local service.", file=sys.stderr)
        return 1
    finally:
        if server is not None:
            if thread is not None and thread.is_alive():
                server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=3)
        if listener is not None:
            listener.close()
        if collector is not None:
            collector.close()
        if observer is not None:
            observer.close()
        for signum, handler in original.items():
            signal.signal(signum, handler)
