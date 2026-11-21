"""Recovery listener owned by the separately admitted root supervisor."""

from contextlib import ExitStack
import os
import sys
import threading

from .recovery_gateway import RecoveryApplication, RecoveryHTTPServer
from .recovery_profiles import RecoveryProfiles
from .recovery_sessions import RecoverySessions
from .recovery_worker import RecoveryWorker
from .recovery_control import RecoveryControl, RecoveryControlServer
from .recovery_incarnations import RecoveryIncarnations
from .recovery_main_passkeys import RecoveryMainPasskeys
from .recovery_bootstrap import RecoveryBootstrap
from .bootstrap_control import RootBootstrapControl, RootBootstrapControlServer
from .controller_return_readiness import ControllerReturnGateway


def _require_root():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise RuntimeError('The recovery listener requires the Linux root supervisor.')


def run_recovery(*, directory, image_id, origin, address, status, stop, ready=None, check=None, control=False,
                 setup=None, installed_listener=False, backend=None, progress=None, handoff_status=None):
    """Serve an enrolled realm with fixed controller return in installed mode.

    The supervisor supplies admitted storage, an independently retained immutable
    worker image, a TLS proxy realm and observed status. Startup never enrolls an
    operator or recovery key. Shutdown drains requests before releasing profiles,
    workers or the store lock, including when a readiness callback fails.
    """
    _require_root()
    if (not isinstance(stop, threading.Event) or not callable(status)
            or progress is not None and not callable(progress)
            or handoff_status is not None and not callable(handoff_status)
            or (ready is not None and not callable(ready)) or (check is not None and not callable(check))
            or type(control) is not bool or type(installed_listener) is not bool
            or setup is not None and not control
            or backend is not (setup.backend if setup is not None else None)
            or backend is not None and not installed_listener):
        raise ValueError('Recovery requires explicit supervisor dependencies.')
    if check is not None:
        check()
    if backend is not None:
        from .recovery_backend_tls import ListenerPeer
        if type(backend) is not ListenerPeer:
            raise ValueError('Recovery requires its exact private listener credentials.')
        backend.verify()
    with ExitStack() as resources:
        sessions = RecoverySessions(directory, setup=setup)
        resources.callback(sessions.close)
        worker = RecoveryWorker(sessions, image_id=image_id)
        resources.callback(worker.close)
        profiles = RecoveryProfiles(sessions, inspect=worker.inspect, verify=worker.verify, verify_counter=worker.verify_counter)
        resources.callback(profiles.close)
        controller_return = None
        if control and installed_listener and backend is not None and handoff_status is not None:
            controller_return = ControllerReturnGateway(
                sessions, origin=origin, setup=setup, invocation_id=os.environ.get('INVOCATION_ID'),
                handoff_status=handoff_status)
        application = RecoveryApplication(origin=origin, sessions=sessions, verify=profiles.verify, status=status,
                                          check=check, binding_observer=setup.observe if setup is not None else None,
                                          progress=progress, handoff_status=handoff_status, controller_return=controller_return)
        transport = {'backend':backend} if backend is not None else {}
        server = RecoveryHTTPServer(address,application,**transport)
        resources.callback(server.server_close)
        controller = None
        bootstrap_controller = None
        if control:
            incarnations = RecoveryIncarnations(sessions, profiles, inspect=worker.inspect_content, origin=origin,
                                                inspect_effective=worker.inspect_effective_content)
            main_passkeys = RecoveryMainPasskeys(sessions, profiles, origin=origin)
            controller = RecoveryControlServer(os.path.join(directory, 'control.sock'),
                RecoveryControl(sessions=sessions, profiles=profiles, origin=origin, check=check,
                                incarnations=incarnations, main_passkeys=main_passkeys, capability=worker.capability))
            resources.callback(controller.close)
            bootstrap = RecoveryBootstrap(sessions, profiles, incarnations, origin=origin,
                                          require_held_setup=installed_listener)
            bootstrap_controller = RootBootstrapControlServer(os.path.join(directory, 'bootstrap-control.sock'),
                RootBootstrapControl(bootstrap, check=check, controller_return=controller_return))
            resources.callback(bootstrap_controller.close)
        failures = []

        def serve(listener):
            try:
                if listener is server:
                    listener.serve_forever(poll_interval=0.1)
                else:
                    listener.serve_forever()
            except BaseException as error:
                failures.append(error)

        threads = []
        try:
            for listener, name in ((server, 'orbis-sentinel-recovery'), (controller, 'orbis-sentinel-recovery-control'),
                                   (bootstrap_controller, 'orbis-sentinel-root-bootstrap-control')):
                if listener is not None:
                    thread = threading.Thread(target=serve, args=(listener,), name=name, daemon=False)
                    thread.start()
                    threads.append(thread)
            if ready is not None:
                ready(server.server_address)
            while not stop.wait(0.1):
                if check is not None:
                    check()
                if any(not thread.is_alive() for thread in threads):
                    raise RuntimeError('The recovery listener stopped unexpectedly.')
            if failures:
                raise RuntimeError('The recovery listener stopped unexpectedly.') from failures[0]
        finally:
            if bootstrap_controller is not None:
                bootstrap_controller.shutdown()
            if controller is not None:
                controller.shutdown()
            if threads:
                server.shutdown()
            for thread in threads:
                thread.join()
