"""Read-only local service entry point; privileged operations are separate."""

import argparse
import os
import signal
import socket
import sys
import threading

from . import __version__
from .collector import TelemetryCollector
from .contracts import API_PREFIX, PROTOCOL_VERSION
from .server import SentinelServer
from .status import ComponentStatus, build_status
from .observer import ObserverCollector


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


def main(argv=None):
    parser = argparse.ArgumentParser(description="Orbis Sentinel local status service")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--socket", help="new socket in an existing private runtime directory")
    source.add_argument("--systemd-socket", action="store_true", help="use the systemd API socket")
    parser.add_argument("--disk-path", action="append", dest="paths", help="filesystem to monitor (repeatable)")
    parser.add_argument("--observer-socket", help="enrolled read-only host progress socket")
    args = parser.parse_args(argv)
    stop = threading.Event()
    original = {}
    collector = observer = listener = server = thread = None
    try:
        collector = TelemetryCollector(tuple(args.paths) if args.paths else ("/",))
        if args.observer_socket:
            observer = ObserverCollector(args.observer_socket)
        if args.systemd_socket:
            listener = activation_listener()
        providers = {
            API_PREFIX + "/health": lambda: {"schema": "orbis-sentinel.health.v1", "state": "ready",
                                            "version": __version__, "protocolVersion": PROTOCOL_VERSION},
            API_PREFIX + "/status": lambda: build_status(ComponentStatus(None, None, "unknown"),
                                                          ComponentStatus(__version__, None, "healthy")),
            API_PREFIX + "/telemetry": collector.snapshot,
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
