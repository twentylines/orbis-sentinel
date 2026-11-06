"""Shared lifecycle vocabulary; authority and execution stay in the supervisor."""

from enum import Enum

PROTOCOL_VERSION = 1
API_PREFIX = "/sentinel/api/v1"
APPLICATIONS = frozenset({"orbis", "sentinel"})
OPERATIONS = frozenset({"update", "restart", "repair", "restore_previous", "reinstall", "backup", "restore", "diagnostics"})


class Phase(str, Enum):
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    VERIFYING = "verifying"
    STOPPING = "stopping"
    INSTALLING = "installing"
    MIGRATING = "migrating"
    STARTING = "starting"
    HEALTH_CHECK = "health_check"
    ROLLING_BACK = "rolling_back"
    SUCCEEDED = "succeeded"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    RECOVERY_REQUIRED = "recovery_required"
    CANCELLED = "cancelled"


TERMINAL_PHASES = frozenset({Phase.SUCCEEDED, Phase.ROLLED_BACK, Phase.FAILED, Phase.CANCELLED})
TRANSITIONS = {
    Phase.QUEUED: frozenset({Phase.PREPARING, Phase.CANCELLED}),
    Phase.PREPARING: frozenset({Phase.RUNNING, Phase.VERIFYING, Phase.FAILED, Phase.CANCELLED}),
    Phase.RUNNING: frozenset({Phase.VERIFYING, Phase.STOPPING, Phase.HEALTH_CHECK, Phase.SUCCEEDED, Phase.FAILED, Phase.RECOVERY_REQUIRED, Phase.ROLLING_BACK}),
    Phase.VERIFYING: frozenset({Phase.RUNNING, Phase.STOPPING, Phase.FAILED, Phase.RECOVERY_REQUIRED}),
    Phase.STOPPING: frozenset({Phase.INSTALLING, Phase.STARTING, Phase.FAILED, Phase.RECOVERY_REQUIRED, Phase.ROLLING_BACK}),
    Phase.INSTALLING: frozenset({Phase.MIGRATING, Phase.STARTING, Phase.FAILED, Phase.RECOVERY_REQUIRED, Phase.ROLLING_BACK}),
    Phase.MIGRATING: frozenset({Phase.STARTING, Phase.FAILED, Phase.RECOVERY_REQUIRED, Phase.ROLLING_BACK}),
    Phase.STARTING: frozenset({Phase.HEALTH_CHECK, Phase.ROLLING_BACK, Phase.FAILED, Phase.RECOVERY_REQUIRED}),
    Phase.HEALTH_CHECK: frozenset({Phase.SUCCEEDED, Phase.ROLLED_BACK, Phase.ROLLING_BACK, Phase.FAILED, Phase.RECOVERY_REQUIRED}),
    Phase.ROLLING_BACK: frozenset({Phase.STARTING, Phase.ROLLED_BACK, Phase.RECOVERY_REQUIRED}),
    Phase.RECOVERY_REQUIRED: frozenset({Phase.ROLLING_BACK}),
}
