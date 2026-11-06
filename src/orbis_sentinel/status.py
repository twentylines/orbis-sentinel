"""Pure, deterministic component status serialization."""

from dataclasses import dataclass
import re

from .contracts import PROTOCOL_VERSION

_STATES = frozenset({"unknown", "healthy", "unavailable", "updating", "recovering"})
_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z", re.ASCII)
_MAX_VERSION_LENGTH = 128


@dataclass(frozen=True)
class ComponentStatus:
    """An explicitly observed component state and its known versions."""

    installed_version: str | None
    available_version: str | None
    state: str

    def __post_init__(self) -> None:
        for name, version in (("installed_version", self.installed_version), ("available_version", self.available_version)):
            if version is not None:
                if type(version) is not str:
                    raise TypeError(f"{name} must be a string or None")
                if len(version) > _MAX_VERSION_LENGTH or not _VERSION.fullmatch(version):
                    raise ValueError(f"{name} must be a valid version string of at most {_MAX_VERSION_LENGTH} characters")
        if type(self.state) is not str:
            raise TypeError("state must be a string")
        if self.state not in _STATES:
            raise ValueError("state must be one of: " + ", ".join(sorted(_STATES)))


def build_status(orbis: ComponentStatus, sentinel: ComponentStatus) -> dict:
    """Serialize observations without inferring health or update decisions."""
    if not isinstance(orbis, ComponentStatus) or not isinstance(sentinel, ComponentStatus):
        raise TypeError("orbis and sentinel must be ComponentStatus instances")

    def serialize(component: ComponentStatus) -> dict:
        return {
            "installedVersion": component.installed_version,
            "availableVersion": component.available_version,
            "state": component.state,
        }

    return {
        "schema": "orbis-sentinel.status.v1",
        "protocolVersion": PROTOCOL_VERSION,
        "components": {"orbis": serialize(orbis), "sentinel": serialize(sentinel)},
    }
