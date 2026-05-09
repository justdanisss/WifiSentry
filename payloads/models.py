from __future__ import annotations

import dataclasses
from pathlib import Path


@dataclasses.dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    bssid: str
    channel: str
    signal: int
    security: str

    @property
    def display_name(self) -> str:
        return self.ssid or "<hidden>"

    @property
    def is_hidden(self) -> bool:
        return not self.ssid.strip()


@dataclasses.dataclass(frozen=True)
class RiskFinding:
    severity: str
    title: str
    evidence: str
    recommendation: str
    references: tuple[str, ...] = ()

    _SEVERITY_ORDER = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
        "Informational": 4,
    }

    @property
    def order(self) -> int:
        return self._SEVERITY_ORDER.get(self.severity, 99)


@dataclasses.dataclass(frozen=True)
class AttackVector:
    name: str
    feasible: bool
    difficulty: str
    description: str
    tools: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class AssessmentContext:
    interface: str | None
    mode: str
    target_source: str
    assume_yes: bool
    offensive_requests: tuple[str, ...]


# --- ACTIVE WORKFLOW MODELS ---

@dataclasses.dataclass
class ToolResult:
    """Encapsulates the result of executing a system tool."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def success(self) -> bool:
        """A run is considered successful when it exits cleanly and does not time out."""
        return self.returncode == 0 and not self.timed_out


@dataclasses.dataclass
class AssessmentResult:
    """Shared assessment state accumulated across the workflow."""
    target: WifiNetwork
    workspace: Path
    findings: list[RiskFinding] = dataclasses.field(default_factory=list)
    vectors: list[AttackVector] = dataclasses.field(default_factory=list)
    environment_notes: list[str] = dataclasses.field(default_factory=list)
    
    # Runtime progress and collected artifacts
    captured_files: dict[str, Path] = dataclasses.field(default_factory=dict)
    attack_log: list[str] = dataclasses.field(default_factory=list)

    # Final credential outcome when available
    cracked_password: str | None = None

    def add_attack_step(self, step_description: str) -> None:
        """Append a step to the execution log for later reporting."""
        self.attack_log.append(step_description)

    @property
    def is_compromised(self) -> bool:
        """Return whether the target has been compromised."""
        return self.cracked_password is not None
