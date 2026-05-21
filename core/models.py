from __future__ import annotations

import dataclasses
import re
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

    @property
    def band(self) -> str:
        """Infer the WiFi band from the advertised channel."""
        try:
            channel_number = int(self.channel)
        except ValueError:
            return "unknown"
        if 1 <= channel_number <= 14:
            return "2.4GHz"
        if channel_number >= 36:
            return "5GHz"
        return "unknown"

    @property
    def security_tokens(self) -> set[str]:
        return {
            token.strip().upper()
            for token in re.split(r"[\s,/]+", self.security)
            if token.strip()
        }

    @property
    def has_wps(self) -> bool:
        return "WPS" in self.security.upper()

    @property
    def is_wps_locked(self) -> bool:
        return "WPS(LOCKED)" in self.security.upper()

    @property
    def has_wpa2(self) -> bool:
        return "WPA2" in self.security.upper()

    @property
    def has_sae(self) -> bool:
        return "SAE" in self.security_tokens

    @property
    def is_wpa3_transition(self) -> bool:
        """True when WPA2 and WPA3 are both advertised."""
        security = self.security.upper()
        return "WPA2" in security and "WPA3" in security

    @property
    def has_wpa3_only(self) -> bool:
        security = self.security.upper()
        return "WPA3" in security and "WPA2" not in security


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
    # True only when the active phase actually ran and produced an artefact or
    # conclusive negative result.  None means the phase was not attempted.
    active_phase_ran: bool = False


@dataclasses.dataclass
class DualBandResult:
    """Result of the dual-band PSK parity check."""
    sibling: WifiNetwork
    same_password: bool | None
    method: str
    note: str


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
        return self.returncode == 0 and not self.timed_out


@dataclasses.dataclass
class AssessmentResult:
    """Shared assessment state accumulated across the workflow."""
    target: WifiNetwork
    workspace: Path
    findings: list[RiskFinding] = dataclasses.field(default_factory=list)
    vectors: list[AttackVector] = dataclasses.field(default_factory=list)
    environment_notes: list[str] = dataclasses.field(default_factory=list)

    # Runtime progress and collected artefacts
    captured_files: dict[str, Path] = dataclasses.field(default_factory=dict)
    attack_log: list[str] = dataclasses.field(default_factory=list)

    # Credential outcome — only set when the active phase actually ran AND
    # succeeded.  None means either the phase did not run, or it ran but
    # found nothing; use active_phase_ran on AssessmentContext to tell which.
    cracked_password: str | None = None

    # Set to True only when the active phase ran (live or demo).
    active_phase_ran: bool = False

    # Populated when another AP with the same SSID exists on a different band.
    dual_band_result: DualBandResult | None = None

    def add_attack_step(self, step_description: str) -> None:
        self.attack_log.append(step_description)

    @property
    def is_compromised(self) -> bool:
        """
        True only when the active phase actually ran AND returned a credential.
        Avoids false positives in passive-only runs where cracked_password is
        never set but the attribute would otherwise be None == not compromised
        by accident.
        """
        return self.active_phase_ran and self.cracked_password is not None

# Import ThirdPartyResult lazily to avoid circular dependency
# ThirdPartyResult is defined in core.third_party
