from __future__ import annotations

from typing import Iterable

from core.models import AttackVector, RiskFinding, WifiNetwork


_SSID_PATTERNS = [
    ("MOVISTAR", "Default ISP naming pattern may indicate unchanged router setup."),
    ("VODAFONE", "Default ISP naming pattern may indicate unchanged router setup."),
    ("ORANGE", "Default ISP naming pattern may indicate unchanged router setup."),
    ("JAZZTEL", "Default ISP naming pattern may indicate unchanged router setup."),
    ("LIVEBOX", "Vendor naming pattern may indicate stock configuration."),
    ("TP-LINK", "Vendor naming pattern may indicate stock configuration."),
    ("TPLINK", "Vendor naming pattern may indicate stock configuration."),
    ("NETGEAR", "Vendor naming pattern may indicate stock configuration."),
]


def ssid_pattern_note(ssid: str) -> str | None:
    upper_ssid = ssid.upper()
    for pattern, note in _SSID_PATTERNS:
        if pattern in upper_ssid:
            return note
    return None


def analyze_network(network: WifiNetwork) -> tuple[list[RiskFinding], list[AttackVector]]:
    security = network.security.upper()
    findings: list[RiskFinding] = []
    vectors: list[AttackVector] = []

    if "OPEN" in security or security == "--":
        findings.append(
            RiskFinding(
                severity="Critical",
                title="Open network detected",
                evidence=f"{network.display_name} advertises no link-layer encryption.",
                recommendation="Use WPA3-Personal or WPA2-Personal with a strong passphrase.",
            )
        )
        vectors.append(
            AttackVector(
                name="Passive traffic observation",
                feasible=True,
                difficulty="Low",
                description="Open networks expose traffic metadata and any unprotected plaintext services without link-layer authentication.",
                tools=("Wireshark", "tcpdump"),
            )
        )

    if "WEP" in security:
        findings.append(
            RiskFinding(
                severity="Critical",
                title="Deprecated WEP encryption",
                evidence=f"Security field: {network.security}",
                recommendation="Replace WEP with WPA3-Personal. WPA2-Personal is the minimum acceptable fallback.",
                references=("Legacy WEP deployment",),
            )
        )
        vectors.append(
            AttackVector(
                name="Legacy WEP exposure",
                feasible=True,
                difficulty="Low",
                description="WEP is deprecated and should be treated as broken for modern security expectations.",
                tools=("aircrack-ng",),
            )
        )

    if "WPS" in security:
        findings.append(
            RiskFinding(
                severity="High",
                title="WPS is advertised",
                evidence=f"Security field: {network.security}",
                recommendation="Disable WPS. Prefer manual onboarding or a managed provisioning workflow.",
                references=("WPS operational risk",),
            )
        )
        vectors.append(
            AttackVector(
                name="WPS exposure",
                feasible=True,
                difficulty="Low",
                description="WPS increases attack surface and should be disabled unless there is a strict operational need.",
                tools=("wash", "reaver"),
            )
        )

    if network.is_wpa3_transition:
        findings.append(
            RiskFinding(
                severity="Low",
                title="WPA3 transition mode advertised",
                evidence=f"Security field: {network.security}",
                recommendation=(
                    "Use WPA3-only mode when client compatibility allows it. "
                    "Transition mode keeps WPA2-Personal available for legacy clients."
                ),
            )
        )
        vectors.append(
            AttackVector(
                name="WPA2 transition compatibility exposure",
                feasible=False,
                difficulty="Medium",
                description=(
                    "WPA3 transition mode improves compatibility but still allows WPA2-Personal "
                    "associations, so password strength and legacy client hygiene remain relevant."
                ),
                tools=("hashcat", "aircrack-ng"),
            )
        )

    if "WPA3" not in security and ("WPA" in security or "WPA2" in security):
        findings.append(
            RiskFinding(
                severity="Medium",
                title="WPA3 is not advertised",
                evidence=f"Security field: {network.security}",
                recommendation="Enable WPA3-Personal transition mode if client compatibility requires WPA2.",
            )
        )
        vectors.extend(
            [
                AttackVector(
                    name="Offline credential material risk",
                    feasible=False,
                    difficulty="Medium",
                    description="WPA2-Personal networks rely heavily on password strength and can expose recoverable authentication material in poorly managed environments.",
                    tools=("hashcat",),
                ),
                AttackVector(
                    name="Client-driven authentication exposure",
                    feasible=False,
                    difficulty="Medium",
                    description="When legacy authentication remains in use, weak passphrases and poor client hygiene become the dominant risk factors.",
                    tools=("aircrack-ng",),
                ),
            ]
        )

    if network.is_hidden:
        findings.append(
            RiskFinding(
                severity="Low",
                title="Hidden SSID",
                evidence="The network does not broadcast a human-readable SSID.",
                recommendation="Do not rely on SSID hiding as a security control; use strong encryption instead.",
            )
        )
        vectors.append(
            AttackVector(
                name="SSID disclosure by client behavior",
                feasible=False,
                difficulty="Low",
                description="Hidden SSIDs are routinely revealed by normal client association behavior and should not be treated as a security control.",
                tools=("Kismet",),
            )
        )

    pattern_note = ssid_pattern_note(network.ssid)
    if pattern_note:
        findings.append(
            RiskFinding(
                severity="Medium",
                title="Default or vendor-style SSID naming",
                evidence=pattern_note,
                recommendation="Rename the SSID and review whether the router is still using stock configuration defaults.",
            )
        )

    if network.signal >= 75:
        findings.append(
            RiskFinding(
                severity="Informational",
                title="Strong external signal",
                evidence=f"Observed signal strength is {network.signal}%.",
                recommendation="Review transmit power and physical placement if the lab signal reaches unintended areas.",
            )
        )

    if not findings:
        findings.append(
            RiskFinding(
                severity="Informational",
                title="No obvious beacon-level issues",
                evidence=f"Security field: {network.security}",
                recommendation="Continue with authorized configuration review, firmware checks, and password policy validation.",
            )
        )

    findings.sort(key=lambda finding: finding.order)
    return findings, vectors


def severity_score(findings: Iterable[RiskFinding]) -> int:
    weights = {
        "Critical": 35,
        "High": 25,
        "Medium": 15,
        "Low": 5,
        "Informational": 0,
    }
    return min(100, sum(weights.get(finding.severity, 0) for finding in findings))


def classify_risk(score: int) -> str:
    if score >= 60:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"
