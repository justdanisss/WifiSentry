from __future__ import annotations

import dataclasses
import logging

from payloads.models import WifiNetwork

log = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class SsidProfile:
    """Documentary profile inferred from the network name."""

    name: str
    prefixes: tuple[str, ...]
    vendor: str
    notes: tuple[str, ...]
    recommendations: tuple[str, ...]
    priority: int = 100
    match_mode: str = "startswith"


@dataclasses.dataclass(frozen=True)
class StrategyPlan:
    """Documentary review plan derived from a detected profile."""

    name: str
    kind: str
    description: str
    priority: int
    source_profile: str
    notes: tuple[str, ...] = ()


SSID_PROFILES: tuple[SsidProfile, ...] = (
    SsidProfile(
        name="Digi Fibra",
        prefixes=("DIGIFIBRA",),
        vendor="Digi",
        notes=(
            "ISP naming pattern detected.",
            "Review whether the router still uses stock onboarding defaults.",
        ),
        recommendations=(
            "Confirm the passphrase was changed during provisioning.",
            "Review firmware revision and remote management settings.",
            "Check whether WPS is disabled.",
        ),
        priority=10,
        match_mode="startswith",
    ),
    SsidProfile(
        name="Movistar",
        prefixes=("MOVISTAR_", "MOVISTAR_PLUS_", "JAZZTEL_"),
        vendor="Telefonica / Jazztel",
        notes=(
            "Common ISP naming pattern detected.",
            "This may indicate stock router setup or default provisioning flow.",
        ),
        recommendations=(
            "Verify SSID customization policy.",
            "Confirm WPA mode and password rotation policy.",
            "Review whether guest network isolation is enabled.",
        ),
        priority=20,
        match_mode="startswith",
    ),
    SsidProfile(
        name="Orange / Jazztel Fibra",
        prefixes=("MIFIBRA-", "LIVEBOX"),
        vendor="Orange",
        notes=(
            "Vendor-style naming pattern detected.",
            "Provisioning defaults should be compared against current configuration.",
        ),
        recommendations=(
            "Check firmware update status.",
            "Review admin panel password and remote access exposure.",
        ),
        priority=30,
        match_mode="startswith",
    ),
    SsidProfile(
        name="Vodafone",
        prefixes=("VODAFONE",),
        vendor="Vodafone",
        notes=(
            "ISP naming pattern detected.",
            "Review whether the access point is still on default naming conventions.",
        ),
        recommendations=(
            "Confirm WPA3 availability and current transition mode.",
            "Check whether WPS and UPnP are disabled when not required.",
        ),
        priority=40,
        match_mode="startswith",
    ),
    SsidProfile(
        name="Generic Vendor Pattern",
        prefixes=("TP-LINK", "TPLINK", "NETGEAR", "DLINK", "LINKSYS", "WLAN", "WIFI", "DEFAULT"),
        vendor="Generic vendor",
        notes=(
            "Generic vendor naming pattern detected.",
            "Device may still reflect stock branding or default setup choices.",
        ),
        recommendations=(
            "Rename SSID to a neutral identifier.",
            "Review baseline hardening checklist for consumer routers.",
        ),
        priority=50,
        match_mode="contains",
    ),
)


def profile_matches_ssid(profile: SsidProfile, normalized_ssid: str) -> bool:
    if profile.match_mode == "contains":
        return any(prefix in normalized_ssid for prefix in profile.prefixes)
    return any(normalized_ssid.startswith(prefix) for prefix in profile.prefixes)


def detect_ssid_profiles(ssid: str) -> list[SsidProfile]:
    """Return every documentary profile compatible with the SSID."""
    normalized = ssid.strip().upper()
    if not normalized:
        return []

    matches = [
        profile
        for profile in SSID_PROFILES
        if profile_matches_ssid(profile, normalized)
    ]
    matches.sort(key=lambda item: item.priority)
    for profile in matches:
        log.info("SSID profile detected: %s", profile.name)
    return matches


def detect_ssid_profile(ssid: str) -> SsidProfile | None:
    """Compatibility helper returning the first matching profile."""
    matches = detect_ssid_profiles(ssid)
    return matches[0] if matches else None


def serialize_profile(profile: SsidProfile) -> dict[str, object]:
    return {
        "name": profile.name,
        "vendor": profile.vendor,
        "prefixes": list(profile.prefixes),
        "notes": list(profile.notes),
        "recommendations": list(profile.recommendations),
        "priority": profile.priority,
        "match_mode": profile.match_mode,
    }


def serialize_plan(plan: StrategyPlan) -> dict[str, object]:
    return {
        "name": plan.name,
        "kind": plan.kind,
        "description": plan.description,
        "priority": plan.priority,
        "source_profile": plan.source_profile,
        "notes": list(plan.notes),
    }


def build_review_plan(target: WifiNetwork) -> list[StrategyPlan]:
    """Build a defensive/documentary review plan from the SSID profile."""
    profiles = detect_ssid_profiles(target.ssid)
    plans: list[StrategyPlan] = []

    if not profiles:
        plans.append(
            StrategyPlan(
                name="Generic Baseline Review",
                kind="baseline",
                description="Run the standard router hardening and configuration review checklist.",
                priority=100,
                source_profile="Generic",
                notes=(
                    "No vendor-specific SSID profile detected.",
                    "Prioritize encryption mode, firmware, password policy, and WPS settings.",
                ),
            )
        )
        return plans

    for profile in profiles:
        plans.append(
            StrategyPlan(
                name=f"{profile.name} Configuration Review",
                kind="profile-review",
                description=f"Review configuration assumptions associated with the detected {profile.vendor} naming profile.",
                priority=profile.priority,
                source_profile=profile.name,
                notes=profile.notes,
            )
        )

        for index, recommendation in enumerate(profile.recommendations, start=1):
            plans.append(
                StrategyPlan(
                    name=f"{profile.name} Check {index}",
                    kind="targeted-check",
                    description=recommendation,
                    priority=profile.priority + index,
                    source_profile=profile.name,
                )
            )

    plans.append(
        StrategyPlan(
            name="Generic Baseline Review",
            kind="baseline",
            description="Run the standard router hardening and configuration review checklist after profile-specific checks.",
            priority=(profiles[0].priority if profiles else 100) + 20,
            source_profile=profiles[0].name if profiles else "Generic",
        )
    )

    deduped: list[StrategyPlan] = []
    seen = set()
    for plan in sorted(plans, key=lambda item: item.priority):
        fingerprint = (plan.kind, plan.description, plan.source_profile)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(plan)

    return deduped
