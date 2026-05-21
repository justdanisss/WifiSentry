from __future__ import annotations

import dataclasses
import re
from typing import Iterable

from core.models import WifiNetwork


@dataclasses.dataclass(frozen=True)
class TechniquePlan:
    slug: str
    name: str
    description: str
    probability: int
    cost: int
    noise: int
    impact: int
    score: int
    threshold: int
    evidence: tuple[str, ...]
    should_attempt: bool


def _normalize_score(value: int) -> int:
    return max(0, min(100, value))


def _parse_security_tokens(network: WifiNetwork) -> set[str]:
    return {
        token.strip().upper()
        for token in re.split(r"[\s,/]+", network.security)
        if token.strip()
    }


def _infer_vendor_hint(network: WifiNetwork) -> str | None:
    normalized_ssid = network.ssid.strip().upper()
    vendors = {
        "MOVISTAR": "Telefonica",
        "VODAFONE": "Vodafone",
        "ORANGE": "Orange",
        "JAZZTEL": "Telefonica",
        "LIVEBOX": "Orange",
        "DIFI": "Digi",
        "TP-LINK": "TP-Link",
        "TPLINK": "TP-Link",
        "NETGEAR": "Netgear",
        "DLINK": "D-Link",
        "LINKSYS": "Linksys",
        "ASUS": "ASUS",
        "HUAWEI": "Huawei",
        "ZTE": "ZTE",
        "XIAOMI": "Xiaomi",
    }
    for prefix, vendor in vendors.items():
        if normalized_ssid.startswith(prefix):
            return vendor
    return None


@dataclasses.dataclass(frozen=True)
class OffensiveFingerprint:
    vendor_hint: str | None
    normalized_ssid: str
    has_wps: bool
    has_wps_locked: bool
    has_wpa2: bool
    has_wpa3: bool
    has_sae: bool
    is_transition: bool
    is_open: bool
    band: str
    signal: int


def _build_fingerprint(network: WifiNetwork) -> OffensiveFingerprint:
    security = network.security.upper()
    tokens = _parse_security_tokens(network)
    return OffensiveFingerprint(
        vendor_hint=_infer_vendor_hint(network),
        normalized_ssid=network.ssid.strip().upper(),
        has_wps="WPS" in security,
        has_wps_locked="WPS(LOCKED)" in security,
        has_wpa2="WPA2" in security,
        has_wpa3="WPA3" in security,
        has_sae="SAE" in tokens,
        is_transition=network.is_wpa3_transition,
        is_open="OPEN" in security or security.strip() == "--",
        band=network.band,
        signal=network.signal,
    )


def _make_candidate(
    slug: str,
    name: str,
    description: str,
    probability: int,
    cost: int,
    noise: int,
    impact: int,
    threshold: int,
    evidence: Iterable[str],
    should_attempt: bool,
) -> TechniquePlan:
    score = _normalize_score(probability + impact - cost - noise)
    return TechniquePlan(
        slug=slug,
        name=name,
        description=description,
        probability=_normalize_score(probability),
        cost=_normalize_score(cost),
        noise=_normalize_score(noise),
        impact=_normalize_score(impact),
        score=score,
        threshold=threshold,
        evidence=tuple(evidence),
        should_attempt=should_attempt,
    )


def _evaluate_wps(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if not fingerprint.has_wps:
        return _make_candidate(
            slug="wps",
            name="WPS Pixie Dust",
            description="WPS attack path using visible or hidden WPS metadata.",
            probability=0,
            cost=40,
            noise=20,
            impact=45,
            threshold=45,
            evidence=("No WPS metadata advertised.",),
            should_attempt=False,
        )

    probability = 75
    evidence = ["WPS advertised in beacon metadata."]
    if fingerprint.has_wps_locked:
        probability = 45
        evidence.append("WPS appears locked; exploitation probability is lower.")
    if fingerprint.vendor_hint:
        evidence.append(f"Vendor hint suggests consumer router family: {fingerprint.vendor_hint}.")
    if fingerprint.signal >= 70:
        evidence.append("Strong signal makes the WPS probe path more reliable.")
        probability += 5

    return _make_candidate(
        slug="wps",
        name="WPS Pixie Dust",
        description="WPS attack path using visible or hidden WPS metadata.",
        probability=probability,
        cost=35,
        noise=20,
        impact=50,
        threshold=45,
        evidence=evidence,
        should_attempt=probability >= 45,
    )


def _evaluate_pmkid(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if fingerprint.is_open:
        return _make_candidate(
            slug="pmkid",
            name="PMKID capture",
            description="Passive PMKID capture from WPA2/transition networks.",
            probability=0,
            cost=15,
            noise=10,
            impact=40,
            threshold=40,
            evidence=("Target is not encrypted or is open.",),
            should_attempt=False,
        )

    if not fingerprint.has_wpa2 and not fingerprint.is_transition:
        return _make_candidate(
            slug="pmkid",
            name="PMKID capture",
            description="Passive PMKID capture from WPA2/transition networks.",
            probability=20,
            cost=25,
            noise=10,
            impact=35,
            threshold=35,
            evidence=("WPA2 is not clearly advertised.",),
            should_attempt=False,
        )

    probability = 60
    evidence = ["Target advertises WPA2 / transition mode."]
    if fingerprint.is_transition:
        probability -= 10
        evidence.append("WPA3 transition mode is present, reducing the pure WPA2 surface.")
    if fingerprint.vendor_hint:
        evidence.append(f"Vendor hint: {fingerprint.vendor_hint}.")
    if fingerprint.signal >= 70:
        probability += 5
    return _make_candidate(
        slug="pmkid",
        name="PMKID capture",
        description="Passive PMKID capture from WPA2/transition networks.",
        probability=probability,
        cost=30,
        noise=15,
        impact=45,
        threshold=40,
        evidence=evidence,
        should_attempt=probability >= 40,
    )


def _evaluate_eapol(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if fingerprint.is_open:
        return _make_candidate(
            slug="eapol",
            name="EAPOL capture",
            description="Active EAPOL capture and deauthentication path.",
            probability=0,
            cost=55,
            noise=60,
            impact=55,
            threshold=50,
            evidence=("Target is open and does not require EAPOL capture.",),
            should_attempt=False,
        )

    probability = 55 if fingerprint.has_wpa2 else 35
    evidence = ["Target advertises WPA authentication."]
    if fingerprint.is_transition:
        probability -= 10
        evidence.append("WPA3 transition mode may reduce the effective WPA2 attack surface.")
    if fingerprint.has_wps:
        probability -= 10
        evidence.append("Visible WPS suggests a more specific path may exist.")
    if fingerprint.signal >= 70:
        probability += 5
    return _make_candidate(
        slug="eapol",
        name="EAPOL capture",
        description="Active EAPOL capture and deauthentication path.",
        probability=probability,
        cost=50,
        noise=55,
        impact=55,
        threshold=35,
        evidence=evidence,
        should_attempt=probability >= 35,
    )


def _evaluate_wpa3_assessment(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if not fingerprint.has_wpa3:
        return _make_candidate(
            slug="wpa3",
            name="WPA3 assessment",
            description="Assess WPA3/Dragonblood-related configuration risks.",
            probability=15,
            cost=20,
            noise=10,
            impact=25,
            threshold=30,
            evidence=("WPA3 is not advertised.",),
            should_attempt=False,
        )

    probability = 50
    evidence = ["Target advertises WPA3 or transition mode."]
    if fingerprint.is_transition:
        probability += 10
        evidence.append("Transition mode indicates compatibility with legacy WPA2 clients.")
    if fingerprint.has_sae:
        probability += 5
        evidence.append("SAE is present in the advertised security set.")
    return _make_candidate(
        slug="wpa3",
        name="WPA3 assessment",
        description="Assess WPA3/Dragonblood-related configuration risks.",
        probability=probability,
        cost=25,
        noise=10,
        impact=35,
        threshold=30,
        evidence=evidence,
        should_attempt=probability >= 30,
    )


def _evaluate_fragattacks(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if fingerprint.has_wpa3:
        return _make_candidate(
            slug="fragattacks",
            name="FragAttacks suspicion",
            description="Signal whether the device may be susceptible to fragmentation/aggregation flaws.",
            probability=20,
            cost=20,
            noise=15,
            impact=25,
            threshold=30,
            evidence=("WPA3 is present, making legacy FragAttacks paths less likely.",),
            should_attempt=False,
        )

    probability = 35 if fingerprint.band in ("2.4GHz", "5GHz") else 20
    evidence = [f"Target is on {fingerprint.band}, which is relevant for fragmentation/aggregation issues."]
    if fingerprint.vendor_hint:
        evidence.append(f"Vendor hint suggests consumer device family: {fingerprint.vendor_hint}.")
    return _make_candidate(
        slug="fragattacks",
        name="FragAttacks suspicion",
        description="Signal whether fragmentation-related weaknesses merit deeper review.",
        probability=probability,
        cost=20,
        noise=15,
        impact=30,
        threshold=30,
        evidence=evidence,
        should_attempt=probability >= 30,
    )


def _evaluate_kr00k(fingerprint: OffensiveFingerprint) -> TechniquePlan:
    if not fingerprint.has_wpa2:
        return _make_candidate(
            slug="kr00k",
            name="Kr00k suspicion",
            description="Signal whether known vendor-family WPA2 implementation flaws may apply.",
            probability=15,
            cost=10,
            noise=10,
            impact=20,
            threshold=25,
            evidence=("WPA2 is not clearly present.",),
            should_attempt=False,
        )

    probability = 30
    evidence = ["Target advertises WPA2, which is the relevant protocol family for Kr00k-like flaws."]
    if fingerprint.vendor_hint:
        evidence.append(f"Vendor hint: {fingerprint.vendor_hint}.")
        probability += 10
    if fingerprint.signal >= 70:
        probability += 5
    return _make_candidate(
        slug="kr00k",
        name="Kr00k suspicion",
        description="Signal whether known WPA2 implementation families may be vulnerable.",
        probability=probability,
        cost=10,
        noise=10,
        impact=30,
        threshold=30,
        evidence=evidence,
        should_attempt=probability >= 30,
    )


def plan_offensive_techniques(network: WifiNetwork) -> list[TechniquePlan]:
    fingerprint = _build_fingerprint(network)
    candidates = [
        _evaluate_wps(fingerprint),
        _evaluate_pmkid(fingerprint),
        _evaluate_eapol(fingerprint),
        _evaluate_wpa3_assessment(fingerprint),
        _evaluate_fragattacks(fingerprint),
        _evaluate_kr00k(fingerprint),
    ]
    return sorted(candidates, key=lambda item: item.score, reverse=True)


def serialize_technique_plan(plan: TechniquePlan) -> dict[str, object]:
    return {
        "slug": plan.slug,
        "name": plan.name,
        "description": plan.description,
        "probability": plan.probability,
        "cost": plan.cost,
        "noise": plan.noise,
        "impact": plan.impact,
        "score": plan.score,
        "threshold": plan.threshold,
        "should_attempt": plan.should_attempt,
        "evidence": list(plan.evidence),
    }
