from __future__ import annotations

"""
demo.py — Simulated active workflow for presentations and walkthroughs.

Mirrors the real attack pipeline structure step by step, using realistic
timings and log messages, without touching any hardware or external tools.
"""

import logging
import time
from pathlib import Path

from core.config import DEMO_CRACKED_PASSWORD, DEMO_TIMINGS
from core.models import AssessmentResult
from core.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)


def _step(message: str, duration: float) -> None:
    log.info(message)
    time.sleep(duration)


def run_demo_active_phase(
    assessment: AssessmentResult,
    workspace_manager: WorkspaceManager,
) -> None:
    """
    Simulate the full active pipeline and populate the AssessmentResult in the
    same way the live phase would.  Called by cli.py when --demo is active.
    """
    target = assessment.target
    security = target.security.upper()

    log.info("=" * 50)
    log.info("[DEMO] Starting simulated active pipeline: %s", target.display_name)
    log.info("=" * 50)

    # --- Passive scan already done; simulate brief analysis pause ---
    _step("[DEMO] Re-checking beacon metadata...", DEMO_TIMINGS["scan"])
    assessment.add_attack_step("Demo: beacon metadata re-checked.")

    # --- WPS path (only when the beacon advertises WPS) ---
    if "WPS" in security:
        _step("[DEMO] Probing WPS with Reaver Pixie Dust...", DEMO_TIMINGS["wps_attempt"])
        if DEMO_CRACKED_PASSWORD is not None:
            log.info("[DEMO] WPS Pixie Dust succeeded.")
            assessment.add_attack_step("Demo: WPS Pixie Dust returned a credential.")
            _finish_demo(assessment, workspace_manager, via="WPS Pixie Dust")
            return
        log.warning("[DEMO] WPS Pixie Dust did not succeed. Pivoting to WPA capture paths.")
        assessment.add_attack_step("Demo: WPS path unsuccessful, pivoting.")

    # --- PMKID ---
    if "WPA" in security:
        _step("[DEMO] Attempting passive PMKID capture (hcxdumptool)...", DEMO_TIMINGS["pmkid_attempt"])
        log.info("[DEMO] PMKID frame captured.")
        assessment.add_attack_step("Demo: PMKID capture simulated.")

        _step("[DEMO] Converting capture to 22000 hash format...", DEMO_TIMINGS["hash_prep"])
        assessment.add_attack_step("Demo: hash file prepared (hcxpcapngtool).")

        _step("[DEMO] Running Hashcat dictionary attack...", DEMO_TIMINGS["hashcat_dict"])

        if DEMO_CRACKED_PASSWORD is not None:
            log.info("[DEMO] Hashcat recovered the password via dictionary.")
            assessment.add_attack_step("Demo: Hashcat dictionary attack succeeded.")
            _finish_demo(assessment, workspace_manager, via="PMKID + Hashcat dictionary")
            return

        # Dictionary exhausted — try numeric brute force
        _step("[DEMO] Dictionary exhausted. Trying 8-digit numeric mask...", DEMO_TIMINGS["hashcat_brute"])
        if DEMO_CRACKED_PASSWORD is not None:
            log.info("[DEMO] Hashcat recovered the password via brute-force mask.")
            assessment.add_attack_step("Demo: Hashcat brute-force mask succeeded.")
            _finish_demo(assessment, workspace_manager, via="PMKID + Hashcat brute-force")
            return

    # If we reach here the demo is configured to simulate a failed run.
    log.warning("[DEMO] Simulated active phase completed without credential recovery.")
    assessment.add_attack_step("Demo: active phase completed — no credential recovered.")
    assessment.active_phase_ran = True
    workspace_manager.save_metadata("compromised", False)
    workspace_manager.save_metadata("demo_mode", True)


def _finish_demo(
    assessment: AssessmentResult,
    workspace_manager: WorkspaceManager,
    via: str,
) -> None:
    assessment.cracked_password = DEMO_CRACKED_PASSWORD
    assessment.active_phase_ran = True
    workspace_manager.save_metadata("compromised", True)
    workspace_manager.save_metadata("demo_mode", True)
    workspace_manager.save_metadata("demo_via", via)
    workspace_manager.save_metadata("cracked_password", DEMO_CRACKED_PASSWORD)

    # Create placeholder artefact files so the report artefact table is populated
    _write_placeholder(workspace_manager.get_path("pmkid"), "[demo] simulated PMKID capture")
    _write_placeholder(workspace_manager.get_path("hash"), "[demo] simulated 22000 hash")
    _write_placeholder(workspace_manager.get_path("potfile"), f"[hash]:{DEMO_CRACKED_PASSWORD}")

    log.info("[DEMO] Pipeline complete via: %s | credential: %s", via, DEMO_CRACKED_PASSWORD)


def _write_placeholder(path: Path, content: str) -> None:
    try:
        path.write_text(content + "\n", encoding="utf-8")
    except OSError:
        pass
