from __future__ import annotations

"""
third_party.py — Integration layer for bundled research tools.

Three families are supported:

  kr00k/       — CVE-2019-15126 (WPA2 AES-CCMP zero-TK decryption)
                 Works on captured pcap files through ESET's kr00k.py.
                 Invokes: third-party/kr00k/malware-research/kr00k/kr00k.py

  dragonforce/ — WPA3-SAE Dragonblood attacks (CVE-2019-13377 family)
                 Requires compiled binaries from dragonforce/dragonslayer.
                 Invokes: dragondrain-and-time, dragonforce bruter.

  fragattacks/ — 802.11 fragmentation/aggregation CVEs (CVE-2020-24588 family)
                 Requires patched drivers + compiled fragattacks suite.
                 Invokes: fragattack.py from fragattacks/research/

All functions return a ThirdPartyResult dataclass so callers don't need to
know which tool produced the output.
"""

import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Root of the third-party tree (relative to the project root, where main.py lives)
# ---------------------------------------------------------------------------
_TP_ROOT = Path(__file__).parent.parent / "third-party"

_KR00K_ESET = _TP_ROOT / "kr00k" / "malware-research" / "kr00k" / "kr00k.py"
_DRAGONFORCE   = _TP_ROOT / "dragonforce" / "dragonforce" / "dragonforce"  # compiled binary
_DRAGONTIME    = _TP_ROOT / "dragonforce" / "dragondrain-and-time" / "src" / "dragontime"
_FRAGATTACK    = _TP_ROOT / "fragattacks" / "research" / "fragattack.py"


# ---------------------------------------------------------------------------
# Shared result type
# ---------------------------------------------------------------------------

@dataclass
class ThirdPartyResult:
    tool: str                        # human-readable tool name
    slug: str                        # machine key: "kr00k" | "dragonblood" | "fragattacks"
    ran: bool = False                # True if the tool actually executed
    success: bool = False            # True if a vulnerability was confirmed
    output: str = ""                 # raw stdout/stderr snippet
    artefacts: dict[str, Path] = field(default_factory=dict)
    note: str = ""                   # human explanation for the report


# ---------------------------------------------------------------------------
# Availability helpers
# ---------------------------------------------------------------------------

def _python() -> str:
    return sys.executable


def _tool_available(path: Path) -> bool:
    return path.exists() and path.is_file()


def _binary_available(path: Path) -> bool:
    return path.exists() and path.is_file() and shutil.which(str(path)) is not None or (
        path.exists() and path.stat().st_size > 0
    )


# ---------------------------------------------------------------------------
# Kr00k integration — CVE-2019-15126
# ---------------------------------------------------------------------------

def check_kr00k_available() -> tuple[bool, str]:
    """Return (available, reason_if_not)."""
    if _tool_available(_KR00K_ESET):
        return True, ""
    return False, f"kr00k.py not found at {_KR00K_ESET}."


def run_kr00k_pcap(
    pcap_path: Path,
    workspace: Path,
) -> ThirdPartyResult:
    """
    Run the ESET kr00k script in offline (-f) mode against an existing pcap.
    This is non-destructive and safe — just reads the file.
    Returns immediately with the analysis.
    """
    result = ThirdPartyResult(tool="Kr00k (ESET)", slug="kr00k")

    available, reason = check_kr00k_available()
    if not available:
        result.note = f"Kr00k tool not found: {reason}"
        log.warning("[kr00k] %s", result.note)
        return result

    if not pcap_path.exists():
        result.note = f"Pcap file not found: {pcap_path}"
        log.warning("[kr00k] %s", result.note)
        return result

    output_file = workspace / "kr00k_analysis.txt"

    log.info("[kr00k] Analysing capture %s for Kr00k vulnerability...", pcap_path.name)
    cmd = [_python(), str(_KR00K_ESET), "-f", str(pcap_path)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        combined = proc.stdout + proc.stderr
        output_file.write_text(combined, encoding="utf-8")
        result.ran = True
        result.output = combined[:2000]
        result.artefacts["kr00k_log"] = output_file

        # Heuristic: ESET tool prints "[!] Device with MAC … is vulnerable"
        if "is vulnerable" in combined.lower():
            result.success = True
            result.note = "Kr00k (CVE-2019-15126) confirmed vulnerable — zero-TK decryption succeeded on captured frames."
            log.info("[kr00k] VULNERABLE: %s", result.note)
        else:
            result.note = "Kr00k analysis completed — no zero-TK decryptable frames found in this capture."
            log.info("[kr00k] Not vulnerable (or not enough traffic).")

    except subprocess.TimeoutExpired:
        result.ran = True
        result.note = "Kr00k analysis timed out (60s)."
        log.warning("[kr00k] Timeout.")
    except (subprocess.SubprocessError, OSError) as exc:
        result.note = f"Kr00k execution error: {exc}"
        log.error("[kr00k] %s", exc)

    return result

# ---------------------------------------------------------------------------
# Dragonblood integration — CVE-2019-13377 family (WPA3-SAE)
# ---------------------------------------------------------------------------

def check_dragonblood_available() -> tuple[bool, str]:
    if _binary_available(_DRAGONFORCE):
        return True, ""
    return False, (
        f"dragonforce binary not found at {_DRAGONFORCE}. "
        "Build it with: cd third-party/dragonforce/dragonforce && bash build.sh"
    )


def run_dragonblood_timing(
    interface: str,
    bssid: str,
    ssid: str,
    workspace: Path,
    wordlist: Path | None = None,
    attempts: int = 50,
) -> ThirdPartyResult:
    """
    Run dragontime timing attack against a WPA3-SAE target to infer whether
    the AP is susceptible to cache-based or timing side-channels.

    The tool attempts SAE commit exchanges and measures response times.
    """
    result = ThirdPartyResult(tool="Dragontime (Dragonblood)", slug="dragonblood")

    available, reason = check_dragonblood_available()
    if not available:
        result.note = reason
        log.warning("[dragonblood] %s", reason)
        return result

    output_file = workspace / "dragonblood_timing.txt"
    log.info("[dragonblood] Starting SAE timing analysis against %s (%s)...", ssid, bssid)

    cmd = [str(_DRAGONFORCE), "--interface", interface, "--bssid", bssid,
           "--ssid", ssid, "--num", str(attempts)]
    if wordlist and wordlist.exists():
        cmd += ["--wordlist", str(wordlist)]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        combined = proc.stdout + proc.stderr
        output_file.write_text(combined, encoding="utf-8")
        result.ran = True
        result.output = combined[:2000]
        result.artefacts["dragonblood_log"] = output_file

        # Look for timing vulnerability indicators
        lower = combined.lower()
        if any(kw in lower for kw in ("timing leak", "vulnerable", "side-channel confirmed", "attack succeeded")):
            result.success = True
            result.note = "Dragonblood timing side-channel detected on WPA3-SAE AP."
            log.info("[dragonblood] VULNERABLE: timing side-channel confirmed.")
        elif "not vulnerable" in lower or "no timing" in lower:
            result.note = "Dragonblood analysis completed — no timing vulnerability detected."
        else:
            result.note = "Dragonblood analysis completed — result inconclusive, review log."
        log.info("[dragonblood] %s", result.note)

    except subprocess.TimeoutExpired:
        result.ran = True
        result.note = "Dragonblood timing analysis timed out (120s)."
        log.warning("[dragonblood] Timeout.")
    except (subprocess.SubprocessError, OSError) as exc:
        result.note = f"Dragonblood execution error: {exc}"
        log.error("[dragonblood] %s", exc)

    return result


# ---------------------------------------------------------------------------
# FragAttacks integration — CVE-2020-24588 family
# ---------------------------------------------------------------------------

def check_fragattacks_available() -> tuple[bool, str]:
    if _tool_available(_FRAGATTACK):
        return True, ""
    return False, (
        f"fragattack.py not found at {_FRAGATTACK}. "
        "Make sure the fragattacks submodule is checked out."
    )


def run_fragattacks_ping_test(
    interface: str,
    bssid: str,
    workspace: Path,
    test_name: str = "ping",
    extra_args: list[str] | None = None,
) -> ThirdPartyResult:
    """
    Run a fragattacks ping test against the target AP.

    The ping test (CVE-2020-24586/24587/24588) sends specially crafted
    fragmented/aggregated frames and listens for an ICMP echo reply that
    should not arrive if the AP is patched.

    Note: requires the patched ath9k firmware from
    third-party/fragattacks/research/ath9k-firmware/ and a compatible
    adapter (ath9k_htc).
    """
    result = ThirdPartyResult(tool="FragAttacks", slug="fragattacks")

    available, reason = check_fragattacks_available()
    if not available:
        result.note = reason
        log.warning("[fragattacks] %s", reason)
        return result

    output_file = workspace / "fragattacks_output.txt"
    log.info("[fragattacks] Running '%s' test against %s...", test_name, bssid)

    # fragattack.py needs wpa_supplicant config; build a minimal one
    client_conf = workspace / "fragattack_client.conf"
    if not client_conf.exists():
        client_conf.write_text(
            "network={\n    key_mgmt=NONE\n    scan_ssid=1\n}\n",
            encoding="utf-8",
        )

    cmd = [
        _python(), str(_FRAGATTACK),
        interface, test_name,
        "--bssid", bssid,
        "--config", str(client_conf),
    ]
    if extra_args:
        cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=90,
            cwd=str(_FRAGATTACK.parent),
        )
        combined = proc.stdout + proc.stderr
        output_file.write_text(combined, encoding="utf-8")
        result.ran = True
        result.output = combined[:2000]
        result.artefacts["fragattacks_log"] = output_file

        lower = combined.lower()
        if "vulnerable" in lower or "received ping" in lower or "test passed" in lower:
            result.success = True
            result.note = f"FragAttacks '{test_name}': AP appears VULNERABLE to fragmentation/aggregation flaw."
            log.info("[fragattacks] VULNERABLE confirmed for test '%s'.", test_name)
        elif "not vulnerable" in lower or "no ping" in lower or "test failed" in lower:
            result.note = f"FragAttacks '{test_name}': target appears patched or not susceptible."
        else:
            result.note = (
                f"FragAttacks '{test_name}': test completed — result inconclusive. "
                "Review fragattacks_output.txt for details."
            )
        log.info("[fragattacks] %s", result.note)

    except subprocess.TimeoutExpired:
        result.ran = True
        result.note = "FragAttacks test timed out (90s)."
        log.warning("[fragattacks] Timeout.")
    except (subprocess.SubprocessError, OSError) as exc:
        result.note = f"FragAttacks execution error: {exc}"
        log.error("[fragattacks] %s", exc)

    return result


# ---------------------------------------------------------------------------
# Dispatcher: given a TechniquePlan list, run the appropriate third-party tools
# ---------------------------------------------------------------------------

def run_applicable_third_party(
    interface: str,
    target_bssid: str,
    target_ssid: str,
    workspace: Path,
    technique_slugs: set[str],
    captured_pcap: Path | None = None,
    wordlist: Path | None = None,
) -> list[ThirdPartyResult]:
    """
    Called by offensive.py after the main pipeline.
    Runs third-party tools for whichever technique slugs are enabled and
    whose tools are available.

    Returns a list of ThirdPartyResult (may be empty if nothing ran).
    """
    results: list[ThirdPartyResult] = []

    # --- Kr00k ---
    if "kr00k" in technique_slugs:
        if captured_pcap and captured_pcap.exists():
            log.info("[third-party] Running Kr00k offline analysis on %s...", captured_pcap.name)
            results.append(run_kr00k_pcap(captured_pcap, workspace))
        else:
            tp = ThirdPartyResult(tool="Kr00k", slug="kr00k")
            tp.note = "Kr00k skipped: no captured pcap available for offline analysis."
            results.append(tp)

    # --- Dragonblood ---
    if "wpa3" in technique_slugs:
        results.append(
            run_dragonblood_timing(
                interface, target_bssid, target_ssid, workspace, wordlist=wordlist
            )
        )

    # --- FragAttacks ---
    if "fragattacks" in technique_slugs:
        results.append(
            run_fragattacks_ping_test(interface, target_bssid, workspace)
        )

    return results
