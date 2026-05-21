from __future__ import annotations

import logging
from dataclasses import dataclass

from core.system import run_command

log = logging.getLogger(__name__)


@dataclass
class RadioState:
    interface: str
    nm_killed: bool = False


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


def ensure_monitor_mode(interface: str) -> RadioState:
    log.info("Preparing monitor mode on %s...", interface)
    nm_killed = False
    try:
        kill_output = run_command(["airmon-ng", "check", "kill"])
        if "Killing these processes:" in kill_output:
            nm_killed = True

        output = run_command(["airmon-ng", "start", interface])
        new_iface = parse_airmon_start(output)

        if new_iface:
            log.info("Monitor mode enabled. New interface: %s", new_iface)
            return RadioState(interface=new_iface, nm_killed=nm_killed)

        iw_output = run_command(["iw", "dev"])
        fallback_iface = parse_iw_dev_monitor(iw_output)
        if fallback_iface:
            log.info("Monitor mode detected via iw fallback: %s", fallback_iface)
            return RadioState(interface=fallback_iface, nm_killed=nm_killed)

        raise RuntimeError(f"Could not determine the monitor interface name for {interface}.")
    except RuntimeError as exc:
        raise RuntimeError(f"Critical failure while enabling monitor mode: {exc}") from exc


def restore_mode(state: RadioState) -> None:
    log.info("Restoring interface %s to managed mode...", state.interface)
    try:
        run_command(["airmon-ng", "stop", state.interface])
        if state.nm_killed:
            run_command(["systemctl", "restart", "NetworkManager"])
            log.info("Network services restored (NetworkManager).")
    except RuntimeError as exc:
        log.warning("Issues were reported while restoring network state: %s", exc)


def set_channel(interface: str, channel: str) -> None:
    log.info("Locking %s to channel %s...", interface, channel)
    try:
        run_command(["iw", "dev", interface, "set", "channel", channel])
    except RuntimeError as exc:
        raise RuntimeError(f"Failed to set channel {channel}: {exc}") from exc
