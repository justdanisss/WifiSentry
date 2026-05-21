from __future__ import annotations

import re
import subprocess
from typing import Iterable

from core.models import WifiNetwork
from core.system import optional_command, run_command


# ---------------------------------------------------------------------------
# nmcli field parser
# ---------------------------------------------------------------------------

def split_nmcli_fields(line: str) -> list[str]:
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == ":":
            fields.append("".join(current))
            current = []
            continue
        current.append(char)
    fields.append("".join(current))
    return fields


# ---------------------------------------------------------------------------
# Interface detection
# ---------------------------------------------------------------------------

def detect_interfaces() -> list[str]:
    if optional_command("nmcli"):
        output = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"])
        interfaces = []
        for line in output.splitlines():
            parts = split_nmcli_fields(line)
            if len(parts) >= 2 and parts[1] == "wifi":
                interfaces.append(parts[0])
        return interfaces

    if optional_command("iw"):
        output = run_command(["iw", "dev"])
        interfaces = []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                interfaces.append(line.split(maxsplit=1)[1])
        return interfaces

    return []


def resolve_interface(requested_interface: str | None) -> str | None:
    if requested_interface:
        return requested_interface
    try:
        interfaces = detect_interfaces()
    except RuntimeError:
        return None
    return interfaces[0] if interfaces else None


# ---------------------------------------------------------------------------
# Network scan
# ---------------------------------------------------------------------------

def scan_networks(interface: str | None = None) -> list[WifiNetwork]:
    if not optional_command("nmcli"):
        raise RuntimeError("nmcli is required for live WiFi scanning on this system.")

    command = [
        "nmcli", "-t", "--escape", "yes",
        "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY",
        "device", "wifi", "list", "--rescan", "yes",
    ]
    if interface:
        command.extend(["ifname", interface])

    output = run_command(command)
    networks: list[WifiNetwork] = []
    for line in output.splitlines():
        parts = split_nmcli_fields(line)
        if len(parts) < 5:
            continue
        ssid, bssid, channel, signal_raw, security = parts[:5]
        try:
            signal = int(signal_raw)
        except ValueError:
            signal = 0
        networks.append(
            WifiNetwork(
                ssid=ssid.strip(),
                bssid=bssid.strip(),
                channel=channel.strip(),
                signal=signal,
                security=security.strip() or "OPEN",
            )
        )
    return deduplicate_networks(networks)


def deduplicate_networks(networks: Iterable[WifiNetwork]) -> list[WifiNetwork]:
    by_bssid: dict[str, WifiNetwork] = {}
    for network in networks:
        previous = by_bssid.get(network.bssid)
        if previous is None or network.signal > previous.signal:
            by_bssid[network.bssid] = network
    return sorted(by_bssid.values(), key=lambda item: item.signal, reverse=True)


# ---------------------------------------------------------------------------
# WPS hidden detection via wash
# ---------------------------------------------------------------------------

def probe_wps_with_wash(interface: str, timeout: int = 15) -> dict[str, bool]:
    """
    Run wash briefly and return BSSID -> wps_locked.

    False means WPS is reported as unlocked/attackable. An empty dict means
    wash is unavailable, failed, or did not report any BSSID.
    """
    if not interface or not optional_command("wash"):
        return {}

    result: dict[str, bool] = {}
    command_variants = [
        ["wash", "-i", interface, "--scan", f"--timeout={timeout}"],
        ["wash", "-i", interface],
    ]

    for command in command_variants:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            continue

        parsed = parse_wash_table(proc.stdout)
        if parsed:
            result.update(parsed)
            break

    return result


def parse_wash_table(output: str) -> dict[str, bool]:
    """Parse wash table output into BSSID -> locked."""
    result: dict[str, bool] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("BSSID") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        bssid = parts[0].upper()
        if not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
            continue
        locked_str = parts[4].upper()
        locked = locked_str.startswith("Y")
        result[bssid] = locked
    return result


def enrich_with_wps(
    networks: list[WifiNetwork],
    wps_map: dict[str, bool],
) -> list[WifiNetwork]:
    """
    Return new WifiNetwork instances with WPS injected into the security field
    for any network whose BSSID appears in wps_map.
    """
    enriched = []
    for net in networks:
        bssid_norm = net.bssid.upper()
        if bssid_norm in wps_map and "WPS" not in net.security.upper():
            locked = wps_map[bssid_norm]
            wps_tag = "WPS" if not locked else "WPS(locked)"
            enriched.append(
                WifiNetwork(
                    ssid=net.ssid,
                    bssid=net.bssid,
                    channel=net.channel,
                    signal=net.signal,
                    security=f"{net.security} {wps_tag}".strip(),
                )
            )
        else:
            enriched.append(net)
    return enriched


# ---------------------------------------------------------------------------
# Dual-band sibling detection
# ---------------------------------------------------------------------------

_BAND_SUFFIXES = re.compile(
    r"[_\-\s]?(2\.?4\s?[Gg](Hz)?|5\s?[Gg](Hz)?|6\s?[Gg](Hz)?)$",
    re.IGNORECASE,
)


def _strip_band_suffix(ssid: str) -> str:
    return _BAND_SUFFIXES.sub("", ssid).strip()


def find_dual_band_sibling(
    target: WifiNetwork,
    all_networks: list[WifiNetwork],
) -> WifiNetwork | None:
    """
    Try to find the other-band sibling of target in all_networks.

    Strategies:
    1. Same SSID, opposite band.
    2. Same SSID after removing common band suffixes.
    3. Same OUI and compatible stripped SSID prefix.
    """
    target_band = target.band
    if target_band == "unknown":
        return None

    opposite_band = "5GHz" if target_band == "2.4GHz" else "2.4GHz"
    target_base = _strip_band_suffix(target.ssid).upper()
    target_oui = target.bssid.upper()[:8]

    candidates: list[WifiNetwork] = []
    for net in all_networks:
        if net.bssid.lower() == target.bssid.lower():
            continue
        if net.band != opposite_band:
            continue

        net_base = _strip_band_suffix(net.ssid).upper()
        net_oui = net.bssid.upper()[:8]

        if net.ssid == target.ssid:
            candidates.append(net)
            continue

        if target_base and net_base and target_base == net_base:
            candidates.append(net)
            continue

        if net_oui == target_oui and target_base and net_base:
            shorter = min(len(target_base), len(net_base))
            if shorter > 0 and target_base[:shorter] == net_base[:shorter]:
                candidates.append(net)

    if not candidates:
        return None
    return max(candidates, key=lambda item: item.signal)


# ---------------------------------------------------------------------------
# Demo networks
# ---------------------------------------------------------------------------

def demo_networks() -> list[WifiNetwork]:
    return [
        WifiNetwork("Lab-Router-WPA3", "02:11:22:33:44:55", "6", 84, "WPA2 WPA3"),
        WifiNetwork("Lab-Router-WPA3", "02:11:22:33:44:56", "36", 80, "WPA2 WPA3"),
        WifiNetwork("Legacy-Lab-WPS", "02:11:22:33:44:66", "11", 71, "WPA2 WPS"),
        WifiNetwork("Guest-Open", "02:11:22:33:44:77", "1", 58, "OPEN"),
        WifiNetwork("MOVISTAR_TEST", "02:11:22:33:44:89", "3", 52, "WPA2"),
        WifiNetwork("", "02:11:22:33:44:88", "36", 49, "WPA2"),
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def list_networks(networks: list[WifiNetwork]) -> str:
    if not networks:
        return "No networks found."

    lines = ["Detected networks:"]
    for index, network in enumerate(networks, start=1):
        band_tag = f" [{network.band}]" if network.band != "unknown" else ""
        lines.append(
            f"{index:>2}. {network.display_name} | {network.bssid} | "
            f"ch {network.channel}{band_tag} | {network.signal}% | {network.security}"
        )
    return "\n".join(lines)


def select_target(
    networks: list[WifiNetwork],
    ssid: str | None = None,
    bssid: str | None = None,
) -> WifiNetwork:
    if bssid:
        for network in networks:
            if network.bssid.lower() == bssid.lower():
                return network
        raise RuntimeError(f"No network found with BSSID {bssid}.")

    if ssid:
        candidates = [network for network in networks if network.ssid == ssid]
        if not candidates:
            raise RuntimeError(f"No network found with SSID {ssid!r}.")
        return max(candidates, key=lambda item: item.signal)

    if not networks:
        raise RuntimeError("No WiFi networks were found.")

    return networks[0]
