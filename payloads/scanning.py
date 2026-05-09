from __future__ import annotations

from typing import Iterable

from payloads.models import WifiNetwork
from payloads.system import optional_command, run_command


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


def scan_networks(interface: str | None = None) -> list[WifiNetwork]:
    if not optional_command("nmcli"):
        raise RuntimeError("nmcli is required for live WiFi scanning on this system.")

    command = [
        "nmcli",
        "-t",
        "--escape",
        "yes",
        "-f",
        "SSID,BSSID,CHAN,SIGNAL,SECURITY",
        "device",
        "wifi",
        "list",
        "--rescan",
        "yes",
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


def demo_networks() -> list[WifiNetwork]:
    return [
        WifiNetwork("Lab-Router-WPA3", "02:11:22:33:44:55", "6", 84, "WPA2 WPA3"),
        WifiNetwork("Legacy-Lab-WPS", "02:11:22:33:44:66", "11", 71, "WPA2 WPS"),
        WifiNetwork("Guest-Open", "02:11:22:33:44:77", "1", 58, "OPEN"),
        WifiNetwork("MOVISTAR_TEST", "02:11:22:33:44:89", "3", 52, "WPA2"),
        WifiNetwork("", "02:11:22:33:44:88", "36", 49, "WPA2"),
    ]


def list_networks(networks: list[WifiNetwork]) -> str:
    if not networks:
        return "No networks found."

    lines = ["Detected networks:"]
    for index, network in enumerate(networks, start=1):
        lines.append(
            f"{index:>2}. {network.display_name} | {network.bssid} | "
            f"ch {network.channel} | {network.signal}% | {network.security}"
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
