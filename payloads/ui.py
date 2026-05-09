from __future__ import annotations

import os
import sys
from typing import Iterable

from payloads.models import WifiNetwork


def use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def style(text: str, *codes: str) -> str:
    if not use_color() or not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


def bold(text: str) -> str:
    return style(text, "1")


def dim(text: str) -> str:
    return style(text, "2")


def cyan(text: str) -> str:
    return style(text, "96")


def blue(text: str) -> str:
    return style(text, "94")


def green(text: str) -> str:
    return style(text, "92")


def yellow(text: str) -> str:
    return style(text, "93")


def red(text: str) -> str:
    return style(text, "91")


def print_banner(app_name: str, version: str) -> None:
    title = bold(cyan(app_name))
    subtitle = dim("Wireless assessment toolkit")
    line = cyan("═" * 72)
    print()
    print(line)
    print(f"  {title}  {dim(f'v{version}')}")
    print(f"  {subtitle}")
    print(line)


def print_section(title: str) -> None:
    print()
    print(f"{blue('▶')} {bold(title)}")


def print_kv(label: str, value: str) -> None:
    print(f"  {dim(label + ':'):18} {value}")


def confirm_action(message: str, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True

    print()
    print(f"{yellow('!')} {bold(message)}")
    response = input(f"{dim('Continue?')} {green('[Y/n]')} ").strip().lower()
    return response in {"", "y", "yes"}


def format_interfaces(interfaces: Iterable[str]) -> str:
    lines = [bold("Detected WiFi interfaces")]
    for index, interface_name in enumerate(interfaces, start=1):
        lines.append(f"  {cyan(str(index).rjust(2) + '.')} {interface_name}")
    return "\n".join(lines)


def security_badge(security: str) -> str:
    upper = security.upper()
    if "OPEN" in upper:
        return red(security)
    if "WEP" in upper or "WPS" in upper:
        return yellow(security)
    if "WPA3" in upper:
        return green(security)
    return blue(security)


def signal_bar(signal: int) -> str:
    buckets = max(1, min(5, round(signal / 20)))
    filled = "■" * buckets
    empty = "·" * (5 - buckets)
    if signal >= 75:
        return green(filled) + dim(empty)
    if signal >= 45:
        return yellow(filled) + dim(empty)
    return red(filled) + dim(empty)


def format_network_table(networks: list[WifiNetwork], title: str = "Detected networks") -> str:
    if not networks:
        return yellow("No networks found.")

    ssid_width = max(18, min(28, max(len(net.display_name) for net in networks)))
    lines = [bold(title)]
    header = (
        f"  {dim('#'):>3}  "
        f"{dim('SSID'):<{ssid_width}}  "
        f"{dim('CH'):>3}  "
        f"{dim('SIG'):>4}  "
        f"{dim('BAR'):7}  "
        f"{dim('SECURITY'):<18}  "
        f"{dim('BSSID')}"
    )
    lines.append(header)
    lines.append(dim("  " + "─" * max(72, len(header) - 2)))

    for index, network in enumerate(networks, start=1):
        ssid = network.display_name
        if len(ssid) > ssid_width:
            ssid = ssid[: ssid_width - 1] + "…"
        lines.append(
            f"  {cyan(str(index).rjust(2) + '.'):>5} "
            f"{ssid:<{ssid_width}}  "
            f"{network.channel:>3}  "
            f"{network.signal:>3}%  "
            f"{signal_bar(network.signal):7}  "
            f"{security_badge(network.security):<18}  "
            f"{dim(network.bssid)}"
        )
    return "\n".join(lines)
