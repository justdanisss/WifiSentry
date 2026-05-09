from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path


def configure_logging(log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.handlers.clear()
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root_logger.addHandler(stream_handler)


def check_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def validate_environment(mode: str) -> list[str]:
    notes: list[str] = []
    if not optional_command("nmcli"):
        notes.append("`nmcli` is not installed; live scan mode will be unavailable.")
    if mode == "live scan" and not check_root():
        notes.append(
            "Running without root privileges; some WiFi metadata or driver-specific "
            "queries may be limited."
        )
    return notes


def require_command(tool: str) -> None:
    if not shutil.which(tool):
        raise RuntimeError(f"Required command not found: {tool}")


def optional_command(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_command(command: list[str], timeout: int = 20) -> str:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or "no stderr"
        raise RuntimeError(f"Command failed: {' '.join(command)} ({stderr})") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Command timed out: {' '.join(command)}") from exc
    return result.stdout
