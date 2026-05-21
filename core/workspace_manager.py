from __future__ import annotations

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class WorkspaceManager:
    """
    Manage the workspace directory for a specific target.
    Centralizes path creation, metadata persistence, tool logs, and cleanup.
    """

    def __init__(self, base_dir: str | Path, target_bssid: str):
        if not target_bssid:
            raise ValueError("A BSSID is required to isolate the workspace.")

        self.safe_bssid = target_bssid.replace(':', '').upper()
        self.base_dir = Path(base_dir)
        self.workspace_path = self.base_dir / self.safe_bssid
        self._ensure_directories()
        if not self.get_metadata("created_at"):
            self.save_metadata("created_at", datetime.now().isoformat())

    def _ensure_directories(self) -> None:
        """Ensure the target workspace exists, with a writable fallback in /tmp."""
        try:
            self.workspace_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            fallback_base = Path(os.environ.get("WIFISENTRY_TMP_WORKSPACES", "/tmp/wifisentry-workspaces"))
            fallback_base.mkdir(parents=True, exist_ok=True)
            self.workspace_path = fallback_base / self.safe_bssid
            self.workspace_path.mkdir(parents=True, exist_ok=True)
            log.warning(
                "Could not create workspace in %s (%s). Falling back to %s",
                self.base_dir,
                exc,
                self.workspace_path,
            )
        log.debug(f"Workspace ready at: {self.workspace_path}")

    def get_path(self, file_purpose: str) -> Path:
        """
        Return the canonical path for a workspace artifact.
        """
        files = {
            "pmkid": f"{self.safe_bssid}_pmkid.pcapng",
            "eapol_prefix": f"{self.safe_bssid}_eapol",
            "client_scan_prefix": f"{self.safe_bssid}_clients",
            "hash": "target_hashes.hc22000",
            "potfile": "hashcat.potfile",
            "wps_loot": "WPS_LOOT.json",
            "metadata": "execution_meta.json",
            "target_filter": "target.txt",
            "rockyou_local": "rockyou.txt",
            "tool_log": "execution_raw.log",
        }

        if file_purpose not in files:
            raise ValueError(f"Unknown workspace file purpose: {file_purpose}")

        return self.workspace_path / files[file_purpose]

    def save_metadata(self, key: str, value: Any) -> None:
        """Persist execution metadata in JSON format."""
        meta_path = self.get_path("metadata")
        data = {}

        try:
            if meta_path.exists() and meta_path.stat().st_size > 0:
                data = json.loads(meta_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("Metadata file was corrupted and will be overwritten.")

        data[key] = value

        try:
            meta_path.write_text(json.dumps(data, indent=4), encoding="utf-8")
        except OSError as exc:
            log.error(f"Failed to save workspace metadata: {exc}")

    def get_metadata(self, key: str) -> Any | None:
        """Fetch a metadata value by key."""
        meta_path = self.get_path("metadata")
        if not meta_path.exists():
            return None

        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            return data.get(key)
        except json.JSONDecodeError:
            return None

    def append_tool_log(self, tool_name: str, command: str, output: str) -> None:
        """Append a raw execution log entry for a tool run."""
        log_path = self.get_path("tool_log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        separator = "=" * 60
        entry = (
            f"\n{separator}\n"
            f"[{timestamp}] TOOL: {tool_name}\n"
            f"COMMAND: {command}\n"
            f"{separator}\n"
            f"{output}\n"
        )
        try:
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(entry)
        except OSError as exc:
            log.warning(f"Could not write tool log for {tool_name}: {exc}")

    def describe_artifact(self, artifact_name: str, artifact_path: Path) -> dict[str, Any] | None:
        """Build structured metadata for a workspace artifact."""
        if not artifact_path.exists() or not artifact_path.is_file():
            return None

        try:
            stat = artifact_path.stat()
        except OSError as exc:
            log.warning(f"Could not inspect artifact {artifact_path}: {exc}")
            return None

        return {
            "name": artifact_name,
            "path": str(artifact_path.resolve()),
            "filename": artifact_path.name,
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "suffix": artifact_path.suffix,
        }

    def save_artifact_index(self, artifacts: dict[str, Path]) -> dict[str, dict[str, Any]]:
        """Persist a structured artifact index in metadata."""
        artifact_index: dict[str, dict[str, Any]] = {}
        for artifact_name, artifact_path in artifacts.items():
            artifact_info = self.describe_artifact(artifact_name, artifact_path)
            if artifact_info is not None:
                artifact_index[artifact_name] = artifact_info

        self.save_metadata("captured_files", artifact_index)
        self.save_metadata("captured_files_count", len(artifact_index))
        return artifact_index

    def archive_workspace(self, output_dir: Path) -> Path | None:
        """Archive the workspace into a zip file for evidence retention."""
        log.info(f"Archiving evidence for target {self.safe_bssid}...")
        output_dir.mkdir(parents=True, exist_ok=True)
        zip_name = output_dir / f"evidence_{self.safe_bssid}"
        try:
            archive_path = shutil.make_archive(str(zip_name), "zip", str(self.workspace_path))
            log.info(f"Evidence archive created successfully at: {archive_path}")
            return Path(archive_path)
        except OSError as exc:
            log.error(f"Failed to archive workspace: {exc}")
            return None

    def partial_cleanup(self) -> None:
        """
        Remove heavy temporary files while keeping hashes, potfiles,
        loot, metadata, and logs.
        """
        log.info(f"Cleaning temporary files in workspace {self.safe_bssid}...")

        keep_extensions = {".hc22000", ".potfile", ".json", ".log"}
        keep_names = {"WPS_LOOT.json"}

        cleaned_count = 0
        for item in self.workspace_path.iterdir():
            if item.is_file():
                if item.suffix in keep_extensions or item.name in keep_names:
                    continue

                try:
                    item.unlink()
                    cleaned_count += 1
                except OSError as exc:
                    log.warning(f"Could not remove {item.name}: {exc}")

        log.info(f"Partial cleanup completed. Removed {cleaned_count} temporary files.")

    def destroy_workspace(self) -> None:
        """Delete the target workspace entirely."""
        log.warning(f"Destroying workspace: {self.workspace_path}")
        try:
            shutil.rmtree(self.workspace_path)
            log.info("Workspace removed.")
        except OSError as exc:
            log.error(f"Failed to destroy workspace: {exc}")
