from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from core.analysis import analyze_network, severity_score
from core.config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_ARCHIVE_DIR,
    DEFAULT_HTML_REPORT_PATH,
    DEFAULT_LOG_PATH,
    DEFAULT_REPORT_PATH,
    LOCAL_WORDLISTS_DIR,
)
from core.demo import run_demo_active_phase
from core.models import AssessmentContext, AssessmentResult, DualBandResult
from core.offensive import maybe_run_offensive_extensions
from core.third_party import ThirdPartyResult
from core.planning import plan_offensive_techniques, serialize_technique_plan
from core.radio import RadioState, ensure_monitor_mode, restore_mode, set_channel
from core.reporting import (
    build_html_report,
    build_markdown_report,
    write_html_report,
    write_network_inventory,
    write_report,
)
from core.scanning import (
    demo_networks,
    detect_interfaces,
    enrich_with_wps,
    find_dual_band_sibling,
    probe_wps_with_wash,
    scan_networks,
    select_target,
)
from core.strategy import build_review_plan, detect_ssid_profiles, serialize_plan, serialize_profile
from core.system import check_root, configure_logging, require_command, validate_environment
from core.tools_runner import verify_dual_band_psk
from core.ui import (
    bold,
    confirm_action,
    cyan,
    dim,
    format_interfaces,
    format_network_table,
    green,
    print_banner,
    print_kv,
    print_section,
    red,
    yellow,
)
from core.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Artefact collection
# ---------------------------------------------------------------------------

def collect_workspace_artifacts(
    assessment: AssessmentResult,
    workspace_manager: WorkspaceManager,
) -> None:
    """Map generated workspace files into the in-memory assessment object."""
    artifact_map = {
        "pmkid_capture": workspace_manager.get_path("pmkid"),
        "eapol_capture": Path(f"{workspace_manager.get_path('eapol_prefix')}-01.cap"),
        "hash_file": workspace_manager.get_path("hash"),
        "potfile": workspace_manager.get_path("potfile"),
        "wps_loot": workspace_manager.get_path("wps_loot"),
        "tool_log": workspace_manager.get_path("tool_log"),
        "metadata": workspace_manager.get_path("metadata"),
    }
    for key, path in artifact_map.items():
        if path.exists() and path.is_file() and path.stat().st_size > 0:
            assessment.captured_files[key] = path


def evaluate_dual_band(
    assessment: AssessmentResult,
    networks: list,
    workspace_manager: WorkspaceManager,
    context: AssessmentContext,
) -> None:
    """Record whether the target has a same-SSID AP on another band."""
    sibling = find_dual_band_sibling(assessment.target, networks)
    if sibling is None:
        workspace_manager.save_metadata("dual_band_check", {"found": False})
        return

    assessment.add_attack_step(
        f"Dual-band sibling detected: {sibling.display_name} ({sibling.bssid}) on {sibling.band}."
    )

    if assessment.cracked_password and context.interface and context.mode == "live scan":
        radio_state: RadioState | None = None
        try:
            radio_state = ensure_monitor_mode(context.interface)
            set_channel(radio_state.interface, sibling.channel)
            result = verify_dual_band_psk(
                sibling=sibling,
                known_password=assessment.cracked_password,
                interface=radio_state.interface,
                workspace_manager=workspace_manager,
                attack_log=assessment.attack_log,
            )
        except RuntimeError as exc:
            result = DualBandResult(
                sibling=sibling,
                same_password=None,
                method="pmkid+hashcat",
                note=f"Dual-band verification could not run: {exc}",
            )
            assessment.add_attack_step(f"Dual-band verification skipped: {exc}")
        finally:
            if radio_state is not None:
                restore_mode(radio_state)
    else:
        if assessment.cracked_password:
            note = (
                "A same-SSID network was found on another band. PSK parity verification "
                "requires a live interface and is skipped in this mode."
            )
        else:
            note = (
                "A same-SSID network was found on another band, but no recovered credential "
                "is available for PSK parity validation."
            )

        result = DualBandResult(
            sibling=sibling,
            same_password=None,
            method="same-ssid-cross-band-detection",
            note=note,
        )

    assessment.dual_band_result = result
    workspace_manager.save_metadata(
        "dual_band_check",
        {
            "found": True,
            "target_band": assessment.target.band,
            "sibling_ssid": sibling.display_name,
            "sibling_bssid": sibling.bssid,
            "sibling_band": sibling.band,
            "same_password": result.same_password,
            "method": result.method,
            "note": result.note,
        },
    )


# ---------------------------------------------------------------------------
# Wordlist selection
# ---------------------------------------------------------------------------

def _list_local_wordlists() -> list[Path]:
    """Return all .txt / .lst files found under ./wordlists/, sorted."""
    if not LOCAL_WORDLISTS_DIR.is_dir():
        return []
    candidates = sorted(LOCAL_WORDLISTS_DIR.glob("*.txt")) + sorted(LOCAL_WORDLISTS_DIR.glob("*.lst"))
    return candidates


def resolve_wordlist_input(args: argparse.Namespace) -> Path | None:
    """
    Determine which wordlist to use.

    Resolution order:
      1. --wordlist CLI flag (validated immediately).
      2. Interactive menu when the user did not supply a flag and there are
         local wordlists in ./wordlists/.
      3. None → tools_runner.resolve_wordlist() picks the best available
         system/ISP/default fallback at runtime.
    """
    # 1. Explicit flag
    if getattr(args, "wordlist", None):
        wl = Path(args.wordlist)
        if not wl.exists():
            raise RuntimeError(f"Wordlist not found: {wl}")
        return wl

    # 2. Non-interactive modes skip the menu
    if getattr(args, "demo", False) or getattr(args, "passive", False) or getattr(args, "assume_yes", False):
        return None

    local = _list_local_wordlists()
    if not local:
        return None  # nothing to choose from

    print()
    print(bold("Available wordlists"))
    for idx, wl_path in enumerate(local, start=1):
        size_kb = wl_path.stat().st_size // 1024
        print(f"  {cyan(str(idx).rjust(2) + '.')} {wl_path.name}  {dim(f'({size_kb} KB)')}")
    print(f"  {cyan(str(len(local) + 1).rjust(2) + '.')} {dim('Enter a custom path')}")
    print(f"  {cyan(str(len(local) + 2).rjust(2) + '.')} {dim('Auto-select (skip)')}")

    user_value = input(f"\n{dim('Select wordlist number')} {cyan('>')} ").strip()
    if not user_value:
        return None
    if not user_value.isdigit():
        raise RuntimeError("Wordlist selection must be a number.")

    choice = int(user_value)
    if choice < 1 or choice > len(local) + 2:
        raise RuntimeError(f"Invalid selection. Choose between 1 and {len(local) + 2}.")
    if choice == len(local) + 2:
        return None  # auto
    if choice == len(local) + 1:
        custom = input(f"{dim('Wordlist path')} {cyan('>')} ").strip()
        if not custom:
            return None
        cp = Path(custom)
        if not cp.exists():
            raise RuntimeError(f"Wordlist not found: {cp}")
        return cp
    return local[choice - 1]


# ---------------------------------------------------------------------------
# Interface and target resolution
# ---------------------------------------------------------------------------

def resolve_interface_input(args: argparse.Namespace) -> str | None:
    if args.interface:
        return args.interface
    if args.demo:
        return None

    interfaces = detect_interfaces()
    if not interfaces:
        raise RuntimeError("No WiFi interfaces were detected.")
    if len(interfaces) == 1:
        return interfaces[0]
    if args.assume_yes:
        raise RuntimeError(
            "You must provide -i/--interface when multiple WiFi interfaces are available and --assume-yes is used."
        )

    print()
    print(format_interfaces(interfaces))
    user_value = input(f"\n{dim('Select interface number')} {cyan('>')} ").strip()
    if not user_value:
        raise RuntimeError("No interface was selected.")
    if not user_value.isdigit():
        raise RuntimeError("You must enter a number from the detected interface list.")
    selected_index = int(user_value)
    if selected_index < 1 or selected_index > len(interfaces):
        raise RuntimeError(f"Index out of range. Must be between 1 and {len(interfaces)}.")
    return interfaces[selected_index - 1]


def resolve_target_input(
    args: argparse.Namespace,
    networks: list,
) -> tuple[str | None, str | None, str]:
    if args.bssid:
        return None, args.bssid, f"requested BSSID {args.bssid}"
    if args.ssid:
        return args.ssid, None, f"requested SSID {args.ssid}"
    if args.demo:
        return None, None, "strongest visible network"
    if args.assume_yes:
        raise RuntimeError("You must provide --ssid or --bssid when using --assume-yes in live mode.")

    print()
    print(format_network_table(networks, title="Choose a target network"))
    user_value = input(f"\n{dim('Select target number')} {cyan('>')} ").strip()
    if not user_value:
        raise RuntimeError("No target was provided.")
    if not user_value.isdigit():
        raise RuntimeError("You must enter a number from the detected network list.")
    selected_index = int(user_value)
    if selected_index < 1 or selected_index > len(networks):
        raise RuntimeError(f"Index out of range. Must be between 1 and {len(networks)}.")
    selected_network = networks[selected_index - 1]
    return selected_network.ssid, selected_network.bssid, f"interactive index {selected_index}"


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="wifisentry: defensive assessment and active validation toolkit."
    )
    parser.add_argument("-i", "--interface", help="WiFi interface to use, e.g. wlan0.")
    parser.add_argument("--ssid", help="Target SSID.")
    parser.add_argument("--bssid", help="Target BSSID (takes precedence over SSID).")
    parser.add_argument(
        "-w", "--wordlist",
        help="Wordlist for the cracking phase. Skips interactive selection.",
    )
    parser.add_argument("-p", "--passive", action="store_true", help="Passive mode: scan and risk analysis only.")
    parser.add_argument("-d", "--demo", action="store_true", help="Demo mode: simulated lab workflow.")
    parser.add_argument("-o", "--output", default=str(DEFAULT_REPORT_PATH), help="Markdown report output path.")
    parser.add_argument("--html-report", default=str(DEFAULT_HTML_REPORT_PATH), help="HTML report output path.")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation.")
    parser.add_argument("--list-interfaces", action="store_true", help="List detected WiFi interfaces and exit.")
    parser.add_argument("--list-networks", action="store_true", help="List detected WiFi networks and exit.")
    parser.add_argument("--assume-yes", action="store_true", help="Skip interactive confirmation prompts.")
    parser.add_argument("--log-file", default=str(DEFAULT_LOG_PATH), help="Log file path.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Main auditor
# ---------------------------------------------------------------------------

def run_auditor(args: argparse.Namespace) -> int:
    try:
        print_banner(APP_NAME, APP_VERSION)

        if not args.demo and not args.list_interfaces:
            require_command("nmcli")

        if not args.demo and not args.list_interfaces and not args.passive and not check_root():
            log.warning("Running without root privileges; the active phase may be limited.")

        # --list-interfaces
        if args.list_interfaces:
            interfaces = detect_interfaces()
            if not interfaces:
                print(yellow("No WiFi interfaces were detected."))
                return 1
            print(format_interfaces(interfaces))
            return 0

        selected_interface = resolve_interface_input(args)

        # Network scan / demo data
        if args.demo:
            networks = demo_networks()
            mode = "demo"
        else:
            networks = scan_networks(selected_interface)
            if selected_interface:
                wps_map = probe_wps_with_wash(selected_interface)
                networks = enrich_with_wps(networks, wps_map)
            mode = "live scan"

        # --list-networks
        if args.list_networks:
            print(format_network_table(networks))
            return 0

        # Target selection
        target_ssid, target_bssid, target_source = resolve_target_input(args, networks)
        target = select_target(networks, ssid=target_ssid, bssid=target_bssid)

        # Wordlist selection (interactive when applicable)
        wordlist_override: Path | None = None
        if not args.passive:
            wordlist_override = resolve_wordlist_input(args)

        offensive_requests: tuple[str, ...] = (
            () if args.passive else ("auto", "wps", "pmkid", "eapol", "crack")
        )

        context = AssessmentContext(
            interface=selected_interface,
            mode=mode,
            target_source=target_source,
            assume_yes=args.assume_yes,
            offensive_requests=offensive_requests,
        )
        environment_notes = validate_environment(mode)

        # Execution plan summary
        print_section("Execution plan")
        print_kv("Mode", mode)
        print_kv("Interface", selected_interface or "auto")
        print_kv("Target", f"{target.display_name} ({target.bssid})")
        print_kv("Selection", target_source)
        print_kv("Workflow", "passive only" if args.passive else "passive + active")
        if wordlist_override:
            print_kv("Wordlist", str(wordlist_override))
        elif not args.passive:
            print_kv("Wordlist", "auto-select")

        scope_message = f"Use target {target.display_name} ({target.bssid})?"
        if not confirm_action(scope_message, assume_yes=context.assume_yes):
            print(yellow("Operation cancelled by user."))
            return 1

        # Passive phase
        findings, vectors = analyze_network(target)
        workspace_manager = WorkspaceManager("workspaces", target.bssid)

        workspace_manager.save_metadata("target_ssid", target.display_name)
        workspace_manager.save_metadata("target_bssid", target.bssid)
        workspace_manager.save_metadata("target_band", target.band)
        workspace_manager.save_metadata("mode", mode)
        workspace_manager.save_metadata("target_source", target_source)
        workspace_manager.save_metadata("offensive_requests", list(offensive_requests))

        detected_profiles = detect_ssid_profiles(target.ssid)
        review_plan = build_review_plan(target)
        workspace_manager.save_metadata("ssid_profiles", [serialize_profile(p) for p in detected_profiles])
        workspace_manager.save_metadata("review_plan", [serialize_plan(p) for p in review_plan])

        if not args.passive:
            offensive_plan = plan_offensive_techniques(target)
            workspace_manager.save_metadata(
                "offensive_plan",
                [serialize_technique_plan(candidate) for candidate in offensive_plan],
            )
            print_section("Offensive route plan")
            for item in offensive_plan:
                plan_state = "proposed" if item.should_attempt else "low confidence"
                print_kv(
                    item.name,
                    f"score={item.score}, threshold={item.threshold}, {plan_state}",
                )

        assessment = AssessmentResult(
            target=target,
            workspace=workspace_manager.workspace_path,
            findings=findings,
            vectors=vectors,
            environment_notes=environment_notes,
        )
        assessment.add_attack_step("Passive analysis completed.")
        if detected_profiles:
            assessment.environment_notes.append(
                "SSID profile matches: " + ", ".join(p.name for p in detected_profiles)
            )

        print_section("Passive phase")
        print_kv("Findings", str(len(findings)))
        print_kv("Risk score", f"{severity_score(findings)}/100")
        print_kv("Workspace", str(workspace_manager.workspace_path.resolve()))

        # Initial report (passive data)
        output_path = Path(args.output)
        html_output_path = Path(args.html_report)
        report_md = build_markdown_report(assessment, networks, context)
        write_report(report_md, output_path)
        inventory_path = write_network_inventory(networks, output_path)
        workspace_manager.save_metadata("markdown_report", str(output_path.resolve()))
        workspace_manager.save_metadata("inventory_file", str(inventory_path.resolve()))
        if not args.no_html:
            write_html_report(build_html_report(assessment, networks, context), html_output_path)
            workspace_manager.save_metadata("html_report", str(html_output_path.resolve()))

        # Active phase
        if not args.passive:
            print_section("Active phase")
            if args.demo:
                print_kv("Mode", "demo simulation")
                run_demo_active_phase(assessment, workspace_manager)
            else:
                print_kv("Mode", "live execution")
                cracked = maybe_run_offensive_extensions(
                    context,
                    assessment.target,
                    workspace_manager=workspace_manager,
                    attack_log=assessment.attack_log,
                    captured_files=assessment.captured_files,
                    wordlist_override=wordlist_override,
                    third_party_results=assessment.third_party_results,
                )
                assessment.active_phase_ran = True
                if cracked:
                    assessment.cracked_password = cracked
                    assessment.add_attack_step("Active module returned a credential successfully.")
                    workspace_manager.save_metadata("compromised", True)
                else:
                    workspace_manager.save_metadata("compromised", False)
        else:
            workspace_manager.save_metadata("compromised", False)

        evaluate_dual_band(assessment, networks, workspace_manager, context)

        # Refresh report with active results
        if assessment.active_phase_ran or assessment.dual_band_result is not None:
            write_report(build_markdown_report(assessment, networks, context), output_path)
            if not args.no_html:
                write_html_report(build_html_report(assessment, networks, context), html_output_path)

        # Finalise workspace metadata and archive
        workspace_manager.save_metadata("attack_log_entries", len(assessment.attack_log))
        workspace_manager.save_metadata("findings_count", len(assessment.findings))
        workspace_manager.save_metadata("risk_score", severity_score(assessment.findings))
        collect_workspace_artifacts(assessment, workspace_manager)
        if assessment.captured_files:
            workspace_manager.save_artifact_index(assessment.captured_files)
        else:
            workspace_manager.save_metadata("captured_files", {})
            workspace_manager.save_metadata("captured_files_count", 0)
        archive_path = workspace_manager.archive_workspace(DEFAULT_ARCHIVE_DIR)
        if archive_path is not None:
            workspace_manager.save_metadata("archive_file", str(archive_path.resolve()))

        # Final summary
        print_section("Final summary")
        print_kv("Target", f"{assessment.target.display_name} ({assessment.target.bssid})")
        print_kv("Findings", str(len(assessment.findings)))
        print_kv("Risk score", f"{severity_score(assessment.findings)}/100")
        print_kv("Workspace", str(assessment.workspace.resolve()))
        print_kv("Inventory", str(inventory_path.resolve()))
        print_kv("Artifacts", str(len(assessment.captured_files)))
        if assessment.dual_band_result is not None:
            print_kv("Dual band", f"sibling on {assessment.dual_band_result.sibling.band}")

        if assessment.is_compromised:
            print_kv("Status", red(f"COMPROMISED  |  password: {assessment.cracked_password}"))
        elif assessment.active_phase_ran:
            print_kv("Status", green("Active phase completed — no credentials recovered"))
        else:
            print_kv("Status", green("Passive analysis only"))

        print_kv("Markdown", str(output_path.resolve()))
        if not args.no_html:
            print_kv("HTML", str(html_output_path.resolve()))
        if archive_path is not None:
            print_kv("Archive", str(archive_path.resolve()))

        return 0

    except RuntimeError as exc:
        log.error("Critical error: %s", exc)
        print(red(f"Error: {exc}"), file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(Path(args.log_file))
    try:
        return run_auditor(args)
    except KeyboardInterrupt:
        print(yellow("\n\nInterrupt detected. Cleaning up and exiting..."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
