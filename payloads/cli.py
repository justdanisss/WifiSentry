from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from payloads.analysis import analyze_network, severity_score
from payloads.config import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_ARCHIVE_DIR,
    DEFAULT_HTML_REPORT_PATH,
    DEFAULT_LOG_PATH,
    DEFAULT_REPORT_PATH,
)
from payloads.models import AssessmentContext, AssessmentResult
from payloads.offensive import maybe_run_offensive_extensions
from payloads.reporting import (
    build_html_report,
    build_markdown_report,
    write_html_report,
    write_network_inventory,
    write_report,
)
from payloads.scanning import (
    demo_networks,
    detect_interfaces,
    scan_networks,
    select_target,
)
from payloads.strategy import build_review_plan, detect_ssid_profiles, serialize_plan, serialize_profile
from payloads.system import check_root, configure_logging, require_command, validate_environment
from payloads.ui import (
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
from payloads.workspace_manager import WorkspaceManager

log = logging.getLogger(__name__)


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


def resolve_interface_input(args: argparse.Namespace) -> str | None:
    """Resolve the WiFi interface. If multiple are detected, ask the user to choose one."""
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
        raise RuntimeError(f"Index out of range. It must be between 1 and {len(interfaces)}.")

    return interfaces[selected_index - 1]


def resolve_target_input(
    args: argparse.Namespace,
    networks: list,
) -> tuple[str | None, str | None, str]:
    """Resolve the target. In live mode, require explicit index selection if no flags are provided."""
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
        raise RuntimeError(f"Index out of range. It must be between 1 and {len(networks)}.")

    selected_network = networks[selected_index - 1]
    return selected_network.ssid, selected_network.bssid, f"interactive index {selected_index}"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="wifisentry: defensive assessment and active validation toolkit."
    )
    parser.add_argument("-i", "--interface", help="WiFi interface to use, for example wlan0.")
    parser.add_argument("--ssid", help="Target SSID.")
    parser.add_argument("--bssid", help="Target BSSID. Takes precedence over SSID.")

    parser.add_argument("-p", "--passive", action="store_true", help="Passive mode: scan and risk analysis only.")
    parser.add_argument("-d", "--demo", action="store_true", help="Demo mode: simulated lab data and workflow.")

    parser.add_argument("-o", "--output", default=str(DEFAULT_REPORT_PATH), help="Markdown report output path.")
    parser.add_argument("--html-report", default=str(DEFAULT_HTML_REPORT_PATH), help="HTML report output path.")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report generation.")

    parser.add_argument("--list-interfaces", action="store_true", help="List detected WiFi interfaces and exit.")
    parser.add_argument("--list-networks", action="store_true", help="List detected WiFi networks and exit.")
    parser.add_argument("--assume-yes", action="store_true", help="Skip the interactive confirmation prompt.")
    parser.add_argument("--log-file", default=str(DEFAULT_LOG_PATH), help="Log file path.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")

    return parser.parse_args(argv)


def run_auditor(args: argparse.Namespace) -> int:
    try:
        print_banner(APP_NAME, APP_VERSION)

        if not args.demo and not args.list_interfaces:
            require_command("nmcli")

        if not args.demo and not args.list_interfaces and not args.passive and not check_root():
            log.warning("Running without root privileges; the active phase may be limited.")

        if args.list_interfaces:
            interfaces = detect_interfaces()
            if not interfaces:
                print(yellow("No WiFi interfaces were detected."))
                return 1
            print(format_interfaces(interfaces))
            return 0

        selected_interface = resolve_interface_input(args)

        if args.demo:
            networks = demo_networks()
            mode = "demo"
        else:
            networks = scan_networks(selected_interface)
            mode = "live scan"

        if args.list_networks:
            print(format_network_table(networks))
            return 0

        target_ssid, target_bssid, target_source = resolve_target_input(args, networks)
        target = select_target(networks, ssid=target_ssid, bssid=target_bssid)

        offensive_requests = () if args.passive else ("auto", "wps", "pmkid", "eapol", "crack")

        context = AssessmentContext(
            interface=selected_interface,
            mode=mode,
            target_source=target_source,
            assume_yes=args.assume_yes,
            offensive_requests=offensive_requests,
        )
        environment_notes = validate_environment(mode)

        print_section("Execution plan")
        print_kv("Mode", mode)
        print_kv("Interface", selected_interface or "auto")
        print_kv("Target", f"{target.display_name} ({target.bssid})")
        print_kv("Selection", target_source)
        print_kv("Workflow", "passive only" if args.passive else "passive + active")

        scope_message = f"Use target {target.display_name} ({target.bssid})?"
        if not confirm_action(scope_message, assume_yes=context.assume_yes):
            print(yellow("Operation cancelled by user."))
            return 1

        findings, vectors = analyze_network(target)
        workspace_manager = WorkspaceManager("workspaces", target.bssid)

        workspace_manager.save_metadata("target_ssid", target.display_name)
        workspace_manager.save_metadata("target_bssid", target.bssid)
        workspace_manager.save_metadata("mode", mode)
        workspace_manager.save_metadata("target_source", target_source)
        workspace_manager.save_metadata("offensive_requests", list(offensive_requests))

        detected_profiles = detect_ssid_profiles(target.ssid)
        review_plan = build_review_plan(target)
        workspace_manager.save_metadata(
            "ssid_profiles",
            [serialize_profile(profile) for profile in detected_profiles],
        )
        workspace_manager.save_metadata(
            "review_plan",
            [serialize_plan(plan) for plan in review_plan],
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
                "SSID profile matches: " + ", ".join(profile.name for profile in detected_profiles)
            )

        print_section("Passive phase")
        print_kv("Findings", str(len(findings)))
        print_kv("Risk score", f"{severity_score(findings)}/100")
        print_kv("Workspace", str(workspace_manager.workspace_path.resolve()))

        output_path = Path(args.output)
        report_md = build_markdown_report(assessment, networks, context)
        write_report(report_md, output_path)
        inventory_path = write_network_inventory(networks, output_path)
        workspace_manager.save_metadata("markdown_report", str(output_path.resolve()))
        workspace_manager.save_metadata("inventory_file", str(inventory_path.resolve()))
        html_output_path = Path(args.html_report)
        if not args.no_html:
            write_html_report(build_html_report(assessment, networks, context), html_output_path)
            workspace_manager.save_metadata("html_report", str(html_output_path.resolve()))

        if not args.passive:
            if args.demo:
                log.info("Simulating active workflow in demo mode...")
                print_section("Active phase")
                print_kv("Mode", "demo simulation")
                time.sleep(2)
                assessment.cracked_password = "ProfeApruebame123"
                assessment.add_attack_step("Demo mode: simulated credential recovered.")
                workspace_manager.save_metadata("compromised", True)
            else:
                print_section("Active phase")
                print_kv("Mode", "live execution")
                cracked = maybe_run_offensive_extensions(
                    context,
                    assessment.target,
                    workspace_manager=workspace_manager,
                    attack_log=assessment.attack_log,
                    captured_files=assessment.captured_files,
                )
                if cracked:
                    assessment.cracked_password = cracked
                    assessment.add_attack_step("Active module returned a credential successfully.")
                    workspace_manager.save_metadata("compromised", True)
                else:
                    workspace_manager.save_metadata("compromised", False)
        else:
            workspace_manager.save_metadata("compromised", False)

        if assessment.is_compromised:
            final_report = build_markdown_report(assessment, networks, context)
            write_report(final_report, output_path)
            if not args.no_html:
                write_html_report(build_html_report(assessment, networks, context), html_output_path)

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

        print_section("Final summary")
        print_kv("Target", f"{assessment.target.display_name} ({assessment.target.bssid})")
        print_kv("Findings", str(len(assessment.findings)))
        print_kv("Risk score", f"{severity_score(assessment.findings)}/100")
        print_kv("Workspace", str(assessment.workspace.resolve()))
        print_kv("Inventory", str(inventory_path.resolve()))
        print_kv("Artifacts", str(len(assessment.captured_files)))
        if assessment.is_compromised:
            print_kv("Status", red(f"COMPROMISED  |  password: {assessment.cracked_password}"))
        else:
            print_kv("Status", green("No credentials were recovered"))
        print_kv("Markdown", str(output_path.resolve()))
        if not args.no_html:
            print_kv("HTML", str(html_output_path.resolve()))
        if archive_path is not None:
            print_kv("Archive", str(archive_path.resolve()))

        return 0

    except RuntimeError as exc:
        log.error(f"Critical error: {exc}")
        print(red(f"Error: {exc}"), file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    configure_logging(Path(args.log_file))
    try:
        return run_auditor(args)
    except KeyboardInterrupt:
        print(yellow("\n\nInterrupt detected. Cleaning up state and exiting..."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
