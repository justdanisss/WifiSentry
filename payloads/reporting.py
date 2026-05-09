from __future__ import annotations

import datetime as dt
import html
import json
from pathlib import Path
from typing import Any

from payloads.config import APP_NAME, APP_VERSION
from payloads.analysis import classify_risk, severity_score
from payloads.models import AssessmentContext, AssessmentResult, WifiNetwork
from payloads.scanning import list_networks


def executive_summary(assessment: AssessmentResult, score: int) -> str:
    critical_or_high = [f for f in assessment.findings if f.severity in {"Critical", "High"}]
    if critical_or_high:
        return (
            f"The target network `{assessment.target.display_name}` has {len(critical_or_high)} "
            f"high-impact finding(s). The current risk score is `{score}/100`; remediation "
            "should prioritize encryption mode, WPS exposure, and password policy."
        )
    return (
        f"The target network `{assessment.target.display_name}` does not expose obvious high-impact "
        f"issues in beacon-level metadata. The current risk score is `{score}/100`."
    )


def escape_markdown_table(value: str) -> str:
    return value.replace("|", "\\|")


def load_artifact_index(assessment: AssessmentResult) -> dict[str, dict[str, Any]]:
    metadata_path = assessment.workspace / "execution_meta.json"
    if metadata_path.exists():
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
            artifact_index = payload.get("captured_files")
            if isinstance(artifact_index, dict):
                return artifact_index
        except (json.JSONDecodeError, OSError):
            pass

    artifact_index: dict[str, dict[str, Any]] = {}
    for artifact_name, artifact_path in assessment.captured_files.items():
        if not artifact_path.exists() or not artifact_path.is_file():
            continue
        try:
            stat = artifact_path.stat()
        except OSError:
            continue
        artifact_index[artifact_name] = {
            "name": artifact_name,
            "path": str(artifact_path.resolve()),
            "filename": artifact_path.name,
            "size_bytes": stat.st_size,
            "modified_at": dt.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "suffix": artifact_path.suffix,
        }
    return artifact_index


def load_workspace_metadata(assessment: AssessmentResult) -> dict[str, Any]:
    metadata_path = assessment.workspace / "execution_meta.json"
    if not metadata_path.exists():
        return {}
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def build_markdown_report(
    assessment: AssessmentResult,
    all_networks: list[WifiNetwork],
    context: AssessmentContext,
    include_trophy: bool = True
) -> str:
    """Construye el informe en texto plano Markdown."""
    generated_at = dt.datetime.now().astimezone().isoformat(timespec="seconds")
    score = severity_score(assessment.findings)
    risk_level = classify_risk(score)

    lines = [f"# {APP_NAME} Report\n"]

    # Trophy block
    if assessment.is_compromised and include_trophy:
        lines.extend([
            "## 🚨 STATUS: NETWORK COMPROMISED 🚨",
            "",
            "> **Attention:** The active validation workflow recovered the network access credential.",
            "> ",
            f"> **Recovered password:** `{assessment.cracked_password}`",
            "",
            "---",
            ""
        ])

    lines.extend([
        f"- Generated at: `{generated_at}`",
        f"- Version: `{APP_VERSION}`",
        f"- Mode: `{context.mode}`",
        f"- Interface: `{context.interface or 'not specified'}`",
        f"- Target selection: `{context.target_source}`",
        f"- Target SSID: `{assessment.target.display_name}`",
        f"- Target BSSID: `{assessment.target.bssid}`",
        f"- Channel: `{assessment.target.channel}`",
        f"- Signal: `{assessment.target.signal}%`",
        f"- Security: `{assessment.target.security}`",
        f"- Risk score: `{score}/100`",
        f"- Risk level: `{risk_level}`",
        "",
    ])

    if assessment.environment_notes:
        lines.extend(["## Environment Notes", ""])
        for note in assessment.environment_notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.extend([
        "## Executive Summary", "",
        executive_summary(assessment, score), "",
        "## Findings", ""
    ])

    for index, finding in enumerate(assessment.findings, start=1):
        lines.extend([
            f"### {index}. {finding.title}", "",
            f"- Severity: `{finding.severity}`",
            f"- Evidence: {finding.evidence}",
            f"- Recommendation: {finding.recommendation}",
        ])
        if finding.references:
            lines.append(f"- References: {', '.join(finding.references)}")
        lines.append("")

    # Attack log
    if assessment.attack_log:
        lines.extend([
            "## Attack Log", "",
        ])
        for step in assessment.attack_log:
            lines.append(f"- {step}")
        lines.append("")

    metadata = load_workspace_metadata(assessment)
    ssid_profiles = metadata.get("ssid_profiles", [])
    if ssid_profiles:
        lines.extend([
            "## SSID Profiles", "",
            "| Profile | Vendor | Priority | Match Mode |",
            "| --- | --- | ---: | --- |",
        ])
        for profile in ssid_profiles:
            lines.append(
                f"| {escape_markdown_table(str(profile.get('name', 'n/a')))} | "
                f"{escape_markdown_table(str(profile.get('vendor', 'n/a')))} | "
                f"{profile.get('priority', 'n/a')} | "
                f"{escape_markdown_table(str(profile.get('match_mode', 'n/a')))} |"
            )
        lines.append("")
        for profile in ssid_profiles:
            lines.extend([
                f"### {profile.get('name', 'Unnamed Profile')}",
                "",
                f"- Vendor: `{profile.get('vendor', 'n/a')}`",
                f"- Match mode: `{profile.get('match_mode', 'n/a')}`",
                f"- Priority: `{profile.get('priority', 'n/a')}`",
            ])
            notes = profile.get("notes", [])
            if notes:
                lines.append("- Notes:")
                for note in notes:
                    lines.append(f"  - {note}")
            recommendations = profile.get("recommendations", [])
            if recommendations:
                lines.append("- Recommendations:")
                for recommendation in recommendations:
                    lines.append(f"  - {recommendation}")
            lines.append("")

    review_plan = metadata.get("review_plan", [])
    if review_plan:
        lines.extend([
            "## Review Plan", "",
            "| Step | Kind | Priority | Source Profile |",
            "| --- | --- | ---: | --- |",
        ])
        for plan in review_plan:
            lines.append(
                f"| {escape_markdown_table(str(plan.get('name', 'n/a')))} | "
                f"{escape_markdown_table(str(plan.get('kind', 'n/a')))} | "
                f"{plan.get('priority', 'n/a')} | "
                f"{escape_markdown_table(str(plan.get('source_profile', 'n/a')))} |"
            )
        lines.append("")
        for plan in review_plan:
            lines.extend([
                f"### {plan.get('name', 'Unnamed Step')}",
                "",
                f"- Description: {plan.get('description', 'n/a')}",
                f"- Priority: `{plan.get('priority', 'n/a')}`",
                f"- Source profile: `{plan.get('source_profile', 'n/a')}`",
            ])
            notes = plan.get("notes", [])
            if notes:
                lines.append("- Notes:")
                for note in notes:
                    lines.append(f"  - {note}")
            lines.append("")

    artifact_index = load_artifact_index(assessment)
    if artifact_index:
        lines.extend([
            "## Artifacts", "",
            "| Artifact | File | Size | Modified | Type |",
            "| --- | --- | ---: | --- | --- |",
        ])
        for artifact_name, artifact_info in artifact_index.items():
            lines.append(
                f"| {escape_markdown_table(str(artifact_name))} | "
                f"{escape_markdown_table(str(artifact_info.get('filename', 'n/a')))} | "
                f"{artifact_info.get('size_bytes', 0)} B | "
                f"{escape_markdown_table(str(artifact_info.get('modified_at', 'n/a')))} | "
                f"{escape_markdown_table(str(artifact_info.get('suffix', 'n/a')))} |"
            )
        lines.append("")
        for artifact_name, artifact_info in artifact_index.items():
            lines.extend([
                f"### {artifact_name}",
                "",
                f"- Path: `{artifact_info.get('path', 'n/a')}`",
                f"- Filename: `{artifact_info.get('filename', 'n/a')}`",
                f"- Size: `{artifact_info.get('size_bytes', 0)} bytes`",
                f"- Modified: `{artifact_info.get('modified_at', 'n/a')}`",
                f"- Type: `{artifact_info.get('suffix', 'n/a')}`",
                "",
            ])

    lines.extend([
        "## Documented Vectors", "",
        "| Vector | Feasible | Difficulty | Tools |",
        "| --- | --- | --- | --- |",
    ])
    if assessment.vectors:
        for vector in assessment.vectors:
            lines.append(
                f"| {escape_markdown_table(vector.name)} | "
                f"{'Yes' if vector.feasible else 'Conditional'} | "
                f"{vector.difficulty} | {', '.join(vector.tools)} |"
            )
        lines.append("")
        for vector in assessment.vectors:
            lines.extend(["### " + vector.name, "", vector.description, ""])
    else:
        lines.extend(["No documented vectors were added for this target.", ""])

    lines.extend([
        "## Nearby Networks", "",
        "| SSID | BSSID | Channel | Signal | Security |",
        "| --- | --- | --- | ---: | --- |",
    ])
    for network in all_networks:
        lines.append(
            f"| {escape_markdown_table(network.display_name)} | {network.bssid} | "
            f"{network.channel} | {network.signal}% | {escape_markdown_table(network.security)} |"
        )

    lines.extend([
        "", "## Scope Notes", "",
        "- This report is based on passive network metadata, local system inventory, and authorized active offensive routines.",
        "- Any deeper validation must be explicitly authorized, isolated to a lab network, and documented by the student/operator.",
        ""
    ])
    return "\n".join(lines)


def build_html_report(assessment: AssessmentResult, all_networks: list[WifiNetwork], context: AssessmentContext) -> str:
    """Construye un documento HTML estructurado de forma nativa y robusta."""
    
    # Generamos el markdown interno SIN el trofeo (para no duplicarlo)
    raw_markdown = build_markdown_report(assessment, all_networks, context, include_trophy=False)
    html_body = html.escape(raw_markdown)
    score = severity_score(assessment.findings)
    score_label = classify_risk(score)
    score_color = "#dc2626" if score >= 60 else "#d97706" if score >= 25 else "#16a34a"
    
    # Construimos el bloque HTML del trofeo de forma limpia
    trophy_html = ""
    if assessment.is_compromised:
        trophy_html = f"""
        <div class="alert">
            <h2 style="margin-top: 0;">🚨 STATUS: NETWORK COMPROMISED 🚨</h2>
            <p><strong>Attention:</strong> The active validation workflow recovered the network access credential.</p>
            <p style="font-size: 1.1em; margin-bottom: 0;">
                <strong>Recovered password:</strong> 
                <code style="background: #fecaca; padding: 0.2rem 0.4rem; border-radius: 4px; color: #7f1d1d;">{html.escape(assessment.cracked_password)}</code>
            </p>
        </div>
        """

    attack_log_html = ""
    if assessment.attack_log:
        attack_log_items = "".join(
            f"<li>{html.escape(step)}</li>" for step in assessment.attack_log
        )
        attack_log_html = f"""
        <div class="panel">
            <h2>Attack Log</h2>
            <ul>{attack_log_items}</ul>
        </div>
        """

    metadata = load_workspace_metadata(assessment)
    ssid_profiles = metadata.get("ssid_profiles", [])
    profiles_html = ""
    if ssid_profiles:
        profile_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(profile.get('name', 'n/a')))}</td>"
                f"<td>{html.escape(str(profile.get('vendor', 'n/a')))}</td>"
                f"<td>{html.escape(str(profile.get('priority', 'n/a')))}</td>"
                f"<td>{html.escape(str(profile.get('match_mode', 'n/a')))}</td>"
                "</tr>"
            )
            for profile in ssid_profiles
        )
        profiles_html = f"""
        <div class="panel">
            <h2>SSID Profiles</h2>
            <table class="artifact-table">
                <thead>
                    <tr>
                        <th>Profile</th>
                        <th>Vendor</th>
                        <th>Priority</th>
                        <th>Match Mode</th>
                    </tr>
                </thead>
                <tbody>
                    {profile_rows}
                </tbody>
            </table>
        </div>
        """

    review_plan = metadata.get("review_plan", [])
    review_plan_html = ""
    if review_plan:
        plan_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(plan.get('name', 'n/a')))}</td>"
                f"<td>{html.escape(str(plan.get('kind', 'n/a')))}</td>"
                f"<td>{html.escape(str(plan.get('priority', 'n/a')))}</td>"
                f"<td>{html.escape(str(plan.get('source_profile', 'n/a')))}</td>"
                "</tr>"
            )
            for plan in review_plan
        )
        review_plan_html = f"""
        <div class="panel">
            <h2>Review Plan</h2>
            <table class="artifact-table">
                <thead>
                    <tr>
                        <th>Step</th>
                        <th>Kind</th>
                        <th>Priority</th>
                        <th>Source Profile</th>
                    </tr>
                </thead>
                <tbody>
                    {plan_rows}
                </tbody>
            </table>
        </div>
        """

    artifact_index = load_artifact_index(assessment)
    artifacts_html = ""
    if artifact_index:
        artifact_rows = "".join(
            (
                "<tr>"
                f"<td>{html.escape(str(name))}</td>"
                f"<td>{html.escape(str(info.get('filename', 'n/a')))}</td>"
                f"<td>{html.escape(str(info.get('size_bytes', 0)))} B</td>"
                f"<td>{html.escape(str(info.get('modified_at', 'n/a')))}</td>"
                f"<td>{html.escape(str(info.get('suffix', 'n/a')))}</td>"
                "</tr>"
            )
            for name, info in artifact_index.items()
        )
        artifacts_html = f"""
        <div class="panel">
            <h2>Artifacts</h2>
            <table class="artifact-table">
                <thead>
                    <tr>
                        <th>Artifact</th>
                        <th>File</th>
                        <th>Size</th>
                        <th>Modified</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
                    {artifact_rows}
                </tbody>
            </table>
        </div>
        """

    html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{APP_NAME} Report</title>
  <style>
    :root {{ color-scheme: light; }}
    body {{ font-family: Arial, sans-serif; margin: 2rem auto; max-width: 1080px; line-height: 1.5; color: #1f2937; background: #f8fafc; }}
    .shell {{ background: white; border: 1px solid #dbe4ee; border-radius: 12px; overflow: hidden; box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08); }}
    .topbar {{ padding: 1rem 1.25rem; background: #0f172a; color: white; font-weight: 700; }}
    .summary {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem; padding: 1.5rem; border-bottom: 1px solid #e5e7eb; }}
    .stat {{ background: #f8fafc; border: 1px solid #e5e7eb; border-radius: 10px; padding: 1rem; }}
    .stat-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.04em; color: #64748b; }}
    .stat-value {{ font-size: 1rem; margin-top: 0.35rem; color: #0f172a; font-weight: 700; word-break: break-word; }}
    .score {{ color: {score_color}; }}
    .alert {{ background-color: #fee2e2; border-left: 4px solid #ef4444; padding: 1.5rem; margin: 1.5rem; color: #991b1b; border-radius: 0 8px 8px 0; }}
    .alert h2 {{ color: #7f1d1d; }}
    .panel {{ margin: 0 1.5rem 1.5rem 1.5rem; padding: 1.25rem; border: 1px solid #e5e7eb; border-radius: 8px; background: white; }}
    .panel h2 {{ margin-top: 0; font-size: 1rem; }}
    .panel ul {{ margin: 0; padding-left: 1.25rem; }}
    .artifact-table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
    .artifact-table th, .artifact-table td {{ text-align: left; padding: 0.6rem 0.75rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    .artifact-table th {{ background: #f8fafc; color: #475569; font-size: 0.78rem; text-transform: uppercase; }}
    pre {{ white-space: pre-wrap; margin: 0 1.5rem 1.5rem 1.5rem; background: white; padding: 1.25rem; overflow: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; border: 1px solid #e5e7eb; border-radius: 8px; }}
  </style>
</head>
<body>
  <div class="shell">
    <div class="topbar">{APP_NAME} v{APP_VERSION}</div>
    <div class="summary">
      <div class="stat"><div class="stat-label">Target</div><div class="stat-value">{html.escape(assessment.target.display_name)}</div></div>
      <div class="stat"><div class="stat-label">BSSID</div><div class="stat-value">{html.escape(assessment.target.bssid)}</div></div>
      <div class="stat"><div class="stat-label">Mode</div><div class="stat-value">{html.escape(context.mode)}</div></div>
      <div class="stat"><div class="stat-label">Risk</div><div class="stat-value score">{score}/100 ({html.escape(score_label)})</div></div>
    </div>
    {trophy_html}
    {attack_log_html}
    {profiles_html}
    {review_plan_html}
    {artifacts_html}
    <pre>{html_body}</pre>
  </div>
</body>
</html>"""
    return html_document


def write_report(report: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")


def write_html_report(html_content: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_content, encoding="utf-8")


def write_network_inventory(networks: list[WifiNetwork], output_path: Path) -> Path:
    inventory_path = output_path.with_name(f"{output_path.stem}_inventory.txt")
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(list_networks(networks) + "\n", encoding="utf-8")
    return inventory_path
