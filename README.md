# WifiSentry

WifiSentry is a Python-based toolkit for WiFi assessment workflows in controlled and authorized environments. It combines passive network inventory, configuration risk analysis, structured reporting, workspace-based evidence collection, and an active validation pipeline designed for lab use.

The project is organized as a modular package so scanning, analysis, reporting, workspace management, and active routines can evolve independently without turning the codebase into a monolith.

## Features

- Passive WiFi inventory using `nmcli`
- Target selection by SSID, BSSID, or interactive index selection
- Risk analysis for common beacon-level findings
- SSID profile detection with documentary review plans
- Markdown and HTML reporting
- Per-target workspace isolation
- Structured metadata and artifact indexing
- Evidence archive generation for completed runs
- Demo mode for walkthroughs and presentations

## Project Structure

```text
.
├── main.py
├── prelaunch.sh
├── README.md
└── payloads
    ├── analysis.py
    ├── cli.py
    ├── config.py
    ├── models.py
    ├── offensive.py
    ├── reporting.py
    ├── scanning.py
    ├── strategy.py
    ├── system.py
    ├── ui.py
    └── workspace_manager.py
```

## Installation

The repository includes a `prelaunch.sh` helper that detects Debian/Ubuntu, Fedora, or Arch-based systems and installs the primary system dependencies required by the project.

```bash
sudo ./prelaunch.sh
```

If your distribution packages some tools differently, the script will report any missing commands after installation.

## Usage

### Demo mode

```bash
python3 main.py --demo
```

### Passive mode

```bash
python3 main.py --passive
```

### Target a specific SSID

```bash
python3 main.py --ssid "ExampleNetwork"
```

### Target a specific BSSID

```bash
python3 main.py --bssid AA:BB:CC:DD:EE:FF
```

### List available interfaces

```bash
python3 main.py --list-interfaces
```

### List detected networks

```bash
python3 main.py --list-networks
```

## Reporting

Each run can produce:

- a Markdown report
- an HTML report
- a network inventory file
- workspace metadata
- indexed artifacts
- a compressed evidence archive

Artifacts and execution metadata are stored per target inside `workspaces/<BSSID>/`.

## SSID Profiles and Review Plans

The project includes a profile engine in `strategy.py` that maps SSID naming patterns to documentary profiles and review plans. These profiles are used to enrich metadata and reporting with:

- detected vendor or ISP naming patterns
- profile-specific notes
- recommended validation steps
- ordered review plans

This layer is intentionally separate from scanning and reporting so it can evolve independently.

## Notes

- Demo mode simulates the active workflow for presentation purposes.
- Live mode depends on the availability of the required external tools and wireless hardware support.
- Generated workspaces can be archived automatically for evidence retention.

## License

No license has been defined yet. Add one before public distribution if needed.
