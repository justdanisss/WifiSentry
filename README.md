# wifisentry

`wifisentry` is a Python-based WiFi assessment toolkit for controlled and authorized environments. It combines passive inventory, beacon-level risk analysis, SSID/vendor profile enrichment, structured reporting, workspace-based evidence collection, and a modular active validation pipeline intended for lab use.

The internal Python package lives under `core/`.

Advanced research-backed modules can be checked out locally under `third-party/`. They are treated as optional integrations and are not bundled in the tracked repository tree.

## Features

- Passive WiFi inventory using `nmcli`
- Interface and target selection by SSID, BSSID, or interactive index
- WiFi band inference (`2.4GHz` / `5GHz`) from channel data
- WPS enrichment using `wash`, including hidden WPS detection and locked/unlocked tagging
- Beacon-level findings for open, WEP, WPS, hidden SSID, vendor-style naming, and WPA3 transition mode
- SSID profile detection with documentary review plans
- Local wordlist selection with CLI override and system fallback
- Active validation routes for WPS Pixie Dust, PMKID capture, EAPOL capture, and Hashcat
- Client detection before the EAPOL deauthentication path
- Dual-band sibling detection and optional PSK parity verification when a credential is recovered
- Research-module planning for `kr00k`, WPA3/Dragonblood-style assessment, and FragAttacks-style checks
- Markdown and HTML reporting
- Per-target workspace isolation, artifact indexing, metadata persistence, and evidence archive generation
- Demo mode for walkthroughs and presentations

## Project Structure

```text
.
├── main.py
├── prelaunch.sh
├── README.md
├── LICENSE
├── wordlists
│   └── .gitkeep
├── third-party              # local, optional, gitignored research checkouts
└── core
    ├── analysis.py
    ├── cli.py
    ├── config.py
    ├── demo.py
    ├── models.py
    ├── offensive.py
    ├── planning.py
    ├── radio.py
    ├── reporting.py
    ├── scanning.py
    ├── strategy.py
    ├── system.py
    ├── third_party.py
    ├── tools_runner.py
    ├── ui.py
    └── workspace_manager.py
```

## Installation

The repository includes a `prelaunch.sh` helper that detects Debian/Ubuntu, Fedora, or Arch-based systems and installs the primary system dependencies used by the project.

```bash
sudo ./prelaunch.sh
```

The helper checks for tools such as `nmcli`, `iw`, `aircrack-ng`, `hcxdumptool`, `hcxtools`, `reaver`, `hashcat`, `wash`, and `gzip`. If your distribution packages any of them differently, the script reports the missing commands after installation.

`prelaunch.sh` also prepares the local `third-party/` layout used for optional research integrations. Those upstream repositories are expected to be cloned locally when you want to enable that layer.

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

### Choose a wordlist explicitly

```bash
python3 main.py --ssid "ExampleNetwork" --wordlist ./wordlists/custom.lst
```

### List available interfaces

```bash
python3 main.py --list-interfaces
```

### List detected networks

```bash
python3 main.py --list-networks
```

### Skip prompts

```bash
python3 main.py --passive --ssid "ExampleNetwork" --assume-yes
```

## Workflow Summary

### Passive workflow

1. Detect interfaces and scan nearby networks with `nmcli`
2. Enrich scan results with `wash` when available to flag hidden or locked WPS
3. Select the target by SSID, BSSID, or interactive menu
4. Analyze beacon metadata and build findings plus documentary review plans
5. Generate Markdown and HTML reports, workspace metadata, and inventory output

### Active workflow

When active mode is enabled, the tool:

1. Switches the chosen interface into monitor mode
2. Checks for visible or hidden WPS metadata and attempts the WPS Pixie Dust path when relevant
3. Falls back to PMKID capture for WPA/WPA2 targets
4. Uses client detection before attempting the EAPOL deauthentication path
5. Prepares hash material and runs Hashcat using the selected or resolved wordlist
6. Builds a technique plan with confidence scoring and only enables routes that clear the planner threshold
7. Optionally runs locally-available research modules when the target appears relevant and the required third-party tooling is present
8. Optionally compares same-SSID sibling radios on the other band when a credential is recovered

## Conditional Technique Planning

The active pipeline is not intended to launch every route indiscriminately. Before the validation phase, `wifisentry` builds a scored technique plan in `core/planning.py`.

Each candidate path is evaluated on:

- observed security capabilities
- signal quality
- SSID/vendor-style hints
- expected noise and operational cost
- expected payoff for the current target

Today the planner exposes a `should_attempt` decision per technique. In practice, that means research-backed modules such as `kr00k`, WPA3/Dragonblood-oriented assessment, and FragAttacks-style checks are only considered when the target looks relevant enough and the module is locally available.

This keeps the workflow more explainable, reduces unnecessary noise, and makes reports clearer about why a route was proposed, skipped, or attempted.

## Third-Party Research Modules

`wifisentry` can integrate several upstream research projects through `core/third_party.py`. These live under the local `third-party/` directory and are intentionally excluded from Git tracking.

Current families:

- `fragattacks`
  - upstream: `https://github.com/vanhoefm/fragattacks`
  - local path: `third-party/fragattacks`
  - role in `wifisentry`: research-backed protocol assessment and environment-readiness checks for fragmentation and aggregation related validation flows

- `dragonforce`
  - upstream:
    - `https://github.com/vanhoefm/dragonforce`
  - local path: `third-party/dragonforce/`
  - role in `wifisentry`: WPA3/SAE-oriented research assessment and optional timing-oriented validation paths when WPA3-relevant signals are present

- `kr00k`
  - upstream:
    - `https://github.com/eset/malware-research/tree/master/kr00k`
  - local path: `third-party/kr00k/`
  - role in `wifisentry`: offline research assessment through `kr00k.py` when suitable capture material is available

These integrations are optional and environment-dependent. Some require compiled binaries, Python dependencies, or lab-specific wireless support beyond the baseline package installation.

## Reporting

Each run can produce:

- a Markdown report
- an HTML report
- a network inventory file
- workspace metadata
- indexed artifacts
- a compressed evidence archive

Reports include the target band, nearby network bands, SSID profile matches, review plans, attack log entries, artifact metadata, and dual-band sibling information when applicable.

When third-party modules are present, reports can also include a dedicated section that records:

- which research modules were considered
- whether they were attempted
- whether prerequisites were missing
- what evidence or notes were produced

Artifacts and execution metadata are stored per target inside `workspaces/<BSSID>/`.

## Wordlists

Wordlists are resolved in this order:

1. `--wordlist` CLI flag
2. interactive selection from `./wordlists/`
3. ISP-specific dictionary when the SSID matches supported operator patterns
4. system default `rockyou.txt` or its gzipped form

## SSID Profiles and Review Plans

The profile engine in `strategy.py` maps SSID naming patterns to documentary profiles and review plans. These enrich metadata and reporting with:

- detected vendor or ISP naming patterns
- profile-specific notes
- recommended validation steps
- ordered review plans

## Notes

- Demo mode simulates the active workflow for presentation purposes.
- Live mode depends on external tools, driver support, monitor mode support, and compatible wireless hardware.
- Client detection is used to avoid the EAPOL path when no associated stations are seen.
- Dual-band verification only runs when a same-SSID sibling is found and a credential has already been recovered.
- Third-party research modules are local optional checkouts and are only useful when their own prerequisites, build steps, and target signals line up.
- Generated workspaces can be archived automatically for evidence retention.

## Acknowledgements

`wifisentry` builds on ideas, tooling, and public research from several upstream projects that are cloned locally under `third-party/` when this optional layer is enabled.

Thanks to the original authors and maintainers of these projects for publishing their work and making it possible to build richer WiFi assessment workflows on top of it.

- Mathy Vanhoef's `fragattacks` research suite
  - `https://github.com/vanhoefm/fragattacks`
  - used as a reference and optional local integration point for fragmentation and aggregation related protocol assessment

- Mathy Vanhoef's `dragonforce`
  - `https://github.com/vanhoefm/dragonforce`
  - used as the optional local integration point for WPA3/SAE-oriented research assessment

- ESET Malware Research `kr00k.py`
  - `https://github.com/eset/malware-research/tree/master/kr00k`
  - used directly as the optional offline analysis component for Kr00k-family conditions

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for the full text.

## Disclaimer

This software is provided for educational, research, and authorized assessment use only.

The author assumes no responsibility for misuse, damage, legal consequences, service disruption, data loss, or any other outcome resulting from the use of this project. You are solely responsible for ensuring that your use complies with applicable laws, regulations, contracts, and authorization requirements.
