from pathlib import Path

APP_NAME = "wifisentry"
APP_VERSION = "5.0.0"

# Default output paths
DEFAULT_REPORT_PATH = Path("reports/wifi_audit_report.md")
DEFAULT_HTML_REPORT_PATH = Path("reports/wifi_audit_report.html")
DEFAULT_LOG_PATH = Path("logs/audit.log")
DEFAULT_ARCHIVE_DIR = Path("reports/evidence_archives")

# Wordlists
# System default — may be gzipped on Kali/Debian, tools_runner handles extraction.
DEFAULT_WORDLIST = Path("/usr/share/wordlists/rockyou.txt")
ISP_WORDLIST = Path("/usr/share/wordlists/diccionarios_wlan/isp_dict.txt")

# Local wordlists directory — scanned automatically before falling back to system paths.
LOCAL_WORDLISTS_DIR = Path("wordlists")

# Execution timeouts (seconds) for active tooling
TIMEOUTS = {
    "wps_pixie": 60,
    "wash_scan": 12,
    "pmkid_capture": 30,
    "client_scan": 12,
    "eapol_deauth": 15,
    "eapol_listen": 20,
    "hash_prep": 30,
}

# Demo mode — simulated step timings (seconds)
DEMO_TIMINGS = {
    "scan": 1.2,
    "analysis": 0.6,
    "wps_attempt": 1.5,
    "pmkid_attempt": 2.0,
    "eapol_attempt": 2.5,
    "hash_prep": 0.8,
    "hashcat_dict": 2.0,
    "hashcat_brute": 1.5,
}

# Demo mode — simulated cracked password displayed in reports and summary.
# Set to None to simulate a run that did not recover a credential.
DEMO_CRACKED_PASSWORD: str | None = "ProfeApruebame123"
