from pathlib import Path

APP_NAME = "wifisentry"
APP_VERSION = "4.0.0"

# Default output paths
DEFAULT_REPORT_PATH = Path("reports/wifi_audit_report.md")
DEFAULT_HTML_REPORT_PATH = Path("reports/wifi_audit_report.html")
DEFAULT_LOG_PATH = Path("logs/audit.log")
DEFAULT_ARCHIVE_DIR = Path("reports/evidence_archives")

# Wordlists
DEFAULT_WORDLIST = Path("/usr/share/wordlists/rockyou.txt")
ISP_WORDLIST = Path("/usr/share/wordlists/diccionarios_wlan/isp_dict.txt")

# Execution timeouts for active tooling
TIMEOUTS = {
    "wps_pixie": 60,
    "pmkid_capture": 30,
    "eapol_deauth": 15,
    "eapol_listen": 20,
    "hash_prep": 30,
}
