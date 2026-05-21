#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="wifisentry"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
THIRD_PARTY_DIR="${PROJECT_ROOT}/third-party"
PROJECT_VENV="${PROJECT_ROOT}/.venv"

KR00K_SCRIPT="${THIRD_PARTY_DIR}/kr00k/malware-research/kr00k/kr00k.py"
DRAGONFORCE_DIR="${THIRD_PARTY_DIR}/dragonforce/dragonforce"
DRAGONFORCE_BUILD_SCRIPT="${DRAGONFORCE_DIR}/build.sh"
DRAGONFORCE_BINARY="${DRAGONFORCE_DIR}/bruter"
FRAGATTACKS_RESEARCH_DIR="${THIRD_PARTY_DIR}/fragattacks/research"
FRAGATTACKS_BUILD_SCRIPT="${FRAGATTACKS_RESEARCH_DIR}/build.sh"
FRAGATTACKS_PYSETUP_SCRIPT="${FRAGATTACKS_RESEARCH_DIR}/pysetup.sh"
FRAGATTACKS_TOOL="${FRAGATTACKS_RESEARCH_DIR}/fragattack.py"
FRAGATTACKS_VENV_PY="${FRAGATTACKS_RESEARCH_DIR}/venv/bin/python"

BASE_REQUIRED_COMMANDS=(
  python3
  git
  nmcli
  iw
  airmon-ng
  airodump-ng
  aireplay-ng
  hcxdumptool
  hcxpcapngtool
  wash
  reaver
  hashcat
  zcat
)

BUILD_REQUIRED_COMMANDS=(
  cmake
  make
  pkg-config
)

SKIP_SYSTEM_INSTALL=0
SKIP_PROJECT_VENV=0
SKIP_THIRD_PARTY=0
SKIP_FRAGATTACKS_BOOTSTRAP=0
SKIP_DRAGONFORCE_BUILD=0

OWNER_USER="${SUDO_USER:-$(id -un)}"

log() {
  printf '[prelaunch] %s\n' "$1"
}

warn() {
  printf '[prelaunch][warn] %s\n' "$1" >&2
}

fail() {
  printf '[prelaunch][error] %s\n' "$1" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: ./prelaunch.sh [options]

Options:
  --skip-system-install          Do not install distro packages.
  --skip-project-venv            Do not create/update the local .venv.
  --skip-third-party             Do not bootstrap third-party integrations.
  --skip-fragattacks-bootstrap   Skip FragAttacks build + Python venv setup.
  --skip-dragonforce-build       Skip dragonforce compilation.
  -h, --help                     Show this help message.
EOF
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --skip-system-install)
        SKIP_SYSTEM_INSTALL=1
        ;;
      --skip-project-venv)
        SKIP_PROJECT_VENV=1
        ;;
      --skip-third-party)
        SKIP_THIRD_PARTY=1
        ;;
      --skip-fragattacks-bootstrap)
        SKIP_FRAGATTACKS_BOOTSTRAP=1
        ;;
      --skip-dragonforce-build)
        SKIP_DRAGONFORCE_BUILD=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "Unknown option: $1"
        ;;
    esac
    shift
  done
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "Run this script with sudo or as root."
  fi
}

run_as_owner() {
  local workdir="$1"
  local command="$2"

  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    runuser -u "${SUDO_USER}" -- bash -lc "cd '$workdir' && $command"
  else
    bash -lc "cd '$workdir' && $command"
  fi
}

ensure_runtime_layout() {
  log "Preparing local project layout..."
  mkdir -p \
    "${THIRD_PARTY_DIR}" \
    "${PROJECT_ROOT}/wordlists" \
    "${PROJECT_ROOT}/logs" \
    "${PROJECT_ROOT}/reports" \
    "${PROJECT_ROOT}/workspaces"
}

detect_distro() {
  if [[ ! -f /etc/os-release ]]; then
    fail "Could not detect the distribution: /etc/os-release is missing."
  fi

  # shellcheck disable=SC1091
  source /etc/os-release

  local distro_like="${ID_LIKE:-}"
  local distro_id="${ID:-}"
  local distro_blob="${distro_id} ${distro_like}"

  case "${distro_blob,,}" in
    *arch*)
      printf 'arch\n'
      ;;
    *fedora*|*rhel*|*centos*)
      printf 'fedora\n'
      ;;
    *debian*|*ubuntu*|*linuxmint*|*pop*)
      printf 'debian\n'
      ;;
    *)
      fail "Distribution not supported automatically: ${distro_id:-unknown}"
      ;;
  esac
}

install_for_debian() {
  log "Updating APT package indexes..."
  apt-get update

  log "Installing dependencies for Debian/Ubuntu..."
  apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    git \
    network-manager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip \
    cmake \
    make \
    pkg-config \
    build-essential \
    libssl-dev \
    libdbus-1-dev \
    libnl-3-dev \
    libnl-genl-3-dev \
    libnl-route-3-dev \
    net-tools \
    macchanger \
    rfkill
}

install_for_fedora() {
  log "Installing dependencies for Fedora..."
  dnf install -y \
    python3 \
    python3-pip \
    git \
    NetworkManager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip \
    cmake \
    make \
    pkgconf-pkg-config \
    gcc \
    gcc-c++ \
    openssl-devel \
    dbus-devel \
    libnl3-devel \
    net-tools \
    macchanger \
    rfkill
}

install_for_arch() {
  log "Synchronizing Arch package databases..."
  pacman -Sy --noconfirm

  log "Installing dependencies for Arch..."
  pacman -S --noconfirm \
    python \
    python-pip \
    git \
    networkmanager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip \
    cmake \
    make \
    pkgconf \
    base-devel \
    openssl \
    dbus \
    libnl \
    net-tools \
    macchanger \
    rfkill
}

verify_commands() {
  local missing=()
  local cmd

  for cmd in "$@"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      missing+=("${cmd}")
    fi
  done

  if ((${#missing[@]} > 0)); then
    warn "Missing commands detected:"
    for cmd in "${missing[@]}"; do
      printf '  - %s\n' "${cmd}" >&2
    done
    return 1
  fi

  return 0
}

bootstrap_project_venv() {
  if [[ "${SKIP_PROJECT_VENV}" -eq 1 ]]; then
    log "Skipping local project venv bootstrap."
    return
  fi

  log "Preparing local Python venv for project-side helpers..."
  run_as_owner "${PROJECT_ROOT}" "python3 -m venv '${PROJECT_VENV}'"
  run_as_owner "${PROJECT_ROOT}" "'${PROJECT_VENV}/bin/pip' install --upgrade pip setuptools wheel"
  run_as_owner "${PROJECT_ROOT}" "'${PROJECT_VENV}/bin/pip' install pycryptodome scapy"
}

bootstrap_fragattacks() {
  if [[ "${SKIP_THIRD_PARTY}" -eq 1 || "${SKIP_FRAGATTACKS_BOOTSTRAP}" -eq 1 ]]; then
    log "Skipping FragAttacks bootstrap."
    return
  fi

  if [[ ! -d "${FRAGATTACKS_RESEARCH_DIR}" ]]; then
    warn "FragAttacks checkout not found at ${FRAGATTACKS_RESEARCH_DIR}."
    return
  fi

  if [[ ! -f "${FRAGATTACKS_BUILD_SCRIPT}" || ! -f "${FRAGATTACKS_PYSETUP_SCRIPT}" ]]; then
    warn "FragAttacks checkout is incomplete. Expected build.sh and pysetup.sh under research/."
    return
  fi

  log "Bootstrapping FragAttacks research environment..."
  run_as_owner "${FRAGATTACKS_RESEARCH_DIR}" "bash './build.sh'"
  run_as_owner "${FRAGATTACKS_RESEARCH_DIR}" "bash './pysetup.sh'"
}

bootstrap_dragonforce() {
  if [[ "${SKIP_THIRD_PARTY}" -eq 1 || "${SKIP_DRAGONFORCE_BUILD}" -eq 1 ]]; then
    log "Skipping dragonforce build."
    return
  fi

  if [[ ! -d "${DRAGONFORCE_DIR}" ]]; then
    warn "dragonforce checkout not found at ${DRAGONFORCE_DIR}."
    return
  fi

  if [[ ! -f "${DRAGONFORCE_BUILD_SCRIPT}" ]]; then
    warn "dragonforce checkout is incomplete. Missing build.sh."
    return
  fi

  log "Building dragonforce binaries..."
  run_as_owner "${DRAGONFORCE_DIR}" "bash './build.sh'"
}

print_third_party_summary() {
  printf '\n'
  log "Third-party readiness summary:"

  if [[ -f "${KR00K_SCRIPT}" ]]; then
    printf '  - kr00k.py: present (%s)\n' "${KR00K_SCRIPT}"
  else
    printf '  - kr00k.py: missing\n'
  fi

  if [[ -f "${DRAGONFORCE_BINARY}" ]]; then
    printf '  - dragonforce bruter: built (%s)\n' "${DRAGONFORCE_BINARY}"
  elif [[ -d "${DRAGONFORCE_DIR}" ]]; then
    printf '  - dragonforce bruter: source present, binary not built\n'
  else
    printf '  - dragonforce bruter: checkout missing\n'
  fi

  if [[ -f "${FRAGATTACKS_TOOL}" ]]; then
    printf '  - fragattack.py: present (%s)\n' "${FRAGATTACKS_TOOL}"
  else
    printf '  - fragattack.py: missing\n'
  fi

  if [[ -x "${FRAGATTACKS_VENV_PY}" ]]; then
    printf '  - FragAttacks Python env: ready (%s)\n' "${FRAGATTACKS_VENV_PY}"
  elif [[ -d "${FRAGATTACKS_RESEARCH_DIR}" ]]; then
    printf '  - FragAttacks Python env: not prepared\n'
  else
    printf '  - FragAttacks Python env: checkout missing\n'
  fi
}

main() {
  parse_args "$@"
  ensure_runtime_layout

  if [[ "${SKIP_SYSTEM_INSTALL}" -eq 0 ]]; then
    need_root
    log "Preparing system dependencies for ${PROJECT_NAME}..."

    local distro
    distro="$(detect_distro)"
    log "Detected distribution: ${distro}"

    case "${distro}" in
      debian)
        install_for_debian
        ;;
      fedora)
        install_for_fedora
        ;;
      arch)
        install_for_arch
        ;;
      *)
        fail "No installer exists for the detected distribution."
        ;;
    esac
  else
    log "Skipping distro package installation."
  fi

  verify_commands "${BASE_REQUIRED_COMMANDS[@]}" || warn "Some base commands are still missing."
  verify_commands "${BUILD_REQUIRED_COMMANDS[@]}" || warn "Some build commands are still missing."

  bootstrap_project_venv
  bootstrap_fragattacks
  bootstrap_dragonforce

  print_third_party_summary

  printf '\n'
  log "Prelaunch completed."
  log "Review the summary above before running live assessments."
}

main "$@"
