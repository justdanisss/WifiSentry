#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="wifisentry"

REQUIRED_COMMANDS=(
  nmcli
  iw
  airmon-ng
  airodump-ng
  aireplay-ng
  hcxdumptool
  hcxpcapngtool
  reaver
  hashcat
  zcat
)

log() {
  printf '[prelaunch] %s\n' "$1"
}

fail() {
  printf '[prelaunch][error] %s\n' "$1" >&2
  exit 1
}

need_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "Run this script with sudo or as root."
  fi
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
    network-manager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip
}

install_for_fedora() {
  log "Installing dependencies for Fedora..."
  dnf install -y \
    NetworkManager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip
}

install_for_arch() {
  log "Synchronizing Arch package databases..."
  pacman -Sy --noconfirm

  log "Installing dependencies for Arch..."
  pacman -S --noconfirm \
    networkmanager \
    iw \
    aircrack-ng \
    hcxdumptool \
    hcxtools \
    reaver \
    hashcat \
    gzip
}

verify_commands() {
  local missing=()
  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
      missing+=("${cmd}")
    fi
  done

  if ((${#missing[@]} > 0)); then
    printf '\n'
    log "Installation completed, but some commands are still missing:"
    for cmd in "${missing[@]}"; do
      printf '  - %s\n' "${cmd}"
    done
    printf '\n'
    log "Check whether any of those commands require extra repositories or manual installation on your distribution."
    return 1
  fi

  printf '\n'
  log "All primary dependencies are available."
  return 0
}

main() {
  need_root
  log "Preparing dependencies for ${PROJECT_NAME}..."

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

  verify_commands || exit 1

  printf '\n'
  log "Prelaunch completado."
  log "Ya puedes ejecutar el proyecto."
}

main "$@"
