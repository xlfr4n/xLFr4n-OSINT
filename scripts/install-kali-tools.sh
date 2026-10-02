#!/usr/bin/env bash
set -u

echo "⚡ xLFr4n // OSINT — Kali external tool setup"
echo

if ! command -v sudo >/dev/null 2>&1; then
  echo "[ERROR] sudo is required for optional APT packages."
  exit 1
fi

sudo apt-get update

install_apt_if_available() {
  local package="$1"
  if apt-cache show "$package" >/dev/null 2>&1; then
    echo "[APT] installing $package"
    sudo apt-get install -y "$package"
  else
    echo "[SKIP] APT package not available: $package"
  fi
}

for package in pipx amass subfinder theharvester spiderfoot exiftool; do
  install_apt_if_available "$package"
done

if command -v pipx >/dev/null 2>&1; then
  pipx ensurepath || true
  export PATH="$HOME/.local/bin:$PATH"
  for package in maigret sherlock-project holehe; do
    echo "[PIPX] installing/updating $package"
    pipx install --force "$package" || echo "[WARN] could not install $package"
  done
else
  echo "[WARN] pipx is unavailable; Maigret/Sherlock/Holehe were not installed."
fi

echo
echo "Run:"
echo "  xlfr4n-osint doctor"
echo
echo "The doctor will show which providers are actually ready."
