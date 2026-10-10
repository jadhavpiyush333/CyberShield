#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential git
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
mkdir -p data/raw data/processed models reports logs
cp -n .env.example .env 2>/dev/null || true
python -m pytest -q
if command -v systemctl >/dev/null 2>&1 && [ "${EUID}" -eq 0 ]; then
  RUN_USER="${SUDO_USER:-root}"
  sed -e "s#__ROOT__#$ROOT#g" -e "s#__RUN_USER__#$RUN_USER#g" deployment/kali/cybershield.service.template | sudo tee /etc/systemd/system/cybershield.service >/dev/null
  sudo systemctl daemon-reload
  echo "System service installed: sudo systemctl enable --now cybershield"
fi
echo "CyberShield Kali installation complete. Run ./deployment/kali/start.sh"
