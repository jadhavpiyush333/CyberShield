#!/usr/bin/env bash
set -euo pipefail
mkdir -p data/raw
cat <<'EOF'
CyberShield dataset acquisition guide

SMS: UCI SMS Spam Collection -> save as data/raw/sms.csv with columns text,label.
Phishing: use a permitted PhishTank/OpenPhish export -> normalize to data/raw/phishing.csv with url,label.
Network: use permitted UNSW-NB15 or CICIDS2017 flow CSV -> normalize to data/raw/network.csv with label plus numeric flow columns.
Malware behaviour: use a permitted safe telemetry/behavior dataset or your own sandbox traces -> normalize to data/raw/malware_behavior.csv.

Do not commit raw datasets unless their licenses permit redistribution.
EOF
