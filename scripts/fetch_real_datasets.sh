#!/usr/bin/env bash
set -euo pipefail
mkdir -p data/raw
python3 - <<'PY'
import urllib.request,zipfile,io,os
u='https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip'
print('Downloading UCI SMS Spam Collection...')
data=urllib.request.urlopen(u).read(); z=zipfile.ZipFile(io.BytesIO(data)); z.extractall('data/raw/uci_sms')
print('Saved to data/raw/uci_sms')
PY
cat <<'EOF'
echo 'UNSW-NB15: download the official training/testing CSVs from UNSW and place them in data/raw/unsw/.'
echo 'PhishTank: obtain the permitted verified feed/API key and save a snapshot in data/raw/phishtank/.'
echo 'Malware: use a permitted behavioural telemetry dataset or your isolated analysis lab export; do not execute unknown malware on the host.'
EOF
