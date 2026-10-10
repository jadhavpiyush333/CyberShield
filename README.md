
# CyberShield AI — Bharat AI-SoC Phase 1

CyberShield is a local, privacy-first cybersecurity assistant for phishing URLs, scam communications, network intrusion/anomaly signals and safe malware-behaviour telemetry. The detection verdict is produced by deterministic/ML components; a Llama-family model is used only for grounded explanation and remediation.

## Current release

This repository is the **Phase 1 release-candidate foundation**. The application works with the built-in detectors. The remaining evidence gates are deliberately explicit: train on permitted real datasets, record evaluation metrics, export/run a permitted Llama model through ExecuTorch, prove offline inference, and validate on an available ARM/Android target.

## Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git build-essential
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest -q
python app.py
```

Open `http://127.0.0.1:5000`.

For a production-like local service:

```bash
./deployment/kali/install_kali.sh
./deployment/kali/start.sh
```

## Train the Phase 1 baselines

Normalize permitted datasets according to `docs/DATASETS.md` and keep raw data outside Git unless redistribution is allowed.

```bash
python scripts/train_models.py sms --csv data/raw/sms.csv --text-column text --label-column label
python scripts/train_models.py phishing --csv data/raw/phishing.csv --url-column url --label-column label
python scripts/train_models.py network --csv data/raw/network.csv --label-column label
```

Then evaluate:

```bash
python scripts/evaluate_models.py sms --model models/scam_text.joblib --csv data/raw/sms.csv --output reports/sms_metrics.json
python scripts/evaluate_models.py phishing --model models/phishing_url.joblib --csv data/raw/phishing.csv --output reports/phishing_metrics.json
python scripts/evaluate_models.py network --model models/network.joblib --csv data/raw/network.csv --output reports/network_metrics.json
```

## Llama + ExecuTorch

See `docs/EXECUTORCH.md` and `scripts/export_llama.sh`. Do not put a placeholder `.pte` into the submission and call it inference. The final evidence must show a permitted Llama-family checkpoint exported to `.pte` and executed through an actual ExecuTorch LLM runner.

## Phase 1 submission evidence

See `docs/PHASE1_CHECKLIST.md`. The final package should contain source, reproducible training/evaluation scripts, model artifacts or instructions, Llama/ExecuTorch evidence, offline test evidence, benchmark results, technical report and demo video.

## Safety / scope

Malware functionality is limited to defensive classification of safe behavioural telemetry. CyberShield does not automate exploitation, credential theft, persistence, or destructive actions.

## Continuous learning and UI
The dashboard now includes URL/SMS/network/malware analysis views, user feedback, and a controlled learning queue. Feedback is stored for verification and cannot directly poison the production model. Unknown malware is deliberately not auto-executed on the host; use imported behavioural telemetry from an isolated lab.

# CyberShield


