# CyberShield AI — Bharat AI-SoC Challenge 2026–27

**Privacy-first, on-device cybersecurity assistant for phishing, scams, network threats, and Android APK analysis.**

CyberShield is a local-first cybersecurity project designed to detect suspicious URLs, fraudulent messages, network intrusion signals, risky application behaviour, and potentially malicious Android APKs. It combines machine-learning classifiers with defensive rule-based analysis and provides understandable findings and remediation guidance.

The project is being developed for the **Bharat AI-SoC Challenge 2026–27**, with an emphasis on offline operation, privacy, explainability, and deployment on supported ARM-based devices.

## Project status

CyberShield has an implemented Flask application, multiple trained detection models, an interactive dashboard, feedback collection, and Phase 2 detection modules.

The remaining deployment evidence must be reported separately from completed model training: Llama-family model export to ExecuTorch, verified on-device `.pte` inference, fully offline advisory testing, and validation on an available ARM/Android target.

## Key features

- **Phishing URL detection:** Identifies suspicious URLs using a trained ML classifier and URL-based signals.
- **SMS scam detection:** Classifies text messages as potentially fraudulent or legitimate.
- **Email phishing detection:** Analyses email text for phishing-related patterns.
- **Social-message scam detection:** Detects suspicious or fraudulent social and messaging content.
- **Network intrusion analysis:** Evaluates network telemetry and intrusion-related signals.
- **Android APK analysis:** Performs defensive static inspection and uses a trained classifier based on application features.
- **Malware behaviour analysis:** Evaluates suspicious behavioural indicators without executing unknown malware.
- **Explainable findings:** Presents evidence, risk scores, severity levels, and recommended defensive actions.
- **Feedback and controlled learning:** Stores user feedback for review through a learning queue; feedback is not automatically trusted as a production training label.
- **Local-first design:** Supports local processing through the application and its available detection components.

## Technology stack

| Component | Technology |
|---|---|
| Backend API | Python, Flask |
| Machine learning | scikit-learn, joblib |
| Data processing | pandas, NumPy, SciPy |
| Dashboard | HTML, CSS, JavaScript |
| APK feature extraction | Androguard |
| Feedback and local persistence | SQLite |
| On-device advisory target | Llama-family model + ExecuTorch |
| Development environment | Kali Linux |
| Target platform | ARM-based Linux and Android, subject to validation |

## Architecture

```text
                 CyberShield Dashboard
                          |
                     Flask API
                          |
              Detection and Analysis Engine
                          |
       +------------------+-------------------+
       |                  |                   |
  URL / Phishing      SMS / Email        Network Signals
       |                  |                   |
       +------------------+-------------------+
                          |
               APK / Malware Analysis
                          |
                 Evidence and Risk
                          |
              Explanation and Remediation
                          |
                User Feedback Queue
                          |
                 Human Review
```

The detection components produce the security findings. The planned Llama-family advisory component is intended to explain those findings and suggest remediation grounded in the detector output; it must not be represented as operational ExecuTorch inference until that integration has been demonstrated.

## Trained model evaluation

The following results are from the project's recorded evaluation outputs. They are dataset-specific measurements, not guarantees of real-world detection performance.

| Model | Accuracy | Precision | Recall | F1-score |
|---|---:|---:|---:|---:|
| SMS scam detection | 98.39% | 93.96% | 93.96% | 93.96% |
| Phishing URL detection | 87.54% | 84.67% | 91.63% | 88.02% |
| Email phishing detection | 98.52% | 97.36% | 98.70% | 98.03% |
| Social-message scam detection | 94.21% | 85.65% | 97.38% | 91.13% |
| APK malware classification | 96.50% | 80.14% | 84.59% | 82.30% |

**Evaluation notes**

- SMS metrics were recorded using a 5,574-row dataset.
- The phishing URL evaluation used 339,613 rows after cleaning.
- Email phishing and social-message scam metrics are from their recorded held-out evaluations.
- APK metrics were calculated on 20,387 held-out rows. The reported class mapping is assumed to be `0 = benign` and `1 = malware`; that mapping and the equivalence of training-time and inference-time feature extraction must be independently verified before making stronger safety claims.
- Dataset composition, class balance, thresholds, feature coverage, and false-positive/false-negative rates affect practical performance.
- Network evaluation and threshold-tuning evidence are maintained separately in the reports directory.
- These measurements do not establish performance against every real-world threat.

## Repository structure

```text
CyberShield/
├── app.py
├── cybershield/
│   ├── api.py
│   ├── engine.py
│   ├── phase2.py
│   ├── apk_ml.py
│   ├── schemas.py
│   ├── security.py
│   ├── storage.py
│   ├── advisor/
│   ├── detectors/
│   ├── learning/
│   └── ml/
├── data/
│   ├── raw/
│   ├── external/
│   └── DATASET_MANIFEST_TEMPLATE.csv
├── models/
├── reports/
│   ├── network_validation/
│   ├── apk_malware_classifier_metrics.json
│   ├── email_phishing_text_metrics.json
│   └── social_scam_text_metrics.json
├── scripts/
├── docs/
├── static/
├── templates/
├── tests/
├── requirements.txt
└── README.md
```

The exact files present may vary by checkout. Raw datasets, local databases, temporary files, and large generated artifacts should not be committed unless their licensing, privacy implications, and repository size have been reviewed.

## Installation on Kali Linux

### 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git build-essential
```

### 2. Clone the repository

```bash
git clone https://github.com/jadhavpiyush333/CyberShield.git
cd CyberShield
```

### 3. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Configure the Python import path

From the project root:

```bash
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
```

### 6. Run the tests

```bash
pytest -q --import-mode=importlib tests/
```

### 7. Start CyberShield

```bash
python app.py
```

Open the local dashboard at:

`http://127.0.0.1:5000`

The service also has a health endpoint:

`http://127.0.0.1:5000/api/health`

Use only trusted local interfaces and follow the deployment documentation before exposing the service to a network.

## Detection and training modules

### Phase 1 models

The training utilities support SMS, phishing URL, and network model workflows. Prepare datasets in the expected schema described in `docs/DATASETS.md`.

Example SMS training:

```bash
python scripts/train_models.py sms \
  --csv data/raw/sms.csv \
  --text-column text \
  --label-column label
```

Example phishing URL training:

```bash
python scripts/train_models.py phishing \
  --csv data/raw/phishing.csv \
  --url-column url \
  --label-column label
```

Example network training:

```bash
python scripts/train_models.py network \
  --csv data/raw/network.csv \
  --label-column label
```

These commands require the corresponding datasets to be prepared in the expected format. Do not assume that a raw dataset can be passed directly to a training script without schema and label validation.

### Phase 2 models

Additional training and validation utilities include:

- `scripts/train_phase2_models.py`
- `scripts/train_all_phase2.py`
- `scripts/train_apk_mh100k.py`
- `scripts/train_apk_mh100k_stream.py`
- `scripts/prepare_unsw_nb15.py`
- `scripts/train_unsw_nb15.py`
- `scripts/tune_network_random_forest.py`
- `scripts/tune_network_threshold.py`
- `scripts/validate_new_module_data.py`

Use each script's `--help` output and its documentation to confirm the required arguments before training.

## API capabilities

The application exposes detection endpoints through the Flask API. Implemented routes include the following:

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Service health check |
| `POST /api/scan/url` | URL and phishing analysis |
| `POST /api/scan/sms` | SMS and scam-message analysis |
| `POST /api/scan/network` | Network event analysis |
| `POST /api/scan/behavior` | Behavioural threat analysis |
| `POST /api/scan/apk` | Android APK static analysis |
| `POST /api/feedback` | Submit user feedback |

Feedback and learning routes are also used by the dashboard. Check `cybershield/api.py` for the current request formats, validation rules, and available endpoints.

### APK analysis

The APK module combines static inspection with an ML classifier. It can examine available application features, permissions, manifest information, DEX-related signals, and embedded URLs, subject to extraction coverage and file-format limitations.

Unknown APKs must not be executed on the host merely to determine whether they are malicious. Static-analysis results are indicators, not proof that an application is safe or malicious.

## Llama-family model and ExecuTorch

The intended on-device advisory pipeline is:

1. Receive structured findings from CyberShield's detection engine.
2. Supply relevant evidence and risk information to a permitted Llama-family model.
3. Export the supported model to the ExecuTorch `.pte` format.
4. Execute inference through a compatible ExecuTorch LLM runner.
5. Return a concise, grounded explanation and recommended remediation.
6. Verify offline operation and validate inference on an available ARM/Android device.

**Completion criteria:** A valid `.pte` file alone is insufficient. The submission must include evidence of successful export, actual runtime inference, reproducible outputs, offline operation, and target-device validation. Do not report these milestones as complete until they have been tested.

Refer to `docs/EXECUTORCH.md` and `scripts/export_llama.sh` for the current integration guidance.

## Privacy, security, and responsible use

- Process security inputs locally wherever the configured components permit.
- Do not claim that all application features operate offline until verified.
- Do not send user messages, APK contents, or telemetry to external services without clear consent and appropriate safeguards.
- Keep secrets, private datasets, local databases, and environment files out of public commits.
- Validate data sources, dataset licences, label definitions, and train/test separation.
- Review user feedback before using it as training data.
- Do not execute unknown APKs or malware on the development host.
- Present risk scores as model outputs rather than absolute probabilities of harm unless they have been appropriately calibrated.
- Provide clear remediation steps and allow users to review findings.

## Current limitations and remaining milestones

The project distinguishes implemented modules and recorded model evaluations from deployment claims that still need proof.

- [x] Flask application and dashboard foundation
- [x] SMS and phishing URL model training
- [x] Email phishing and social-message scam model evaluation
- [x] APK classifier training and recorded held-out metrics
- [x] Network training and threshold-validation utilities
- [x] Feedback storage and controlled learning workflow
- [ ] Independently verify APK label semantics and training/inference feature equivalence
- [ ] Complete Llama-family checkpoint selection and permitted `.pte` export
- [ ] Demonstrate actual ExecuTorch LLM inference
- [ ] Verify offline operation for the complete application and advisory path
- [ ] Validate on an available ARM/Android target
- [ ] Complete final reproducible benchmarks, technical report, and demonstration

## Documentation

Consult the relevant files for detailed implementation and evidence:

- `docs/DATASETS.md` — dataset preparation and expected schemas
- `docs/NEW_MODULE_DATASETS.md` — datasets used for additional modules
- `docs/EXECUTORCH.md` — Llama and ExecuTorch integration
- `docs/CONTINUOUS_LEARNING.md` — feedback review and controlled learning
- `docs/DEPLOYMENT.md` — deployment guidance
- `docs/PHASE1_CHECKLIST.md` — submission evidence and completion checklist

## Challenge submission

The Phase 1 submission package should include the source code, reproducible training and evaluation scripts, permitted model artifacts or download instructions, dataset documentation, actual benchmark reports, test evidence, a technical report, and a demonstration.

For the Bharat AI-SoC Challenge 2026–27, the published Phase 1 submission deadline in the project plan is **30 November 2026**. Confirm the official challenge portal for any schedule updates.

---

**CyberShield AI — Detect threats. Explain risks. Protect users.**

*Defensive cybersecurity research focused on privacy, transparency, and responsible on-device AI.*
