# CyberShield AI — Bharat AI-SoC Phase 1 Gate

## Working now
- Phishing URL detector + ML model loader
- Scam/SMS detector + ML model loader
- Network intrusion detector
- Safe malware-behaviour detector
- Unified risk/evidence schema
- SQLite alert history
- Local dashboard/API
- Offline rule-based fallback advisor
- Reproducible training/evaluation scripts
- Kali installation/start/stop/status scripts

## Must be evidenced before submission
- [ ] Train phishing model on a permitted real dataset
- [ ] Train SMS model on UCI SMS Spam Collection or another permitted real dataset
- [ ] Train network model on permitted UNSW-NB15/CICIDS data
- [ ] Train/evaluate malware-behaviour model on a permitted safe telemetry dataset
- [ ] Record accuracy, precision, recall, F1, FPR, FNR and confusion matrices
- [ ] Export a permitted Llama-family checkpoint to `.pte` with ExecuTorch
- [ ] Run that `.pte` through an actual ExecuTorch LLM runner
- [ ] Demonstrate offline inference with network disabled
- [ ] Validate on ARM/Android where hardware is available
- [ ] Measure latency/RAM/model size
- [ ] Capture final screenshots and demo video
- [ ] Freeze source, models/scripts, report and demo to the same release version

**Important:** a `.pte` placeholder, mocked response, or rule-based advisor must not be presented as actual Llama/ExecuTorch inference.
