# CyberShield — New-module dataset setup

This is a **dataset acquisition and validation scaffold**, not a claim that datasets have already been downloaded or used for training. Some providers require an application form, account, API key, or access approval. Do not bypass those requirements.

## Recommended acquisition order

1. **Email phishing** — Start with the curated phishing-email corpus collection on Zenodo (includes Nazario, SpamAssassin-derived and other email corpora). Check the record's license and each source corpus' terms before use. Keep subject/body and labels; remove corpus instruction rows and duplicates. Add source and license metadata.
   - https://zenodo.org/records/8339691
   - SpamAssassin corpus documentation: https://spamassassin.apache.org/old/publiccorpus/
2. **QR/quishing and document attachments** — Use CIC-Trap4Phish 2025. It includes Word, Excel, PDF, HTML, QR-image and URL-string categories with benign/malicious labels and static-feature pipelines. Download through the official page; inspect its paper, license and archive contents before using.
   - https://www.unb.ca/cic/datasets/trap4phish2025.html
3. **URL reputation and brand impersonation** — Combine your existing labelled phishing URL data with an allowed PhishTank feed snapshot and a benign-domain source such as Tranco. Preserve snapshot dates. A popular domain is not automatically safe, and feeds may contain stale entries.
   - https://www.phishtank.org/developer_info.php
   - https://tranco-list.eu/
4. **Android APK static analysis** — Drebin is a research dataset with access terms; AndroZoo access requires following its registration/API conditions. Begin with metadata/features only. Never install or execute suspicious APKs on your daily-use machine.
   - https://www.sec.cs.tu-bs.de/~danarp/drebin/
   - https://androzoo.uni.lu/
5. **Social-media scam content, UPI/payment scams and call transcripts** — Public, representative, licensed labelled datasets may be limited. Build a carefully reviewed, privacy-preserving corpus from consented or public examples where reuse is permitted. Redact names, phone numbers, handles, account IDs, UPI IDs and other personal data. Keep an explicit source/consent/license record. Do not claim a model is validated for these domains using SMS-only data.
6. **Network IDS** — Continue with the existing UNSW-NB15 files after checking delimiter/headers. Keep train and test files separate if the source provides separate official splits.

## Suggested canonical CSV schemas

The validator script in `scripts/validate_new_module_data.py` checks basic schema and label hygiene. It does not prove that labels are correct or that a dataset is legally reusable.

| File | Required columns | Label convention |
|---|---|---|
| `data/raw/email.csv` | `text,label` | `phishing` / `legitimate` |
| `data/raw/social_scams.csv` | `text,label` | `scam` / `legitimate` |
| `data/raw/qr.csv` | `url,label` | `malicious` / `benign` |
| `data/raw/document_metadata.csv` | `sample_id,file_type,label` | `malicious` / `benign` |
| `data/raw/apk_metadata.csv` | `sample_id,label` plus numeric static features | `malware` / `benign` |
| `data/raw/upi_scams.csv` | `text,label` | `scam` / `legitimate` |
| `data/raw/call_transcripts.csv` | `text,label` | `scam` / `legitimate` |

These files must contain actual records before training. Do not use empty schema templates or fabricated rows as training data.

## Data quality and evaluation checklist

- Keep a source manifest with dataset name, exact download URL, access date, version/snapshot date, license/terms, SHA-256, label mapping and preprocessing.
- Preserve the provider's original archive separately; write normalized data to `data/processed/`.
- Deduplicate before splitting. For URL/domain tasks, group by registered domain where feasible so near-duplicate URLs do not leak across train/test.
- Prefer time-based or group-based holdout tests when possible. Fit text vectorizers and feature selection on training data only.
- Report per-class precision, recall, F1, confusion matrix, false-positive rate and false-negative rate. Include class counts and split strategy.
- For social/UPI/call data, document language coverage (e.g. English, Hindi, Marathi), code-mixing and sampling limitations.
- Do not put raw personal data, restricted datasets, credentials, API keys or large datasets into Git.
- For live threat feeds, use them as a reputation signal and maintain an offline snapshot; do not treat a feed alone as a balanced training dataset.
