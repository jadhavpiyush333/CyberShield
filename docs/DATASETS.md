# Phase 1 Dataset Protocol

Keep raw datasets outside Git unless redistribution is explicitly permitted.

| Detector | Recommended source | Canonical training columns |
|---|---|---|
| SMS/scam | UCI SMS Spam Collection | `text,label` |
| Phishing URL | Permitted PhishTank/OpenPhish export | `url,label` |
| Network IDS | UNSW-NB15 or CICIDS2017 | `label` + numeric flow features |
| Malware behaviour | Permitted safe telemetry/behaviour dataset or controlled benign traces | `label` + behaviour features |

For every dataset record: source URL, access date, license/terms, version, preprocessing, class counts, train/test split and feature list.
