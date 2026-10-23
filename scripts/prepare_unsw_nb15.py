from pathlib import Path
import pandas as pd

ROOT = Path("data/external/unsw-nb15")
OUT = Path("data/processed/unsw-nb15")
OUT.mkdir(parents=True, exist_ok=True)

# Official UNSW-NB15 feature names, in dataset column order.
COLUMNS = [
    "id", "dur", "proto", "service", "state", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "sttl", "dttl", "sload", "dload",
    "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin",
    "stcpb", "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean",
    "dmean", "trans_depth", "res_bdy_len", "ct_srv_src",
    "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst",
    "is_sm_ips_ports", "attack_cat", "label",
]

FILES = [
    "UNSW_NB15_training-set.csv",
    "UNSW_NB15_testing-set.csv",
]

for filename in FILES:
    source = ROOT / filename

    if not source.exists():
        print(f"SKIP: file not found: {source}")
        continue

    # These files were shown to have no header row.
    df = pd.read_csv(source, header=None, sep="\t", low_memory=False)

    if len(df.columns) != len(COLUMNS):
        raise ValueError(
            f"{filename}: expected {len(COLUMNS)} columns, "
            f"found {len(df.columns)}. Nothing was written."
        )

    df.columns = COLUMNS

    # Validate the target labels before saving.
    observed = set(df["label"].astype(str).str.strip().unique())
    if not observed.issubset({"0", "1"}):
        raise ValueError(
            f"Unexpected label values in {filename}: {observed}"
        )

    destination = OUT / filename
    df.to_csv(destination, index=False)

    print(f"\nSaved: {destination}")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print("Label counts:")
    print(df["label"].value_counts().sort_index().to_string())
    print("First columns:", df.columns[:8].tolist())

print("\nDataset preparation finished.")
