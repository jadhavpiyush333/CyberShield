"""MH-100K APK malware inference using static APK/DEX features."""

from functools import lru_cache
from pathlib import Path
import re
import tempfile

import joblib
import numpy as np
import pandas as pd
from androguard.misc import AnalyzeAPK
from scipy.sparse import csr_matrix


ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "apk_malware_classifier.joblib"
FEATURES_PATH = ROOT / "data" / "raw" / "phase2" / "feature_names.csv"

INVOKE_RE = re.compile(r"(L[^;]+);->([^\s(]+)\(")
ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"


@lru_cache(maxsize=1)
def _load_model_and_schema():
    if not MODEL_PATH.is_file():
        raise RuntimeError("APK malware model file is missing.")
    if not FEATURES_PATH.is_file():
        raise RuntimeError("MH-100K feature-name file is missing.")

    model = joblib.load(MODEL_PATH)
    names = pd.read_csv(FEATURES_PATH)["features"].astype(str).tolist()

    if len(names) != 24833 or len(set(names)) != len(names):
        raise RuntimeError("MH-100K feature schema failed validation.")
    if getattr(model, "n_features_in_", None) != len(names):
        raise RuntimeError("APK model and feature schema sizes do not match.")
    if 1 not in list(model.classes_):
        raise RuntimeError("APK model does not contain malware class 1.")
    if not hasattr(model, "predict_proba"):
        raise RuntimeError("APK model does not support probability estimates.")

    return model, names, {name: i for i, name in enumerate(names)}


def _extract_feature_names(apk_bytes):
    """Extract only feature types represented in the MH-100K vocabulary."""
    active = set()

    # Androguard parses the APK in-process; the APK is never installed or run.
    with tempfile.TemporaryDirectory(prefix="cybershield-apk-") as temp_dir:
        apk_path = Path(temp_dir) / "sample.apk"
        apk_path.write_bytes(apk_bytes)

        apk, dex_files, _analysis = AnalyzeAPK(str(apk_path))

        # Permissions: MH-100K uses the short permission name.
        for permission in apk.get_permissions() or []:
            short_name = str(permission).rsplit(".", 1)[-1]
            active.add(f"Permission::{short_name}")

        # Intent actions from the parsed manifest, including binary XML.
        manifest = apk.get_android_manifest_xml()
        if manifest is not None:
            for element in manifest.iter():
                if element.tag.split("}")[-1] != "action":
                    continue
                action = element.get(ANDROID_NAME)
                if action:
                    action_name = str(action).rsplit(".", 1)[-1]
                    active.add(f"Intent::{action_name}")

        # Read method invocation references from DEX instructions.
        for dex in dex_files or []:
            for encoded_method in dex.get_encoded_methods():
                code = encoded_method.get_code()
                if code is None:
                    continue

                for instruction in code.get_bc().get_instructions():
                    output = instruction.get_output() or ""
                    match = INVOKE_RE.search(output)
                    if not match:
                        continue

                    class_name, method_name = match.groups()
                    active.add(f"APICall::{class_name}.{method_name}()")

    return active


def predict_apk(apk_bytes):
    """Return a malware probability and auditable feature extraction summary."""
    if not isinstance(apk_bytes, bytes) or not apk_bytes:
        raise ValueError("Provide non-empty APK bytes.")

    model, names, feature_index = _load_model_and_schema()
    active_names = _extract_feature_names(apk_bytes)
    matched = sorted(name for name in active_names if name in feature_index)

    # The dataset uses binary indicators: each known feature is 0 or 1.
    indices = np.asarray(
        [feature_index[name] for name in matched], dtype=np.int32
    )
    matrix = csr_matrix(
        (
            np.ones(len(indices), dtype=np.int8),
            (np.zeros(len(indices), dtype=np.int32), indices),
        ),
        shape=(1, len(names)),
        dtype=np.int8,
    )

    classes = list(model.classes_)
    malware_index = classes.index(1)
    probability = float(model.predict_proba(matrix)[0, malware_index])

    return {
        "malware_probability": probability,
        "features_matched": len(matched),
        "features_total": len(names),
        "matched_feature_names": matched,
    }
