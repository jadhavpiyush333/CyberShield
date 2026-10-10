import os
from pathlib import Path
BASE_DIR=Path(__file__).resolve().parent
DATA_DIR=Path(os.getenv('CYBERSHIELD_DATA_DIR', BASE_DIR/'data'))
MODEL_DIR=Path(os.getenv('CYBERSHIELD_MODEL_DIR', BASE_DIR/'models'))
DB_PATH=Path(os.getenv('CYBERSHIELD_DB', DATA_DIR/'cybershield.db'))
DATA_DIR.mkdir(parents=True, exist_ok=True); MODEL_DIR.mkdir(parents=True, exist_ok=True)
