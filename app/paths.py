import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", PROJECT_ROOT)).expanduser()


def data_path(*parts):
    return DATA_DIR.joinpath(*parts)
