import numpy as np
import pickle
import os
from app.paths import data_path

SCALER_PATH = str(data_path("models", "scaler.pkl"))
FEATURE_NAMES = (
    "packets",
    "traffic_mb",
    "connections",
    "unknown_destinations",
    "destination_port",
    "protocol_code",
)
FEATURE_SCHEMA_VERSION = 1

class FeatureScaler:
    def __init__(self):
        self.min_vals = None
        self.max_vals = None
        self.range_vals = None
        self.feature_names = None
        self.schema_version = None

    def fit(self, data, feature_names=None):
        data = np.array(data)
        if data.ndim != 2:
            raise ValueError("Scaler training data must be a two-dimensional feature matrix.")
        if feature_names is not None and len(feature_names) != data.shape[1]:
            raise ValueError("Feature names do not match the training data dimensions.")
        self.min_vals = np.min(data, axis=0)
        self.max_vals = np.max(data, axis=0)
        self.feature_names = tuple(feature_names) if feature_names is not None else None
        self.schema_version = FEATURE_SCHEMA_VERSION if feature_names is not None else None
        
        # Prevent division by zero
        range_vals = self.max_vals - self.min_vals
        range_vals[range_vals == 0] = 1.0
        self.range_vals = range_vals

    def transform(self, data):
        data = np.array(data)
        if self.min_vals is None or self.max_vals is None:
            return data
        return (data - self.min_vals) / self.range_vals

    def save(self, path=SCALER_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({
                "min": self.min_vals,
                "max": self.max_vals,
                "range": self.range_vals,
                "feature_names": self.feature_names,
                "schema_version": self.schema_version,
            }, f)

    def load(self, path=SCALER_PATH):
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = pickle.load(f)
                self.min_vals = data['min']
                self.max_vals = data['max']
                self.range_vals = data['range']
                self.feature_names = (
                    tuple(data["feature_names"])
                    if data.get("feature_names") is not None else None
                )
                self.schema_version = data.get("schema_version")
            return True
        return False
