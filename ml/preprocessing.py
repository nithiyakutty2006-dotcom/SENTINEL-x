import numpy as np
import pickle
import os
from app.paths import data_path

SCALER_PATH = str(data_path("models", "scaler.pkl"))

class FeatureScaler:
    def __init__(self):
        self.min_vals = None
        self.max_vals = None
        self.range_vals = None

    def fit(self, data):
        data = np.array(data)
        self.min_vals = np.min(data, axis=0)
        self.max_vals = np.max(data, axis=0)
        
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
            pickle.dump({'min': self.min_vals, 'max': self.max_vals, 'range': self.range_vals}, f)

    def load(self, path=SCALER_PATH):
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = pickle.load(f)
                self.min_vals = data['min']
                self.max_vals = data['max']
                self.range_vals = data['range']
            return True
        return False
