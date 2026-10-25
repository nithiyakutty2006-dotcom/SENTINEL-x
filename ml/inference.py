import os
import logging
import numpy as np
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from keras.models import load_model
from ml.preprocessing import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    FeatureScaler,
)
from app.paths import data_path

logger = logging.getLogger(__name__)

class ModelInference:
    FEATURE_NAMES = FEATURE_NAMES

    def __init__(self):
        self.model = None
        self.scaler = FeatureScaler()
        self.threshold = None
        self.loaded = False
        self.load_error = None

    def load(self, threshold=0.5):
        self.loaded = False
        self.load_error = None
        self.model = None
        self.threshold = None
        model_path = data_path("models", "autoencoder.keras")
        if not os.path.exists(model_path):
            return False
        try:
            if not self.scaler.load():
                raise ValueError("Saved feature scaler is missing.")
            if (
                self.scaler.feature_names != self.FEATURE_NAMES
                or self.scaler.schema_version != FEATURE_SCHEMA_VERSION
            ):
                raise ValueError("Saved scaler feature schema does not match inference.")
            expected_features = len(self.FEATURE_NAMES)
            if (
                self.scaler.min_vals is None
                or self.scaler.max_vals is None
                or self.scaler.range_vals is None
                or len(self.scaler.min_vals) != expected_features
                or len(self.scaler.max_vals) != expected_features
                or len(self.scaler.range_vals) != expected_features
            ):
                raise ValueError("Saved scaler feature count does not match the inference schema.")
            self.model = load_model(model_path)
            if self.model.input_shape[-1] != expected_features:
                raise ValueError("Saved model feature count does not match the inference schema.")
            self.threshold = threshold
            self.loaded = True
            return True
        except Exception as exc:
            self.load_error = str(exc)
            logger.exception("Saved anomaly model or feature scaler could not be loaded.")
            self.model = None
            self.threshold = None
            return False

    def extract_features(self, event):
        """
        Convert event dict into numeric features.
        """
        # Encode Protocol
        proto_map = {"TCP": 1, "UDP": 2, "HTTP": 3, "HTTPS": 4}
        proto_val = proto_map.get(event.get("protocol", "OTHER"), 0)
        
        # Standardize features
        features = [
            float(event.get("packets", 0)),
            float(event.get("traffic", 0.0)),
            float(event.get("connections", 0)),
            float(event.get("unknown", 0)),
            float(event.get("port", 0)),
            float(proto_val)
        ]
        return features

    def predict(self, event):
        """
        Predict anomaly score (0-100) for a single event.
        """
        if not self.loaded or self.model is None:
            return None, False, "Model not loaded"
            
        features = self.extract_features(event)
        
        # Scale
        scaled = self.scaler.transform([features])
        
        # Predict
        reconstructed = self.model.predict(scaled, verbose=0)
        
        # Reconstruction Error (MSE)
        mse = float(np.mean(np.power(scaled - reconstructed, 2), axis=1)[0])
        
        # Calculate Anomaly Score 0-100 based on threshold
        # If mse == threshold, score = 50.
        # If mse >= threshold * 2, score = 100
        score = min(100.0, (mse / max(self.threshold, 0.0001)) * 50.0)
        
        is_anomaly = mse > self.threshold
        
        return round(score, 2), is_anomaly, mse
