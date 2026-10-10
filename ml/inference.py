import os
import numpy as np
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from keras.models import load_model
from ml.preprocessing import FeatureScaler
from app.paths import data_path

class ModelInference:
    def __init__(self):
        self.model = None
        self.scaler = FeatureScaler()
        self.threshold = 0.5 # Default fallback
        self.loaded = False

    def load(self, threshold=0.5):
        model_path = data_path("models", "autoencoder.keras")
        if os.path.exists(model_path) and self.scaler.load():
            try:
                self.model = load_model(model_path)
                self.threshold = threshold
                self.loaded = True
                return True
            except Exception as e:
                print(f"Error loading model: {e}")
                self.loaded = False
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
            return 0.0, False, "Model not loaded"
            
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
