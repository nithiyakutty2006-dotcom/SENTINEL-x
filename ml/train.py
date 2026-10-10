import os
import numpy as np
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
from keras.models import Sequential
from keras.layers import Dense, Input, Dropout
from ml.preprocessing import FeatureScaler
from app.paths import data_path

MODEL_PATH = str(data_path("models", "autoencoder.keras"))

def build_autoencoder(input_dim):
    model = Sequential([
        Input(shape=(input_dim,)),
        Dense(16, activation='relu'),
        Dropout(0.1),
        Dense(8, activation='relu'), # Latent space
        Dense(16, activation='relu'),
        Dense(input_dim, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def train_model(data):
    """
    Train autoencoder on historical normal data.
    data: list of dicts or list of lists representing [packets, traffic, connections, unknown, port_encoded, protocol_encoded]
    Returns metrics dict.
    """
    if len(data) < 10:
        raise ValueError("Not enough data to train. Need at least 10 samples.")
        
    scaler = FeatureScaler()
    scaler.fit(data)
    scaler.save()
    
    scaled_data = scaler.transform(data)
    
    model = build_autoencoder(scaled_data.shape[1])
    
    history = model.fit(
        scaled_data, scaled_data,
        epochs=30,
        batch_size=32,
        validation_split=0.2,
        verbose=0
    )
    
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    model.save(MODEL_PATH)
    
    # Calculate reconstruction errors to define threshold
    predictions = model.predict(scaled_data, verbose=0)
    mse = np.mean(np.power(scaled_data - predictions, 2), axis=1)
    
    # Set threshold as 95th percentile of training error
    threshold = float(np.percentile(mse, 95))
    
    metrics = {
        "loss": float(history.history['loss'][-1]),
        "val_loss": float(history.history['val_loss'][-1]),
        "threshold": threshold,
        "samples": len(data)
    }
    
    return metrics
