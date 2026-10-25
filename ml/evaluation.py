import numpy as np
import os

def evaluate_model_performance(model, scaler, data, threshold):
    """
    Evaluate trained Autoencoder model performance over validation/test dataset samples.
    Calculates MSE reconstruction errors, anomaly rates, and metrics.
    """
    if len(data) == 0:
        return {"error": "No evaluation samples provided"}
        
    scaled_data = scaler.transform(data)
    predictions = model.predict(scaled_data, verbose=0)
    
    mse_errors = np.mean(np.power(scaled_data - predictions, 2), axis=1)
    avg_mse = float(np.mean(mse_errors))
    max_mse = float(np.max(mse_errors))
    min_mse = float(np.min(mse_errors))
    
    anomalies_detected = int(np.sum(mse_errors > threshold))
    anomaly_rate = float(anomalies_detected / len(data)) * 100.0
    
    return {
        "samples_evaluated": len(data),
        "avg_mse_loss": round(avg_mse, 6),
        "max_mse_loss": round(max_mse, 6),
        "min_mse_loss": round(min_mse, 6),
        "threshold_used": round(threshold, 6),
        "anomalies_flagged": anomalies_detected,
        "anomaly_rate_percent": round(anomaly_rate, 2),
        "status": "UNSUPERVISED_DISTRIBUTION_ONLY"
    }
