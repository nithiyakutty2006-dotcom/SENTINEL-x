from ml.train import train_model
from ml.inference import ModelInference
from ml.evaluation import evaluate_model_performance
from app.database import get_db_connection, now_string
import datetime
import csv
from io import StringIO

class ModelManager:
    def __init__(self):
        self.inference = ModelInference()
        self.reload_model()

    def reload_model(self):
        conn = get_db_connection()
        row = conn.execute("SELECT threshold FROM model_metrics ORDER BY id DESC LIMIT 1").fetchone()
        conn.close()
        if row:
            return self.inference.load(threshold=row["threshold"])
        self.inference.loaded = False
        self.inference.model = None
        self.inference.threshold = None
        self.inference.load_error = None
        return False

    def get_status(self):
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM model_metrics ORDER BY id DESC LIMIT 1").fetchone()
        if row and self.inference.loaded:
            return {
                "trained": True,
                "loaded": True,
                "date": row["training_date"],
                "samples": row["samples"],
                "loss": row["loss"],
                "val_loss": row["val_loss"],
                "threshold": row["threshold"],
                "status": "READY"
            }
        if self.inference.load_error:
            return {
                "trained": False,
                "loaded": False,
                "date": None,
                "samples": 0,
                "loss": None,
                "val_loss": None,
                "threshold": None,
                "status": "INVALID ARTIFACT"
            }
        if row:
            return {
                "trained": False,
                "loaded": False,
                "date": row["training_date"],
                "samples": row["samples"],
                "loss": row["loss"],
                "val_loss": row["val_loss"],
                "threshold": None,
                "status": "MODEL ARTIFACTS UNAVAILABLE"
            }
        return {
            "trained": False,
            "loaded": False,
            "date": None,
            "samples": 0,
            "loss": None,
            "val_loss": None,
            "threshold": None,
            "status": "NOT TRAINED"
        }

    def train_on_history(self):
        conn = get_db_connection()
        rows = conn.execute("""
            SELECT * FROM events
            WHERE source_type IN ('LIVE', 'REAL')
              AND severity IN ('LOW', 'NORMAL', 'MEDIUM')
              AND packets IS NOT NULL AND traffic IS NOT NULL
            ORDER BY id DESC LIMIT 2000
        """).fetchall()

        if len(rows) < 10:
            return False, (
                "Not enough labeled-source baseline telemetry to train. At least 10 "
                "LOW, NORMAL, or MEDIUM LIVE/REAL events are required; DEMO and "
                "DATASET events are not used as live training data."
            )

        data = []
        for r in rows:
            data.append(self.inference.extract_features(dict(r)))

        try:
            metrics = train_model(data, feature_names=self.inference.FEATURE_NAMES)

            # Insert into metrics
            conn.execute("""
            INSERT INTO model_metrics (training_date, samples, loss, val_loss, threshold, status)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                now_string(),
                metrics["samples"],
                metrics["loss"],
                metrics["val_loss"],
                metrics["threshold"],
                "READY"
            ))

            # Insert into model registry
            conn.execute("""
            INSERT INTO model_registry (version, model_type, architecture, training_date, samples, loss, val_loss, threshold, status, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                f"v2.0-{now_string().replace(':', '-').replace(' ', '_')}",
                "Autoencoder Neural Network",
                "Input(6) -> Dense(16) -> Dropout(0.1) -> Dense(8, Latent) -> Dense(16) -> Dense(6)",
                now_string(),
                metrics["samples"],
                metrics["loss"],
                metrics["val_loss"],
                metrics["threshold"],
                "READY"
            ))

            conn.commit()

            # Reload model in inference engine
            if not self.inference.load(threshold=metrics["threshold"]):
                raise RuntimeError("The trained model artifacts failed schema or load validation.")

            return True, f"Autoencoder model trained on {metrics['samples']} samples. Loss: {metrics['loss']:.4f}, Threshold: {metrics['threshold']:.4f}"
        except Exception as e:
            return False, f"Training failed: {str(e)}"

    def evaluate_current_model(self):
        if not self.inference.loaded or self.inference.model is None:
            return False, "Model is not loaded or trained yet."

        conn = get_db_connection()
        rows = conn.execute("""
            SELECT * FROM events
            WHERE source_type IN ('LIVE', 'REAL')
              AND packets IS NOT NULL AND traffic IS NOT NULL
            ORDER BY id DESC LIMIT 500
        """).fetchall()
        if len(rows) < 5:
            return False, "At least five LIVE/REAL events are required for unsupervised score-distribution evaluation."

        data = [self.inference.extract_features(dict(r)) for r in rows]
        
        try:
            res = evaluate_model_performance(
                self.inference.model,
                self.inference.scaler,
                data,
                self.inference.threshold
            )

            conn.execute("""
            INSERT INTO model_evaluations (evaluation_date, model_version, accuracy, precision_score, recall_score, f1_score, mse_loss, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now_string(),
                "v2.0-Autoencoder",
                None,
                None,
                None,
                None,
                res["avg_mse_loss"],
                "UNSUPERVISED_ONLY_NO_GROUND_TRUTH"
            ))
            conn.commit()

            return True, res
        except Exception as e:
            return False, str(e)

    def import_dataset_csv(self, csv_content: str, filename: str):
        conn = get_db_connection()
        try:
            reader = csv.DictReader(StringIO(csv_content))
            count = 0
            for row in reader:
                event = {
                    "timestamp": row.get("timestamp", now_string()),
                    "device": row.get("device", "IMPORTED_DATASET"),
                    "source_ip": row.get("source_ip", "192.168.1.100"),
                    "destination_ip": row.get("destination_ip", "10.0.0.1"),
                    "port": int(row.get("port", 80)),
                    "protocol": row.get("protocol", "TCP"),
                    "packets": int(row.get("packets", 100)),
                    "traffic": float(row.get("traffic", 1.0)),
                    "connections": int(row.get("connections", 10)),
                    "unknown": int(row.get("unknown", 0)),
                    "risk": int(row.get("risk", 10)),
                    "severity": row.get("severity", "LOW"),
                    "ai_score": float(row.get("ai_score", 0.0)),
                    "factors": row.get("factors", "Imported Dataset Sample"),
                    "source_type": "DATASET"
                }
                
                conn.execute("""
                INSERT INTO events(timestamp, device, source_ip, destination_ip, port, protocol, packets, traffic, connections, unknown, risk, severity, ai_score, factors, source_type)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    event["timestamp"], event["device"], event["source_ip"], event["destination_ip"],
                    event["port"], event["protocol"], event["packets"], event["traffic"],
                    event["connections"], event["unknown"], event["risk"], event["severity"],
                    event["ai_score"], event["factors"], "DATASET"
                ))
                count += 1

            conn.execute("""
            INSERT INTO datasets (filename, upload_date, samples, source_type, status)
            VALUES (?, ?, ?, ?, ?)
            """, (filename, now_string(), count, "CSV_IMPORT", "PROCESSED"))

            conn.commit()
            return True, f"Successfully imported dataset '{filename}' with {count} event samples."
        except Exception as e:
            return False, f"Failed to parse CSV dataset: {str(e)}"
