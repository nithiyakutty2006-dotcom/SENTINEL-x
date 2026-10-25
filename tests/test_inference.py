import unittest
import tempfile
import os
from unittest.mock import patch
from ml.inference import ModelInference
from ml.preprocessing import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, FeatureScaler

class TestInference(unittest.TestCase):
    def setUp(self):
        self.inference = ModelInference()
        
    def test_extract_features(self):
        event = {
            "packets": 1500,
            "traffic": 5.2,
            "connections": 50,
            "unknown": 2,
            "port": 80,
            "protocol": "TCP"
        }
        features = self.inference.extract_features(event)
        
        self.assertEqual(len(features), 6)
        self.assertEqual(features[0], 1500.0)
        self.assertEqual(features, [1500.0, 5.2, 50.0, 2.0, 80.0, 1.0])
        self.assertEqual(features[4], 80.0)
        self.assertEqual(features[5], 1.0) # TCP encoded as 1

    def test_feature_scaler_persists_the_exact_feature_schema(self):
        scaler = FeatureScaler()
        scaler.fit(
            [[1500, 5.2, 50, 2, 80, 1], [1200, 4.1, 40, 1, 443, 2]],
            feature_names=FEATURE_NAMES,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            scaler_path = os.path.join(temp_dir, "scaler.pkl")
            scaler.save(scaler_path)
            loaded = FeatureScaler()

            self.assertTrue(loaded.load(scaler_path))
            self.assertEqual(loaded.feature_names, FEATURE_NAMES)
            self.assertEqual(loaded.schema_version, FEATURE_SCHEMA_VERSION)

    def test_model_rejects_scaler_with_a_different_feature_order(self):
        self.inference.scaler.feature_names = tuple(reversed(FEATURE_NAMES))
        self.inference.scaler.schema_version = FEATURE_SCHEMA_VERSION
        with tempfile.TemporaryDirectory() as temp_dir:
            model_path = os.path.join(temp_dir, "autoencoder.keras")
            with open(model_path, "wb"):
                pass
            with patch("ml.inference.data_path", return_value=model_path):
                with patch.object(self.inference.scaler, "load", return_value=True):
                    with patch("ml.inference.load_model") as load_model:
                        self.assertFalse(self.inference.load())
                        load_model.assert_not_called()

        self.assertFalse(self.inference.loaded)
        self.assertIn("feature schema", self.inference.load_error)

    def test_unloaded_model_has_no_anomaly_score(self):
        score, is_anomaly, reason = self.inference.predict({"packets": 1})

        self.assertIsNone(score)
        self.assertFalse(is_anomaly)
        self.assertEqual(reason, "Model not loaded")

if __name__ == '__main__':
    unittest.main()
