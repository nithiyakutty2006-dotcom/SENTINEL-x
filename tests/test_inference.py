import unittest
from ml.inference import ModelInference

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
        self.assertEqual(features[4], 80.0)
        self.assertEqual(features[5], 1.0) # TCP encoded as 1

if __name__ == '__main__':
    unittest.main()
