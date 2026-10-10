import unittest
import numpy as np
from ml.preprocessing import FeatureScaler

class TestPreprocessing(unittest.TestCase):
    def setUp(self):
        self.scaler = FeatureScaler()
        self.data = [
            [10, 1.5, 5, 0, 80, 1],
            [100, 5.0, 50, 2, 443, 2],
            [50, 3.0, 25, 1, 22, 1]
        ]
        
    def test_fit_transform(self):
        self.scaler.fit(self.data)
        scaled = self.scaler.transform(self.data)
        
        # Check shapes
        self.assertEqual(scaled.shape, (3, 6))
        
        # Check min and max are 0 and 1
        np.testing.assert_array_almost_equal(np.min(scaled, axis=0), np.zeros(6))
        np.testing.assert_array_almost_equal(np.max(scaled, axis=0), np.ones(6))

if __name__ == '__main__':
    unittest.main()
