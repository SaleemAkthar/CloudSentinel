import unittest
from backend.detection.online_detector import OnlineStats

class TestSaleemCore(unittest.TestCase):
    def test_welford_accuracy(self):
        stats = OnlineStats()
        data = [100, 200, 300] # Mean = 200, Var = 10000, Std = 100
        for val in data:
            stats.update(val)
        
        self.assertEqual(stats.get_mean(), 200)
        self.assertEqual(stats.get_std(), 100)
        
        # Z-score for 400 should be 2.0
        self.assertEqual(stats.get_z_score(400), 2.0)

if __name__ == "__main__":
    unittest.main()