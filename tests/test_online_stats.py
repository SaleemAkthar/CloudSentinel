import unittest
from backend.online_detector import OnlineStats

class TestOnlineStats(unittest.TestCase):
    def setUp(self):
        self.stats = OnlineStats()

    def test_initial_state(self):
        self.assertEqual(self.stats.n, 0)
        self.assertEqual(self.stats.get_mean(), 0.0)

    def test_calculation_accuracy(self):
        data = [10, 20, 30, 40, 50]
        for x in data:
            self.stats.update(x)
        
        # Expected Mean: 30, Expected Variance: 250
        self.assertEqual(self.stats.get_mean(), 30.0)
        self.assertAlmostEqual(self.stats.get_variance(), 250.0)
        self.assertAlmostEqual(self.stats.get_std(), 15.811388, places=5)

    def test_z_score(self):
        # Establish baseline
        for x in [10, 10, 10, 10]: self.stats.update(x)
        self.stats.update(20) # This is an outlier
        
        z = self.stats.get_z_score(20)
        self.assertGreater(z, 1.0)

if __name__ == '__main__':
    unittest.main()