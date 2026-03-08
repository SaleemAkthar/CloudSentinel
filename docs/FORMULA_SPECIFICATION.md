our formula is for the anomaly is :
anomaly_score = min(max_z_score / 3.0, 1.0)

If we do a reverse cal:
If threshold = 0.8:
0.8 = Z / 3.0
Z = 0.8 × 3.0 = 2.4

so anything beyond 2.4 standard deviations will be flaged