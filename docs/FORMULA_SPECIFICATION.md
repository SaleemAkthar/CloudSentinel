# Formula Specification

---

## Overview

This document provides a comprehensive explanation of the mathematical formulas used in Cloud Sentinel's Layer 1 anomaly detection system. The formulas are designed to detect security threats in AWS Lambda functions through statistical analysis of execution metrics.
Target Audience: This specification is written for technical reviewers, security analysts, and developers who need to understand how anomaly scores are calculated.

## System Overview

Cloud Sentinel uses a weighted composite scoring system to detect anomalies in serverless function execution. The system combines four detection components:

1. **Feature Analysis** - Statistical analysis of execution metrics
2. **Packet Analysis** - Network behavior examination
3. **Temporal Analysis** - Time-series pattern detection
4. **Behavioral Analysis** - Attack signature matching

Each component produces a score between 0 and 1, which are then weighted and combined into a final composite score that determines if a request is anomalous.

---

## BaseLine Learning

### Purpose

Before detecting anomalies, the system must first learn what "normal" behavior looks like for a specific Lambda function. This baseline is established by observing the first 100 requests.

### Welford's Online Algorithm

Why This Algorithm:
Traditional statistical methods require storing all historical values to calculate mean and variance, which consumes memory that grows linearly with the number of observations. Welford's algorithm solves this by maintaining running statistics using only three numbers per feature, regardless of how many requests have been processed

### Space Complexity:

- **Traditional method:** $O(n)$ - stores all $n$ values
- **Welford's method:** $O(1)$ - stores only 3 values

### Memory Usage:

- **Traditional:** 800MB for 100,000 requests
- **Welford's:** 24 bytes (constant, regardless of request count)

### Algorithm Explanation

For each feature (duration, memory, API calls, etc.), we maintain three values:

- **n** - count of observations
- **mean** - running average
- **M2** - sum of squared deviations from the mean

### Update Process:

when a new value `x` arrives:

```text
Step 1: Increment count
n = n + 1

Step 2: Calculate deviation from old mean
delta = x - mean

Step 3: Update mean with new value
mean = mean + (delta / n)

Step 4: Calculate deviation from new mean
delta2 = x - mean

Step 5: Update sum of squared deviations
M2 = M2 + (delta × delta2)

```

### Calculate Statistics:

After each update, we can compute:

```text
Variance = M2 / (n - 1)
Standard Deviation = √Variance
```

### Example Walkthrough

Lets track duration values: [500, 510, 495, 505, 490]

- **Request 1: x= 500**

```text
n = 1
delta = 500 - 0 = 500
mean = 0 + (500 / 1) = 500
delta2 = 500 - 500 = 0
M2 = 0 + (500 × 0) = 0

Result: mean = 500, variance = 0 (only one sample)

```

- **Request 2: x=510**

```text
n = 2
delta = 510 - 500 = 10
mean = 500 + (10 / 2) = 505
delta2 = 510 - 505 = 5
M2 = 0 + (10 × 5) = 50

Result: mean = 505, variance = 50 / 1 = 50, std = 7.07

```
- **Request 3: x=495**

```text
n = 3
delta = 495 - 505 = -10
mean = 505 + (-10 / 3) = 501.67
delta2 = 495 - 501.67 = -6.67
M2 = 50 + (-10 × -6.67) = 116.67

Result: mean = 501.67, variance = 58.33, std = 7.64

```
- **After processing all 5 values**

```text
Final mean = 500
Final standard deviation = 7.91

```
---

## Feature Normalization

### The problem

Different features have different scales:

- Duration: measured in milliseconds
- Memory: measured in megabytes
- API calls: count

We cannot directly compare a duratio of 500ms to a memory of usage of 130MB.
We need to normalize them to a common scale.

### Z-Score Transformation

Purpose: Convert each feature value to a standardized score that represnts "how many standard deviations away from the mean."

- **Formula**

```text
Z = (x - μ) / σ

Where:
- Z = Z-score (standardized value)
- x = observed value
- μ = mean (from baseline)
- σ = standard deviation (from baseline)

```
- **Interpretation**

- Z=0:Value is exactly at the mean(perfectly normal)
- Z=1:Value is 1 standard deviations above mean(slightly unusual)
- Z=2:Value is 2 standard deviations above mean(unusual)
- Z=3:Value is 3 standard deviations above mean(very unusual)
-Z>3: Value is extremely outlier(highly anomalous)


