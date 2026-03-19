# Formula Specification

---

# Overview
This document provides a comprehensive explanation of the mathematical formulas used in Cloud Sentinel's Layer 1 anomaly detection system. The formulas are designed to detect security threats in AWS Lambda functions through statistical analysis of execution metrics.
Target Audience: This specification is written for technical reviewers, security analysts, and developers who need to understand how anomaly scores are calculated.

# System Overview

Cloud Sentinel uses a weighted composite scoring system to detect anomalies in serverless function execution. The system combines four detection components:

1.Feature Analysis - Statistical analysis of execution metrics
2.Packet Analysis - Network behavior examination
3.Temporal Analysis - Time-series pattern detection
4.Behavioral Analysis - Attack signature matching

Each component produces a score between 0 and 1, which are then weighted and combined into a final composite score that determines if a request is anomalous.

