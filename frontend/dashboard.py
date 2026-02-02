"""
Streamlit Dashboard for Online Learning Anomaly Detector
Real-time visualization of the detection system
"""

import streamlit as st
import sys
import os
from datetime import datetime
import pandas as pd
import time

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from online_detector import OnlineDetector
from data_generator import generate_log_stream

# Page configuration
st.set_page_config(
    page_title="🛡️ Serverless Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .anomaly-alert {
        background-color: #ffcccc;
        padding: 15px;
        border-radius: 5px;
        border-left: 4px solid #ff0000;
        margin: 10px 0;
    }
    .normal-log {
        background-color: #ccffcc;
        padding: 15px;
        border-radius: 5px;
        border-left: 4px solid #00cc00;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state
if 'detector' not in st.session_state:
    st.session_state.detector = OnlineDetector(learning_window=50, anomaly_threshold_std=2.5)
    st.session_state.logs_processed = 0

# Title and description
st.title("🛡️ Serverless Anomaly Detection System")
st.markdown("**Real-time Online Learning Anomaly Detector for AWS Lambda**")
st.markdown("---")

# Sidebar controls
st.sidebar.header("⚙️ Configuration")
num_logs = st.sidebar.slider("Number of logs to process", 10, 200, 100)
anomaly_rate = st.sidebar.slider("Anomaly rate in test data", 0.0, 0.5, 0.1, step=0.05)
auto_run = st.sidebar.checkbox("Auto-run simulation", value=False)

# Main layout
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("📊 Total Requests", st.session_state.detector.requests_seen)

with col2:
    st.metric("🚨 Anomalies Detected", st.session_state.detector.anomalies_detected)

with col3:
    phase_text = "🎓 Learning" if st.session_state.detector.learning_phase else "🔍 Detection"
    st.metric("Phase", phase_text)

with col4:
    progress = st.session_state.detector.requests_seen / st.session_state.detector.learning_window * 100
    progress = min(progress, 100)
    st.metric("Progress", f"{progress:.0f}%")

st.markdown("---")

# Learning phase indicator
if st.session_state.detector.learning_phase:
    progress = st.session_state.detector.requests_seen / st.session_state.detector.learning_window
    st.info(f"🎓 **Learning Phase**: Building baseline statistics... ({st.session_state.detector.requests_seen}/{st.session_state.detector.learning_window})")
    st.progress(progress)
else:
    st.success("✅ **Detection Mode Active**: Model is now detecting anomalies and adapting to normal changes.")

st.markdown("---")

# Generate and process logs
if st.button("🚀 Run Simulation", use_container_width=True):
    st.session_state.logs_processed = 0
    logs = generate_log_stream(num_logs=num_logs, anomaly_rate=anomaly_rate)
    
    # Create placeholders for real-time updates
    progress_placeholder = st.empty()
    results_placeholder = st.empty()
    
    # Process logs
    all_results = []
    for idx, log in enumerate(logs):
        result = st.session_state.detector.process_log(log)
        all_results.append(result)
        st.session_state.logs_processed += 1
        
        # Update progress
        with progress_placeholder.container():
            progress_bar = st.session_state.logs_processed / num_logs
            st.progress(progress_bar)
            st.caption(f"Processing: {st.session_state.logs_processed}/{num_logs}")
        
        time.sleep(0.05)  # Simulate real-time processing
    
    # Display results
    with results_placeholder.container():
        st.subheader("📋 Simulation Results")
        
        # Summary statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Logs Processed", st.session_state.detector.requests_seen)
        with col2:
            st.metric("Anomalies Found", st.session_state.detector.anomalies_detected)
        with col3:
            detection_rate = (st.session_state.detector.anomalies_detected / st.session_state.detector.requests_seen * 100) if st.session_state.detector.requests_seen > 0 else 0
            st.metric("Detection Rate", f"{detection_rate:.1f}%")
        
        # Recent detections
        st.subheader("🔍 Recent Detections")
        history = st.session_state.detector.get_history(limit=20)
        
        for result in reversed(history):
            if result.get('is_anomaly'):
                st.markdown(f"""
                <div class="anomaly-alert">
                    <strong>🚨 ANOMALY DETECTED</strong><br>
                    Score: {result.get('anomaly_score', 0):.2f} | 
                    Duration: {result.get('features', {}).get('duration', 0):.0f}ms | 
                    Memory: {result.get('features', {}).get('memory_used', 0):.0f}MB
                </div>
                """, unsafe_allow_html=True)
            else:
                if result.get('phase') == 'detection':
                    st.markdown(f"""
                    <div class="normal-log">
                        <strong>✅ Normal</strong><br>
                        Score: {result.get('anomaly_score', 0):.2f} | 
                        Duration: {result.get('features', {}).get('duration', 0):.0f}ms | 
                        Memory: {result.get('features', {}).get('memory_used', 0):.0f}MB
                    </div>
                    """, unsafe_allow_html=True)

# Baseline statistics
st.markdown("---")
st.subheader("📊 Current Baseline Statistics")

status = st.session_state.detector.get_status()
baseline = status['baseline']

col1, col2, col3 = st.columns(3)

with col1:
    st.write("**Duration (ms)**")
    duration_stats = baseline['duration']
    st.metric("Mean", f"{duration_stats['mean']:.1f}")
    st.metric("Std Dev", f"{duration_stats['std']:.1f}")

with col2:
    st.write("**Memory (MB)**")
    memory_stats = baseline['memory_used']
    st.metric("Mean", f"{memory_stats['mean']:.1f}")
    st.metric("Std Dev", f"{memory_stats['std']:.1f}")

with col3:
    st.write("**API Calls**")
    calls_stats = baseline['num_api_calls']
    st.metric("Mean", f"{calls_stats['mean']:.1f}")
    st.metric("Std Dev", f"{calls_stats['std']:.1f}")

# Footer
st.markdown("---")
st.caption("🛡️ Serverless Anomaly Detector | Online Learning System | Built with Streamlit")
