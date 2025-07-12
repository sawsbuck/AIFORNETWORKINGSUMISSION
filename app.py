import streamlit as st
import pandas as pd
import numpy as np
from urllib.parse import urlparse, parse_qs, unquote
import re
import time
from ml_model import URLThreatDetector
from feature_extractor import URLFeatureExtractor

# Initialize the model and feature extractor
@st.cache_resource
def load_model():
    """Load and cache the ML model"""
    detector = URLThreatDetector()
    detector.train_model()
    return detector

@st.cache_resource
def load_feature_extractor():
    """Load and cache the feature extractor"""
    return URLFeatureExtractor()

def main():
    st.set_page_config(
        page_title="URL Threat Detection System",
        page_icon="🔒",
        layout="wide"
    )
    
    # Header
    st.title("🔒 URL Threat Detection System")
    st.markdown("### Real-time XSS and SQL Injection Detection using Machine Learning")
    
    # About section
    st.markdown("---")
    st.markdown("""
    This application uses machine learning to detect:
    - **XSS (Cross-Site Scripting)** attacks
    - **SQL Injection** attacks
    - **Benign** URLs
    
    The system analyzes URL structure, parameters, and patterns to classify threats using advanced machine learning techniques.
    """)
    st.markdown("---")
    
    # Main content
    st.header("🔍 URL Analysis")
    
    # Analysis mode selection
    analysis_mode = st.radio(
        "Choose analysis mode:",
        ["Single URL", "Multiple URLs"],
        horizontal=True
    )
    
    if analysis_mode == "Single URL":
        # Single URL input
        url_input = st.text_area(
            "Enter URL to analyze:",
            height=100,
            placeholder="https://example.com/search?q=<script>alert('xss')</script>",
            help="Enter a URL to analyze for potential XSS or SQL injection threats"
        )
        
        # Analysis button
        if st.button("🔍 Analyze URL", type="primary"):
            if url_input.strip():
                analyze_url(url_input.strip())
            else:
                st.error("Please enter a URL to analyze")
    
    else:
        # Multiple URLs input
        st.subheader("📝 Batch URL Analysis")
        
        urls_input = st.text_area(
            "Enter multiple URLs (one per line):",
            height=200,
            placeholder="https://example.com/search?q=<script>alert('xss')</script>\nhttps://site.com/user?id=1' OR '1'='1\nhttps://normal-site.com/page?q=search",
            help="Enter multiple URLs separated by new lines"
        )
        
        # Batch analysis button
        if st.button("🔍 Analyze All URLs", type="primary"):
            if urls_input.strip():
                analyze_batch_urls(urls_input.strip())
            else:
                st.error("Please enter URLs to analyze")
    


def analyze_url(url):
    """Analyze the given URL for threats"""
    try:
        # Load model and feature extractor
        detector = load_model()
        feature_extractor = load_feature_extractor()
        
        # Show loading spinner
        with st.spinner("Analyzing URL..."):
            time.sleep(0.5)  # Simulate processing time
            
            # Extract features and make prediction
            features = feature_extractor.extract_features(url)
            prediction, confidence = detector.predict(url)
        
        # Display results
        st.header("🔍 Analysis Results")
        
        # Main threat classification
        col1, col2 = st.columns(2)
        
        with col1:
            threat_color = get_threat_color(prediction)
            st.markdown(f"### {threat_color} **{prediction.upper()}**")
        
        with col2:
            confidence_percent = confidence * 100
            st.metric("Confidence", f"{confidence_percent:.1f}%")
        
    except Exception as e:
        st.error(f"An error occurred during analysis: {str(e)}")

def analyze_batch_urls(urls_text):
    """Analyze multiple URLs and display results in a table"""
    try:
        # Load model and feature extractor
        detector = load_model()
        feature_extractor = load_feature_extractor()
        
        # Parse URLs from text
        urls = [url.strip() for url in urls_text.split('\n') if url.strip()]
        
        if not urls:
            st.error("No valid URLs found")
            return
        
        # Show progress
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        results = []
        
        for i, url in enumerate(urls):
            # Update progress
            progress = (i + 1) / len(urls)
            progress_bar.progress(progress)
            status_text.text(f"Analyzing URL {i+1}/{len(urls)}: {url[:50]}...")
            
            try:
                # Extract features and make prediction
                features = feature_extractor.extract_features(url)
                prediction, confidence = detector.predict(url)
                
                # Get threat color
                threat_color = get_threat_color(prediction)
                
                results.append({
                    "URL": url,
                    "Threat Type": f"{threat_color} {prediction.upper()}",
                    "Confidence": f"{confidence*100:.1f}%"
                })
                
            except Exception as e:
                results.append({
                    "URL": url,
                    "Threat Type": "❌ ERROR",
                    "Confidence": "N/A"
                })
        
        # Clear progress indicators
        progress_bar.empty()
        status_text.empty()
        
        # Display results
        st.header("📊 Batch Analysis Results")
        
        # Create DataFrame
        df = pd.DataFrame(results)
        
        # Display summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_urls = len(results)
            st.metric("Total URLs", total_urls)
        
        with col2:
            xss_count = sum(1 for r in results if 'XSS' in r['Threat Type'])
            st.metric("XSS Detected", xss_count)
        
        with col3:
            sqli_count = sum(1 for r in results if 'SQLI' in r['Threat Type'])
            st.metric("SQL Injection", sqli_count)
        
        with col4:
            benign_count = sum(1 for r in results if 'BENIGN' in r['Threat Type'])
            st.metric("Benign URLs", benign_count)
        
        # Display detailed results table
        st.subheader("📋 Detailed Results")
        st.dataframe(df, use_container_width=True)
        
    except Exception as e:
        st.error(f"An error occurred during batch analysis: {str(e)}")

def get_threat_color(prediction):
    """Get color indicator for threat type"""
    colors = {
        "xss": "🔴",
        "sqli": "🔴", 
        "benign": "🟢"
    }
    return colors.get(prediction, "🟡")

if __name__ == "__main__":
    main()
