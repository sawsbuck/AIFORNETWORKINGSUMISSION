import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
import re
from urllib.parse import urlparse, parse_qs, unquote
from feature_extractor import URLFeatureExtractor

class URLThreatDetector:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.feature_extractor = URLFeatureExtractor()
        self.is_trained = False
        
    def create_training_data(self):
        """Load training dataset from CSV files"""
        
        # Load data from CSV files
        xss_df = pd.read_csv('data/xss_examples.csv')
        sqli_df = pd.read_csv('data/sqli_examples.csv')
        benign_df = pd.read_csv('data/benign_examples.csv')
        
        # Combine all datasets
        data = pd.concat([xss_df, sqli_df, benign_df], ignore_index=True)
        
        return data
    
    def train_model(self):
        """Train the machine learning model"""
        if self.is_trained:
            return
        
        # Create training data
        df = self.create_training_data()
        
        # Extract features for all URLs
        X = []
        for url in df['url']:
            features = self.feature_extractor.extract_features(url)
            X.append(features)
        
        X = np.array(X)
        y = df['label'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        self.model.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model trained with accuracy: {accuracy:.3f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        self.is_trained = True
    
    def predict(self, url):
        """Predict threat type for a given URL"""
        if not self.is_trained:
            self.train_model()
        
        # Extract features
        features = self.feature_extractor.extract_features(url)
        features = np.array([features])
        
        # Make prediction
        prediction = self.model.predict(features)[0]
        
        # Get prediction probabilities
        probabilities = self.model.predict_proba(features)[0]
        confidence = max(probabilities)
        
        return prediction, confidence
    
    def get_feature_importance(self):
        """Get feature importance from the trained model"""
        if not self.is_trained:
            return None
        
        feature_names = self.feature_extractor.get_feature_names()
        importance = self.model.feature_importances_
        
        feature_importance = list(zip(feature_names, importance))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        return feature_importance
