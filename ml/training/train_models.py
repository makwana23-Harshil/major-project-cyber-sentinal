"""
Cyber Sentinel - ML Training & Evaluation Pipeline
Trains and evaluates URL and Text Phishing Detection Models.
Computes real test-set metrics, confusion matrices, and serializes trained models for inference and XAI.
"""

import os
import sys
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Add parent path to allow imports from ml
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.dirname(CURRENT_DIR)
PROJECT_DIR = os.path.dirname(ML_DIR)
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from ml.feature_extraction.url_features import extract_url_features, FEATURE_COLUMN_NAMES
from ml.training.dataset_generator import generate_url_dataset, generate_text_dataset


def train_url_model(data_path: str = None) -> dict:
    """Train Random Forest URL Phishing Classifier."""
    print("\n" + "="*50)
    print(" [1/2] TRAINING URL PHISHING CLASSIFIER")
    print("="*50)
    
    if data_path and os.path.exists(data_path):
        df = pd.read_csv(data_path)
    else:
        print(">> Generating fresh URL dataset...")
        df = generate_url_dataset()
        os.makedirs(os.path.join(ML_DIR, "datasets"), exist_ok=True)
        df.to_csv(os.path.join(ML_DIR, "datasets", "url_dataset.csv"), index=False)
        
    print(f"Loaded {len(df)} URLs (Safe: {sum(df['label'] == 0)}, Malicious: {sum(df['label'] == 1)})")
    
    # Extract features for all URLs
    print(">> Extracting 33 URL features for each sample...")
    feature_rows = []
    for url in df['url']:
        res = extract_url_features(str(url))
        feature_rows.append([res['features'][col] for col in FEATURE_COLUMN_NAMES])
        
    X = np.array(feature_rows, dtype=np.float32)
    y = df['label'].values
    
    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    print(f"Train samples: {len(X_train)} | Test samples: {len(X_test)}")
    
    # Train Random Forest Classifier
    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        random_state=42,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    
    # Predictions and Evaluation
    y_pred = rf.predict(X_test)
    y_prob = rf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    # Feature importances
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": FEATURE_COLUMN_NAMES[i], "importance": float(round(importances[i], 4))}
        for i in sorted_idx[:15]
    ]
    
    print("\n--- URL Classifier Test Set Metrics ---")
    print(f"Accuracy:  {acc*100:.2f}%")
    print(f"Precision: {prec*100:.2f}%")
    print(f"Recall:    {rec*100:.2f}%")
    print(f"F1 Score:  {f1*100:.2f}%")
    print("Confusion Matrix [ [TN, FP], [FN, TP] ]:")
    print(cm)
    
    # Save Model
    models_dir = os.path.join(ML_DIR, "trained_models")
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(rf, os.path.join(models_dir, "url_model.joblib"))
    joblib.dump(FEATURE_COLUMN_NAMES, os.path.join(models_dir, "feature_names.joblib"))
    
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "confusion_matrix": cm,
        "total_test_samples": len(y_test),
        "top_features": top_features,
        "model_type": "RandomForestClassifier (120 trees)"
    }


def train_text_model(data_path: str = None) -> dict:
    """Train TF-IDF + Logistic Regression Text/Email/SMS Classifier."""
    print("\n" + "="*50)
    print(" [2/2] TRAINING TEXT / EMAIL / SMS PHISHING CLASSIFIER")
    print("="*50)
    
    if data_path and os.path.exists(data_path):
        df = pd.read_csv(data_path)
    else:
        print(">> Generating fresh Text dataset...")
        df = generate_text_dataset()
        os.makedirs(os.path.join(ML_DIR, "datasets"), exist_ok=True)
        df.to_csv(os.path.join(ML_DIR, "datasets", "text_dataset.csv"), index=False)
        
    print(f"Loaded {len(df)} Texts (Safe: {sum(df['label'] == 0)}, Malicious: {sum(df['label'] == 1)})")
    
    # Train / Test split
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        df['text'].values, df['label'].values, test_size=0.20, random_state=42, stratify=df['label'].values
    )
    
    # TF-IDF Vectorization
    print(">> Fitting TF-IDF Vectorizer (unigrams + bigrams)...")
    vectorizer = TfidfVectorizer(
        max_features=6000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        stop_words='english'
    )
    X_train_tfidf = vectorizer.fit_transform(X_train_raw)
    X_test_tfidf = vectorizer.transform(X_test_raw)
    
    # Logistic Regression Model
    print(">> Training Logistic Regression with L2 regularization...")
    lr = LogisticRegression(C=2.0, max_iter=1000, random_state=42)
    lr.fit(X_train_tfidf, y_train)
    
    # Evaluate
    y_pred = lr.predict(X_test_tfidf)
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    # Extract top phishing & top safe tokens from model coefficients for XAI
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = lr.coef_[0]
    
    # Highest positive coefficients = Phishing indicators
    top_phish_idx = np.argsort(coefs)[::-1][:20]
    top_phishing_tokens = [
        {"token": feature_names[i], "weight": float(round(coefs[i], 4))}
        for i in top_phish_idx
    ]
    
    # Most negative coefficients = Benign indicators
    top_safe_idx = np.argsort(coefs)[:20]
    top_safe_tokens = [
        {"token": feature_names[i], "weight": float(round(abs(coefs[i]), 4))}
        for i in top_safe_idx
    ]
    
    print("\n--- Text Classifier Test Set Metrics ---")
    print(f"Accuracy:  {acc*100:.2f}%")
    print(f"Precision: {prec*100:.2f}%")
    print(f"Recall:    {rec*100:.2f}%")
    print(f"F1 Score:  {f1*100:.2f}%")
    print("Confusion Matrix [ [TN, FP], [FN, TP] ]:")
    print(cm)
    
    # Save Model & Vectorizer
    models_dir = os.path.join(ML_DIR, "trained_models")
    os.makedirs(models_dir, exist_ok=True)
    joblib.dump(lr, os.path.join(models_dir, "text_model.joblib"))
    joblib.dump(vectorizer, os.path.join(models_dir, "tfidf_vectorizer.joblib"))
    
    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "confusion_matrix": cm,
        "total_test_samples": len(y_test),
        "top_phishing_tokens": top_phishing_tokens,
        "top_safe_tokens": top_safe_tokens,
        "model_type": "TF-IDF + LogisticRegression (C=2.0)"
    }


def run_pipeline():
    """Run full ML training and save consolidated metrics json."""
    print("="*60)
    print("   CYBER SENTINEL - ML TRAINING & EVALUATION PIPELINE   ")
    print("="*60)
    
    url_dataset_path = os.path.join(ML_DIR, "datasets", "url_dataset.csv")
    text_dataset_path = os.path.join(ML_DIR, "datasets", "text_dataset.csv")
    
    url_metrics = train_url_model(url_dataset_path)
    text_metrics = train_text_model(text_dataset_path)
    
    consolidated_metrics = {
        "platform": "Cyber Sentinel AI Platform",
        "url_classifier": url_metrics,
        "text_classifier": text_metrics,
        "overall_accuracy": round((url_metrics["accuracy"] + text_metrics["accuracy"]) / 2.0, 4),
        "status": "Trained & Calibrated"
    }
    
    metrics_path = os.path.join(ML_DIR, "trained_models", "model_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(consolidated_metrics, f, indent=2)
        
    print("\n" + "="*60)
    print(f"[SUCCESS] All models trained and saved to: {os.path.join(ML_DIR, 'trained_models')}")
    print(f"[SUCCESS] Metrics recorded at: {metrics_path}")
    print("="*60)
    return consolidated_metrics


if __name__ == "__main__":
    run_pipeline()
