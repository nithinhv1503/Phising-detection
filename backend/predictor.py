"""
Real-time Phishing Detection & Explainability Inference Engine.
Combines Machine Learning prediction with Threat Intelligence overrides,
extracts feature explanations, and computes risk confidence scores in <10ms.
"""

import os
import time
import json
import joblib
import numpy as np

from ml_pipeline.features import extract_url_features, extract_dom_features, FEATURE_COLUMNS
from backend.threat_intel import threat_intel

DEFAULT_MODEL_PATH = "backend/models/phishing_model.joblib"
DEFAULT_METRICS_PATH = "backend/models/model_metrics.json"


class PhishingPredictor:
    def __init__(self, model_path: str = DEFAULT_MODEL_PATH, metrics_path: str = DEFAULT_METRICS_PATH):
        self.model_path = model_path
        self.metrics_path = metrics_path
        self.model = None
        self.metrics = {}
        self.load_model()

    def load_model(self):
        """Load trained model and metrics metadata."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"[+] Loaded ML model from {self.model_path}")
            except Exception as e:
                print(f"[-] Error loading model: {e}")
                self.model = None

        if os.path.exists(self.metrics_path):
            try:
                with open(self.metrics_path, "r", encoding="utf-8") as f:
                    self.metrics = json.load(f)
            except Exception as e:
                print(f"[-] Error loading metrics: {e}")

    def explain_features(self, features: dict) -> list:
        """
        Generate human-interpretable explanations for detected risk indicators.
        Returns a list of identified risk factors with severity weights.
        """
        factors = []
        
        if features.get("has_ip", 0) == 1:
            factors.append({
                "factor": "Raw IP Address Host",
                "severity": "CRITICAL",
                "detail": "Website uses a direct numerical IP address instead of a registered domain name."
            })
            
        if features.get("has_brand_spoofing", 0) == 1:
            factors.append({
                "factor": "Targeted Brand Spoofing",
                "severity": "HIGH",
                "detail": "Recognized brand name detected in subdomains or path on an unrelated host."
            })
            
        if features.get("tld_in_subdomain", 0) == 1:
            factors.append({
                "factor": "Deceptive TLD in Subdomain",
                "severity": "HIGH",
                "detail": "URL embeds '.com' or '.org' inside subdomains to mimic genuine service hosts."
            })
            
        if features.get("keyword_count", 0) >= 2:
            factors.append({
                "factor": f"Multiple Urgency/Auth Keywords ({features['keyword_count']})",
                "severity": "MEDIUM",
                "detail": "URL contains multiple sensitive triggers like login, verify, banking, or password."
            })
            
        if features.get("is_suspicious_tld", 0) == 1:
            factors.append({
                "factor": "High-Abuse Top Level Domain",
                "severity": "MEDIUM",
                "detail": "Domain uses a TLD frequently associated with disposable phishing campaigns."
            })
            
        if features.get("has_double_slash", 0) == 1:
            factors.append({
                "factor": "Path Redirection Anomaly",
                "severity": "MEDIUM",
                "detail": "Embedded double-slash ('//') detected inside URL path."
            })
            
        if features.get("is_shortened", 0) == 1:
            factors.append({
                "factor": "URL Shortener Masking",
                "severity": "LOW",
                "detail": "Destination is hidden behind a generic link shortening redirector."
            })
            
        if features.get("is_https", 0) == 0:
            factors.append({
                "factor": "Unencrypted HTTP Connection",
                "severity": "LOW",
                "detail": "Site transmits data in plain text without SSL/TLS encryption."
            })
            
        if features.get("entropy", 0.0) > 4.4:
            factors.append({
                "factor": "High String Entropy / Obfuscation",
                "severity": "MEDIUM",
                "detail": "URL character distribution appears randomized or encoded."
            })

        return factors

    def predict(self, url: str, html: str = None) -> dict:
        """
        Evaluate full URL risk score using Threat Intel + ML Model + DOM heuristic.
        """
        start_time = time.perf_counter()
        
        # 1. Threat Intel Fast-Check (Whitelist / Blocklist)
        reputation = threat_intel.check_reputation(url)
        
        # 2. Extract Feature Vector
        features = extract_url_features(url)
        feature_vector = [features[col] for col in FEATURE_COLUMNS]
        
        # 3. DOM Features (if provided by browser content script)
        dom_features = extract_dom_features(html, current_domain=url) if html else None
        
        # 4. ML Model Inference
        ml_prob = 0.5
        model_name = self.metrics.get("champion_model", "Random Forest Ensemble")
        
        if self.model is not None:
            try:
                vec = np.array([feature_vector])
                if hasattr(self.model, "predict_proba"):
                    ml_prob = float(self.model.predict_proba(vec)[0][1])
                else:
                    ml_prob = float(self.model.predict(vec)[0])
            except Exception as e:
                print(f"[-] Inference error: {e}")
                ml_prob = 0.5
        else:
            # Fallback heuristic if model file is still compiling
            ml_prob = 0.85 if (features["has_ip"] or features["has_brand_spoofing"] or features["tld_in_subdomain"]) else 0.15

        # 5. Integrate Threat Intelligence Overrides
        final_score = ml_prob
        
        if reputation["status"] == "whitelisted":
            final_score = 0.02 # Safe override
            verdict = "LEGITIMATE"
            risk_level = "SAFE"
        elif reputation["status"] == "blacklisted":
            final_score = 0.99 # Phishing override
            verdict = "PHISHING"
            risk_level = "CRITICAL"
        else:
            # Adjust with DOM heuristics if present
            if dom_features:
                if dom_features["has_password_field"] and features["is_https"] == 0:
                    final_score = min(1.0, final_score + 0.35)
                if dom_features["insecure_form_action"]:
                    final_score = min(1.0, final_score + 0.25)
            
            # Map score to Verdict
            if final_score >= 0.70:
                verdict = "PHISHING"
                risk_level = "HIGH"
            elif final_score >= 0.40:
                verdict = "SUSPICIOUS"
                risk_level = "MEDIUM"
            else:
                verdict = "LEGITIMATE"
                risk_level = "LOW"

        risk_score_percentage = round(final_score * 100, 2)
        confidence = round(float(abs(final_score - 0.5) * 2), 4) # 0 to 1 confidence
        
        # Risk factors breakdown
        risk_factors = self.explain_features(features)
        
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return {
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score_percentage,
            "risk_level": risk_level,
            "confidence": confidence,
            "threat_intel_status": reputation["status"],
            "reputation_reason": reputation["reason"],
            "model_used": model_name,
            "latency_ms": elapsed_ms,
            "risk_factors": risk_factors,
            "features": features,
            "dom_features": dom_features
        }


# Global predictor instance
predictor = PhishingPredictor()
