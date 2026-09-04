"""
Model Training & Evaluation Pipeline for Phishing Detection.
Trains, validates, and compares multiple Machine Learning architectures:
- Random Forest Classifier (Primary Ensemble)
- Gradient Boosting / HistGradientBoosting Classifier
- Logistic Regression (Linear Baseline)
- Decision Tree Classifier (Tree Baseline)

Evaluates precision, recall, F1-score, ROC-AUC, FPR and exports artifacts.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve
)
from sklearn.preprocessing import StandardScaler

from ml_pipeline.features import FEATURE_COLUMNS
from ml_pipeline.dataset_builder import build_and_save_dataset


def train_and_evaluate_models(dataset_path: str = "ml_pipeline/data/phishing_dataset.csv", output_dir: str = "backend/models"):
    """Train models, evaluate on held-out test set, and serialize artifacts."""
    if not os.path.exists(dataset_path):
        print(f"[*] Dataset not found at {dataset_path}. Building dataset now...")
        df = build_and_save_dataset(dataset_path, n_samples=5000)
    else:
        print(f"[*] Loading dataset from {dataset_path}...")
        df = pd.read_csv(dataset_path)

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("ml_pipeline/models", exist_ok=True)

    X = df[FEATURE_COLUMNS].values
    y = df["label"].values

    # Stratified Train (70%), Val (15%), Test (15%) split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )

    print(f"[*] Split sizes - Train: {len(X_train)}, Validation: {len(X_val)}, Test: {len(X_test)}")

    # Define candidate models
    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=150, max_depth=16, min_samples_split=4, random_state=42, n_jobs=-1
        ),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=150, max_depth=12, learning_rate=0.08, random_state=42
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=120, max_depth=16, random_state=42, n_jobs=-1
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=10, random_state=42
        )
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model = None

    print("\n" + "=" * 65)
    print(f"{'Model':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1':<7} | {'ROC-AUC'}")
    print("-" * 65)

    for name, model in models.items():
        # Train
        model.fit(X_train, y_train)
        
        # Test predictions
        y_pred = model.predict(X_test)
        
        if hasattr(model, "predict_proba"):
            y_proba = model.predict_proba(X_test)[:, 1]
        else:
            y_proba = y_pred

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        auc = roc_auc_score(y_test, y_proba)
        
        # Confusion matrix: TN, FP, FN, TP
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
            "false_positive_rate": round(float(fpr), 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        }

        print(f"{name:<22} | {acc * 100:6.2f}%   | {prec * 100:6.2f}%   | {rec * 100:6.2f}%   | {f1:6.4f} | {auc:6.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model_name = name
            best_model = model

    print("=" * 65)
    print(f"\n[+] Champion Model Selected: '{best_model_name}' (F1-Score: {best_f1:.4f})")

    # Compute ROC and PR curves for champion model
    y_test_proba = best_model.predict_proba(X_test)[:, 1]
    fpr_curve, tpr_curve, _ = roc_curve(y_test, y_test_proba)
    prec_curve, rec_curve, _ = precision_recall_curve(y_test, y_test_proba)

    # Feature Importance (if available on best model)
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        for feat_name, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True):
            feature_importances[feat_name] = round(float(imp), 4)

    # Export Model Metrics & Visual Data
    metrics_payload = {
        "champion_model": best_model_name,
        "feature_columns": FEATURE_COLUMNS,
        "models_comparison": results,
        "champion_metrics": results[best_model_name],
        "feature_importances": feature_importances,
        "roc_curve": {
            "fpr": [round(float(x), 4) for x in fpr_curve[::max(1, len(fpr_curve)//30)]],
            "tpr": [round(float(x), 4) for x in tpr_curve[::max(1, len(tpr_curve)//30)]]
        },
        "dataset_stats": {
            "total_samples": int(len(df)),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "phishing_count": int((df["label"] == 1).sum()),
            "legitimate_count": int((df["label"] == 0).sum())
        }
    }

    # Save artifacts in backend and pipeline
    for directory in [output_dir, "ml_pipeline/models"]:
        model_path = os.path.join(directory, "phishing_model.joblib")
        metrics_path = os.path.join(directory, "model_metrics.json")
        
        joblib.dump(best_model, model_path)
        with open(metrics_path, "w", encoding="utf-8") as f:
            json.dump(metrics_payload, f, indent=2)

    print(f"\n[+] Production Model saved to: {os.path.join(output_dir, 'phishing_model.joblib')}")
    print(f"[+] Metrics & Diagnostics saved to: {os.path.join(output_dir, 'model_metrics.json')}")
    return metrics_payload


if __name__ == "__main__":
    train_and_evaluate_models()
