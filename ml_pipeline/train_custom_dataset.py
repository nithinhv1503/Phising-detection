"""
Custom Dataset Training Pipeline.
Ingests `dataset/phishing_site_urls.csv` (549,000+ real-world URLs),
maps 'bad' -> 1 (Phishing) and 'good' -> 0 (Legitimate),
extracts 25+ features in parallel using multiprocessing,
trains ensemble classifiers, and serializes the production model artifacts.
"""

import os
import json
import time
import joblib
import pandas as pd
import numpy as np
from multiprocessing import Pool, cpu_count
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve
)

from ml_pipeline.features import extract_url_features, FEATURE_COLUMNS


def extract_single_row(row_tuple):
    """Helper for parallel feature extraction with total exception safety."""
    idx, url, label_val = row_tuple
    try:
        feats = extract_url_features(str(url))
        feats["label"] = int(label_val)
        feats["url"] = str(url)
        return feats
    except Exception:
        # Fallback default features for malformed rows
        feats = {col: 0 for col in FEATURE_COLUMNS}
        feats["label"] = int(label_val)
        feats["url"] = str(url)
        return feats


def process_and_train(
    csv_path: str = "dataset/phishing_site_urls.csv",
    sample_size: int = 40000,
    output_dir: str = "backend/models"
):
    print(f"[*] Reading dataset from: {csv_path}")
    start_time = time.time()
    df_raw = pd.read_csv(csv_path)
    print(f"[*] Raw dataset loaded: {len(df_raw)} rows.")
    
    # Identify column names
    url_col = "URL" if "URL" in df_raw.columns else "url"
    label_col = "Label" if "Label" in df_raw.columns else "label"

    # Drop nulls and duplicates
    df_raw = df_raw.dropna(subset=[url_col, label_col]).drop_duplicates(subset=[url_col])
    
    # Map binary labels
    df_raw["binary_label"] = df_raw[label_col].apply(lambda x: 1 if str(x).strip().lower() in ["bad", "1", "phishing"] else 0)
    
    phish_total = (df_raw["binary_label"] == 1).sum()
    legit_total = (df_raw["binary_label"] == 0).sum()
    print(f"[*] Dataset counts -> Phishing (bad): {phish_total}, Legitimate (good): {legit_total}")

    # Stratified sampling for fast, ultra-accurate training (e.g. 40,000 balanced URLs)
    if len(df_raw) > sample_size:
        print(f"[*] Taking balanced stratified sample of {sample_size} URLs for rapid multi-model training...")
        df_phish = df_raw[df_raw["binary_label"] == 1].sample(n=sample_size // 2, random_state=42)
        df_legit = df_raw[df_raw["binary_label"] == 0].sample(n=sample_size // 2, random_state=42)
        df_sample = pd.concat([df_phish, df_legit]).sample(frac=1.0, random_state=42).reset_index(drop=True)
    else:
        df_sample = df_raw.sample(frac=1.0, random_state=42).reset_index(drop=True)

    processed_csv = "ml_pipeline/data/custom_dataset_features.csv"
    if os.path.exists(processed_csv) and os.path.getsize(processed_csv) > 10000:
        print(f"[*] Found pre-extracted feature matrix at {processed_csv}. Loading directly...")
        df_features = pd.read_csv(processed_csv)
    else:
        print(f"[*] Extracting 25+ features in parallel across {cpu_count()} CPU cores...")
        rows_to_process = [
            (i, row[url_col], row["binary_label"])
            for i, row in df_sample.iterrows()
        ]

        with Pool(processes=max(1, cpu_count() - 1)) as pool:
            feature_dicts = pool.map(extract_single_row, rows_to_process)

        df_features = pd.DataFrame(feature_dicts)
        
        # Save processed features CSV
        os.makedirs("ml_pipeline/data", exist_ok=True)
        df_features.to_csv(processed_csv, index=False)
        print(f"[+] Feature matrix saved to: {processed_csv}")

    # Prepare Training & Testing Splits
    X = df_features[FEATURE_COLUMNS].values
    y = df_features["label"].values

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=42
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )

    print(f"[*] Train set: {len(X_train)} | Val set: {len(X_val)} | Test set: {len(X_test)}")

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=160, max_depth=18, min_samples_split=4, random_state=42, n_jobs=-1
        ),
        "Extra Trees": ExtraTreesClassifier(
            n_estimators=140, max_depth=18, random_state=42, n_jobs=-1
        ),
        "Gradient Boosting": HistGradientBoostingClassifier(
            max_iter=150, max_depth=12, learning_rate=0.08, random_state=42
        ),
        "Decision Tree": DecisionTreeClassifier(
            max_depth=12, random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter=1000, random_state=42
        )
    }

    results = {}
    best_model_name = None
    best_f1 = -1.0
    best_model = None

    print("\n" + "=" * 68)
    print(f"{'Model Architecture':<22} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<9} | {'F1':<7} | {'ROC-AUC'}")
    print("-" * 68)

    for name, model in models.items():
        model.fit(X_train, y_train)
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

    print("=" * 68)
    print(f"\n[+] Champion Model: '{best_model_name}' (F1: {best_f1:.4f})")

    # Compute ROC curve for champion model
    y_test_proba = best_model.predict_proba(X_test)[:, 1]
    fpr_curve, tpr_curve, _ = roc_curve(y_test, y_test_proba)

    # Feature Importance
    feature_importances = {}
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        for feat_name, imp in sorted(zip(FEATURE_COLUMNS, importances), key=lambda x: x[1], reverse=True):
            feature_importances[feat_name] = round(float(imp), 4)

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
            "source_file": csv_path,
            "total_raw_records": int(len(df_raw)),
            "sampled_records": int(len(df_sample)),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "phishing_count": int((df_features["label"] == 1).sum()),
            "legitimate_count": int((df_features["label"] == 0).sum())
        }
    }

    # Save to backend/models and ml_pipeline/models
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("ml_pipeline/models", exist_ok=True)
    
    for d in [output_dir, "ml_pipeline/models"]:
        joblib.dump(best_model, os.path.join(d, "phishing_model.joblib"))
        with open(os.path.join(d, "model_metrics.json"), "w", encoding="utf-8") as f:
            json.dump(metrics_payload, f, indent=2)

    total_time = round(time.time() - start_time, 2)
    print(f"\n[+] Successfully trained & serialized models from custom dataset in {total_time}s!")
    print(f"[+] Model saved to: {os.path.join(output_dir, 'phishing_model.joblib')}")
    print(f"[+] Metrics saved to: {os.path.join(output_dir, 'model_metrics.json')}")
    return metrics_payload


if __name__ == "__main__":
    process_and_train()
