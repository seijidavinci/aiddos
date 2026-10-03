"""
Whole-Dataset Scaled Training Module
Trains high-capacity models on a large-scale partition from the 9,209,309-row ready_dataset.csv
Demonstrating scalability from the 12k baseline to large-scale production deployment.
"""
import os
import time
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
from src.config import (
    RAW_DATASET_CSV, MODELS_DIR, RESULTS_DIR, RANDOM_SEED, FEATURE_NAMES
)
from src.feature_engineering import extract_features_from_df
from src.preprocessing import PreprocessingPipeline

def train_on_large_partition(target_samples: int = 150000):
    print(f"\n{'='*70}")
    print(f"WHOLE DATASET SCALE TRAINING (Target: {target_samples} samples from ready_dataset.csv)")
    print(f"{'='*70}")

    collected_benign = []
    collected_ddos = []
    half_target = target_samples // 2

    b_count = 0
    d_count = 0

    print("Streaming ready_dataset.csv for large-scale training...")
    chunk_iter = pd.read_csv(RAW_DATASET_CSV, chunksize=100000, low_memory=False)

    for i, chunk in enumerate(chunk_iter):
        chunk.columns = chunk.columns.str.strip()
        lbl_series = chunk["Label"].astype(str).str.strip().str.upper()

        # Benign
        if b_count < half_target:
            b_chunk = chunk[lbl_series == "BENIGN"]
            if not b_chunk.empty:
                take = min(len(b_chunk), half_target - b_count)
                collected_benign.append(b_chunk.iloc[:take])
                b_count += take

        # DDoS
        if d_count < half_target:
            d_chunk = chunk[lbl_series != "BENIGN"]
            if not d_chunk.empty:
                take = min(len(d_chunk), half_target - d_count)
                collected_ddos.append(d_chunk.iloc[:take])
                d_count += take

        if b_count >= half_target and d_count >= half_target:
            print(f"Collected {b_count} Benign and {d_count} DDoS rows at chunk {i}!")
            break

    df_b = pd.concat(collected_benign, ignore_index=True)
    df_b["is_ddos"] = 0
    df_d = pd.concat(collected_ddos, ignore_index=True)
    df_d["is_ddos"] = 1

    df_full = pd.concat([df_b, df_d], ignore_index=True).sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    print(f"Total dataset shape: {df_full.shape}")

    # Extract 14 features
    print("Extracting 14 live-compatible features...")
    X_df = extract_features_from_df(df_full)
    y = df_full["is_ddos"].values

    # Train / Test split 80/20
    split_idx = int(len(df_full) * 0.8)
    X_train_raw = X_df.iloc[:split_idx]
    y_train = y[:split_idx]
    X_test_raw = X_df.iloc[split_idx:]
    y_test = y[split_idx:]

    pipeline = PreprocessingPipeline(
        scaler_path=str(MODELS_DIR / "scaler_large.joblib"),
        metadata_path=str(MODELS_DIR / "feature_metadata_large.json")
    )
    X_train_scaled = pipeline.fit_transform(X_train_raw)
    X_test_scaled = pipeline.transform(X_test_raw)

    # 1. Scaled Random Forest
    print(f"Fitting Scaled Random Forest on {len(X_train_scaled)} samples...")
    t0 = time.time()
    rf_large = RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=RANDOM_SEED, n_jobs=-1)
    rf_large.fit(X_train_scaled, y_train)
    rf_fit_time = time.time() - t0

    preds_rf = rf_large.predict(X_test_scaled)
    probs_rf = rf_large.predict_proba(X_test_scaled)[:, 1]

    acc_rf = accuracy_score(y_test, preds_rf)
    f1_rf = f1_score(y_test, preds_rf)
    roc_rf = roc_auc_score(y_test, probs_rf)
    cm_rf = confusion_matrix(y_test, preds_rf)
    tn, fp, fn, tp = cm_rf.ravel()
    fpr_rf = fp / (fp + tn)

    print(f"Scaled Random Forest Results on {len(y_test)} Test Samples:")
    print(f"  Acc: {acc_rf*100:.2f}% | F1: {f1_rf:.4f} | ROC-AUC: {roc_rf:.4f} | FPR: {fpr_rf*100:.2f}% (Fit: {rf_fit_time:.2f}s)")

    # 2. Scaled Fast SGD Classifier
    print(f"Fitting Large-scale SGD Classifier on {len(X_train_scaled)} samples...")
    t0 = time.time()
    sgd = SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, max_iter=2000, random_state=RANDOM_SEED)
    sgd.fit(X_train_scaled, y_train)
    sgd_fit_time = time.time() - t0

    preds_sgd = sgd.predict(X_test_scaled)
    probs_sgd = sgd.predict_proba(X_test_scaled)[:, 1]
    acc_sgd = accuracy_score(y_test, preds_sgd)
    f1_sgd = f1_score(y_test, preds_sgd)
    roc_sgd = roc_auc_score(y_test, probs_sgd)

    print(f"Scaled SGD Classifier Results:")
    print(f"  Acc: {acc_sgd*100:.2f}% | F1: {f1_sgd:.4f} | ROC-AUC: {roc_sgd:.4f} (Fit: {sgd_fit_time:.2f}s)")

    # Save artifacts
    joblib.dump(rf_large, MODELS_DIR / "whole_dataset_rf.joblib")
    joblib.dump(sgd, MODELS_DIR / "whole_dataset_sgd.joblib")

    results_scale = {
        "sample_size": target_samples,
        "train_size": len(X_train_scaled),
        "test_size": len(X_test_scaled),
        "random_forest": {
            "accuracy": float(acc_rf),
            "f1": float(f1_rf),
            "roc_auc": float(roc_rf),
            "fpr": float(fpr_rf),
            "confusion_matrix": cm_rf.tolist(),
            "fit_time_sec": float(rf_fit_time)
        },
        "sgd_classifier": {
            "accuracy": float(acc_sgd),
            "f1": float(f1_sgd),
            "roc_auc": float(roc_sgd),
            "fit_time_sec": float(sgd_fit_time)
        }
    }
    with open(RESULTS_DIR / "whole_dataset_evaluation.json", "w") as f:
        json.dump(results_scale, f, indent=2)
    print(f"Saved whole-dataset evaluation to {RESULTS_DIR / 'whole_dataset_evaluation.json'}")

if __name__ == "__main__":
    train_on_large_partition(150000)
