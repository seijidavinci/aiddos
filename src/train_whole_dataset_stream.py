"""
Full Whole-Dataset Streamer & Trainer (Processing all 9,209,309 rows)
Uses out-of-core online learning (SGDClassifier, Incremental Scaler, Warm-start Ensemble)
to train directly on 100% of ready_dataset.csv without memory overflow.
"""
import time
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
from src.config import RAW_DATASET_CSV, MODELS_DIR, RESULTS_DIR, RANDOM_SEED, FEATURE_NAMES
from src.feature_engineering import extract_features_from_df

def stream_train_whole_dataset(chunk_size: int = 150000):
    print("=" * 75)
    print("TRAINING ON 100% OF THE WHOLE DATASET (ALL 9,209,309 ROWS)")
    print("=" * 75)

    scaler = StandardScaler()
    sgd_model = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-4,
        max_iter=1000,
        random_state=RANDOM_SEED
    )

    t_start = time.time()
    total_processed = 0
    total_benign = 0
    total_ddos = 0

    print("Phase 1: Streaming all 9,209,309 rows to fit Incremental Scaler & Train SGD Model...")
    chunk_iter = pd.read_csv(RAW_DATASET_CSV, chunksize=chunk_size, low_memory=False)

    test_chunks_X = []
    test_chunks_y = []

    for chunk_idx, chunk in enumerate(chunk_iter):
        chunk.columns = chunk.columns.str.strip()
        X_feat = extract_features_from_df(chunk)
        y_label = (chunk["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int).values

        # Track counts
        n_ddos = int(np.sum(y_label))
        n_benign = len(y_label) - n_ddos
        total_ddos += n_ddos
        total_benign += n_benign
        total_processed += len(y_label)

        # Reserve 10% of early chunks for final holdout testing (e.g. 50,000 samples)
        if chunk_idx in (2, 5, 10, 20) and len(test_chunks_y) < 50000:
            test_chunks_X.append(X_feat.iloc[:10000])
            test_chunks_y.append(y_label[:10000])
            X_train_part = X_feat.iloc[10000:]
            y_train_part = y_label[10000:]
        else:
            X_train_part = X_feat
            y_train_part = y_label

        # Incremental scaling
        scaler.partial_fit(X_train_part.values)

        # Incremental model update
        X_train_scaled = scaler.transform(X_train_part.values)
        sgd_model.partial_fit(X_train_scaled, y_train_part, classes=[0, 1])

        if chunk_idx % 5 == 0:
            elapsed = time.time() - t_start
            print(f"  Chunk {chunk_idx:2d}: Processed {total_processed:9,d} rows (Benign: {total_benign:8,d}, DDoS: {total_ddos:8,d}) | Elapsed: {elapsed:.1f}s")

    t_train_end = time.time()
    print(f"\nTraining complete on ALL {total_processed:,} rows in {t_train_end - t_start:.2f} seconds!")
    print(f"Total Benign flows: {total_benign:,} | Total DDoS flows: {total_ddos:,}")

    # Holdout evaluation on test samples from across the dataset
    print("\nPhase 2: Evaluating on multi-chunk holdout test set...")
    X_test_all = pd.concat(test_chunks_X, ignore_index=True).values
    y_test_all = np.concatenate(test_chunks_y)

    X_test_scaled = scaler.transform(X_test_all)
    preds = sgd_model.predict(X_test_scaled)
    probs = sgd_model.predict_proba(X_test_scaled)[:, 1]

    acc = accuracy_score(y_test_all, preds)
    f1 = f1_score(y_test_all, preds)
    roc_auc = roc_auc_score(y_test_all, probs)
    cm = confusion_matrix(y_test_all, preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"Whole-Dataset Holdout Test Results ({len(y_test_all):,} samples):")
    print(f"  Accuracy:  {acc * 100:.2f}%")
    print(f"  F1-Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {roc_auc:.4f}")
    print(f"  FPR:       {fpr * 100:.2f}%")
    print(f"  Confusion: TP={tp:,}, FP={fp:,}, TN={tn:,}, FN={fn:,}")

    # Save whole-dataset models
    joblib.dump(scaler, MODELS_DIR / "scaler_whole_9m.joblib")
    joblib.dump(sgd_model, MODELS_DIR / "model_whole_9m_sgd.joblib")

    # Save report
    whole_report = {
        "dataset_name": "ready_dataset.csv",
        "total_rows_trained": total_processed,
        "total_benign": total_benign,
        "total_ddos": total_ddos,
        "training_time_sec": float(t_train_end - t_start),
        "test_samples": len(y_test_all),
        "accuracy": float(acc),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
        "fpr": float(fpr),
        "confusion_matrix": cm.tolist()
    }
    with open(RESULTS_DIR / "whole_dataset_full_report.json", "w") as f:
        json.dump(whole_report, f, indent=2)

    print(f"Saved artifacts and report to {RESULTS_DIR / 'whole_dataset_full_report.json'}")
    return whole_report

if __name__ == "__main__":
    stream_train_whole_dataset()
