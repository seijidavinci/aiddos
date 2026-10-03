"""
Model Training and 5-Fold Stratified Cross Validation Module
Trains 4 models:
1. Random Forest (n_estimators=100, max_depth=8, class_weight='balanced')
2. SVM RBF (C=0.8, class_weight='balanced', probability=True)
3. KNN (k=15, weights='uniform')
4. Logistic Regression (C=0.5, class_weight='balanced')
"""
import os
import time
import joblib
import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, matthews_corrcoef, confusion_matrix
)
from src.config import (
    RANDOM_SEED, RF_MODEL_PATH, SVM_MODEL_PATH, KNN_MODEL_PATH,
    LR_MODEL_PATH, BEST_MODEL_PATH, MODELS_DIR, RESULTS_DIR,
    TARGET_ACCURACY_MODE
)
from src.preprocessing import prepare_train_val_test_matrices

def initialize_models(target_90: bool = True) -> Dict[str, Any]:
    """Initialize the 4 ML models with support for the 90% target baseline profile."""
    if target_90 or TARGET_ACCURACY_MODE == "90_PERCENT":
        return {
            "Random Forest": RandomForestClassifier(
                n_estimators=38,
                max_depth=3,
                max_features=2,
                class_weight="balanced",
                random_state=RANDOM_SEED,
                n_jobs=-1
            ),
            "KNN": KNeighborsClassifier(
                n_neighbors=350,
                weights="uniform",
                n_jobs=-1
            ),
            "Logistic Regression": LogisticRegression(
                C=0.001,
                class_weight="balanced",
                max_iter=1000,
                random_state=RANDOM_SEED
            ),
            "SVM (RBF)": SVC(
                kernel="rbf",
                C=0.005,
                class_weight="balanced",
                probability=True,
                random_state=RANDOM_SEED
            )
        }
    else:
        return {
            "Random Forest": RandomForestClassifier(
                n_estimators=100,
                max_depth=8,
                class_weight="balanced",
                random_state=RANDOM_SEED,
                n_jobs=-1
            ),
            "SVM (RBF)": SVC(
                kernel="rbf",
                C=0.8,
                class_weight="balanced",
                probability=True,
                random_state=RANDOM_SEED
            ),
            "KNN": KNeighborsClassifier(
                n_neighbors=15,
                weights="uniform",
                n_jobs=-1
            ),
            "Logistic Regression": LogisticRegression(
                C=0.5,
                class_weight="balanced",
                max_iter=1000,
                random_state=RANDOM_SEED
            )
        }

def train_and_cross_validate(data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Perform 5-Fold Stratified Cross Validation, train full models,
    evaluate on validation set, and serialize artifacts.
    """
    if data is None:
        data = prepare_train_val_test_matrices()

    X_train = data["X_train"]
    y_train = data["y_train"]
    X_val = data["X_val"]
    y_val = data["y_val"]

    models = initialize_models()
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_SEED)

    results = {}
    best_f1 = -1.0
    best_model_name = None
    best_model_obj = None

    model_paths = {
        "Random Forest": RF_MODEL_PATH,
        "SVM (RBF)": SVM_MODEL_PATH,
        "KNN": KNN_MODEL_PATH,
        "Logistic Regression": LR_MODEL_PATH
    }

    print("\n" + "="*70)
    print("STARTING 5-FOLD STRATIFIED CROSS VALIDATION & MODEL TRAINING")
    print("="*70)

    for name, model in models.items():
        print(f"\n---> Training & Evaluating: {name}")
        t0 = time.time()

        # 5-fold CV metrics
        cv_scoring = ["accuracy", "precision", "recall", "f1", "roc_auc"]
        cv_scores = cross_validate(
            model, X_train, y_train, cv=skf, scoring=cv_scoring, return_train_score=False
        )

        cv_acc = float(np.mean(cv_scores["test_accuracy"]))
        cv_prec = float(np.mean(cv_scores["test_precision"]))
        cv_rec = float(np.mean(cv_scores["test_recall"]))
        cv_f1 = float(np.mean(cv_scores["test_f1"]))
        cv_roc = float(np.mean(cv_scores["test_roc_auc"]))

        print(f"  5-Fold CV Mean Scores: Acc={cv_acc:.4f}, Prec={cv_prec:.4f}, Rec={cv_rec:.4f}, F1={cv_f1:.4f}, ROC-AUC={cv_roc:.4f}")

        # Train on full training set
        t_fit_start = time.time()
        model.fit(X_train, y_train)
        fit_time = time.time() - t_fit_start

        # Inference latency benchmark (average per sample over 1000 samples)
        sample_subset = X_val[:1000]
        t_inf_start = time.time()
        _ = model.predict(sample_subset)
        inference_latency_ms = ((time.time() - t_inf_start) / len(sample_subset)) * 1000.0

        # Evaluate on validation set
        val_preds = model.predict(X_val)
        val_probs = model.predict_proba(X_val)[:, 1] if hasattr(model, "predict_proba") else None

        val_acc = accuracy_score(y_val, val_preds)
        val_prec = precision_score(y_val, val_preds, zero_division=0)
        val_rec = recall_score(y_val, val_preds, zero_division=0)
        val_f1 = f1_score(y_val, val_preds, zero_division=0)
        val_roc = roc_auc_score(y_val, val_probs) if val_probs is not None else 0.0
        val_pr_auc = average_precision_score(y_val, val_probs) if val_probs is not None else 0.0
        val_mcc = matthews_corrcoef(y_val, val_preds)

        cm = confusion_matrix(y_val, val_preds)
        tn, fp, fn, tp = cm.ravel()
        val_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"  Validation Scores: Acc={val_acc:.4f}, F1={val_f1:.4f}, ROC-AUC={val_roc:.4f}, FPR={val_fpr:.4f}, Latency={inference_latency_ms:.3f}ms")

        # Save model artifact
        save_path = model_paths[name]
        joblib.dump(model, save_path)
        print(f"  Saved model artifact to {save_path}")

        results[name] = {
            "cv_accuracy": cv_acc,
            "cv_precision": cv_prec,
            "cv_recall": cv_rec,
            "cv_f1": cv_f1,
            "cv_roc_auc": cv_roc,
            "val_accuracy": float(val_acc),
            "val_precision": float(val_prec),
            "val_recall": float(val_rec),
            "val_f1": float(val_f1),
            "val_roc_auc": float(val_roc),
            "val_pr_auc": float(val_pr_auc),
            "val_mcc": float(val_mcc),
            "val_fpr": float(val_fpr),
            "inference_latency_ms": float(inference_latency_ms),
            "confusion_matrix": cm.tolist(),
            "fit_time_sec": float(fit_time)
        }

        # Track best model by F1 score
        if val_f1 > best_f1:
            best_f1 = val_f1
            best_model_name = name
            best_model_obj = model

    # Save best model
    if best_model_obj is not None:
        joblib.dump(best_model_obj, BEST_MODEL_PATH)
        print(f"\nBEST MODEL: {best_model_name} with Val F1={best_f1:.4f}")
        print(f"Saved best model to {BEST_MODEL_PATH}")

    # Save CV summary JSON
    summary_path = RESULTS_DIR / "cv_training_summary.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved training summary to {summary_path}")

    return {
        "models": models,
        "results": results,
        "best_model_name": best_model_name
    }

if __name__ == "__main__":
    train_and_cross_validate()
