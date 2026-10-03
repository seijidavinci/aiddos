"""
Comprehensive Model Evaluation and Visualization Module
Evaluates the 4 models across Test, Imbalanced Test, and Unseen Test sets.
Generates metrics, comparisons, and publication-quality plots.
"""
import os
import json
import joblib
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, matthews_corrcoef,
    confusion_matrix, roc_curve, precision_recall_curve
)
from src.config import (
    TEST_CSV, IMBALANCED_TEST_CSV, UNSEEN_TEST_CSV, FEATURE_NAMES,
    SCALER_PATH, RF_MODEL_PATH, SVM_MODEL_PATH, KNN_MODEL_PATH,
    LR_MODEL_PATH, RESULTS_DIR
)

# Style configuration for dark modern plots
plt.style.use("dark_background")
sns.set_theme(style="darkgrid", rc={"axes.facecolor": "#121826", "figure.facecolor": "#0d1117"})

def load_artifacts():
    """Load scaler and the 4 trained models."""
    scaler = joblib.load(SCALER_PATH)
    models = {
        "Random Forest": joblib.load(RF_MODEL_PATH),
        "SVM (RBF)": joblib.load(SVM_MODEL_PATH),
        "KNN": joblib.load(KNN_MODEL_PATH),
        "Logistic Regression": joblib.load(LR_MODEL_PATH)
    }
    return scaler, models

def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray = None) -> dict:
    """Compute complete metric suite."""
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    mcc = matthews_corrcoef(y_true, y_pred)

    roc_auc = roc_auc_score(y_true, y_prob) if y_prob is not None and len(np.unique(y_true)) > 1 else 0.0
    pr_auc = average_precision_score(y_true, y_prob) if y_prob is not None and len(np.unique(y_true)) > 1 else 0.0

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "pr_auc": float(pr_auc),
        "mcc": float(mcc),
        "fpr": float(fpr),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        "confusion_matrix": cm.tolist()
    }

def run_evaluation() -> dict:
    """Run evaluation on all datasets and generate plots."""
    scaler, models = load_artifacts()

    # Load datasets
    df_test = pd.read_csv(TEST_CSV)
    df_imb = pd.read_csv(IMBALANCED_TEST_CSV)
    df_unseen = pd.read_csv(UNSEEN_TEST_CSV) if os.path.exists(UNSEEN_TEST_CSV) else None

    # Preprocess
    X_test_scaled = scaler.transform(df_test[FEATURE_NAMES].values)
    y_test = df_test["is_ddos"].values

    X_imb_scaled = scaler.transform(df_imb[FEATURE_NAMES].values)
    y_imb = df_imb["is_ddos"].values

    if df_unseen is not None:
        X_unseen_scaled = scaler.transform(df_unseen[FEATURE_NAMES].values)
        y_unseen = df_unseen["is_ddos"].values
    else:
        X_unseen_scaled, y_unseen = None, None

    test_results = {}
    imb_results = {}
    unseen_results = {}

    print("\n" + "="*70)
    print("EVALUATING MODELS ON STANDARD TEST SET (1,800 SAMPLES)")
    print("="*70)

    # Dictionary to collect curves for plotting
    roc_data = {}
    pr_data = {}

    for name, model in models.items():
        # Inference latency
        t0 = time.time()
        preds = model.predict(X_test_scaled)
        latency_ms = ((time.time() - t0) / len(X_test_scaled)) * 1000.0

        probs = model.predict_proba(X_test_scaled)[:, 1] if hasattr(model, "predict_proba") else preds

        m = compute_metrics(y_test, preds, probs)
        m["latency_ms"] = float(latency_ms)
        test_results[name] = m

        print(f"\n[{name}]")
        print(f"  Accuracy:  {m['accuracy']*100:.2f}% | F1: {m['f1']:.4f} | ROC-AUC: {m['roc_auc']:.4f}")
        print(f"  Precision: {m['precision']:.4f} | Recall: {m['recall']:.4f} | MCC: {m['mcc']:.4f}")
        print(f"  FPR:       {m['fpr']*100:.2f}% | Latency: {m['latency_ms']:.4f} ms/sample")
        print(f"  Confusion: TP={m['tp']}, FP={m['fp']}, TN={m['tn']}, FN={m['fn']}")

        # Imbalanced test
        preds_imb = model.predict(X_imb_scaled)
        probs_imb = model.predict_proba(X_imb_scaled)[:, 1] if hasattr(model, "predict_proba") else preds_imb
        m_imb = compute_metrics(y_imb, preds_imb, probs_imb)
        imb_results[name] = m_imb

        # Unseen test
        if X_unseen_scaled is not None:
            preds_unseen = model.predict(X_unseen_scaled)
            probs_unseen = model.predict_proba(X_unseen_scaled)[:, 1] if hasattr(model, "predict_proba") else preds_unseen
            m_unseen = compute_metrics(y_unseen, preds_unseen, probs_unseen)
            unseen_results[name] = m_unseen

        # ROC & PR curves
        fpr_curve, tpr_curve, _ = roc_curve(y_test, probs)
        roc_data[name] = (fpr_curve, tpr_curve, m["roc_auc"])
        
        prec_curve, rec_curve, _ = precision_recall_curve(y_test, probs)
        pr_data[name] = (rec_curve, prec_curve, m["pr_auc"])

    # 1. Plot ROC Curves
    plt.figure(figsize=(9, 7))
    for name, (fpr_c, tpr_c, auc_val) in roc_data.items():
        plt.plot(fpr_c, tpr_c, lw=2, label=f"{name} (AUC = {auc_val:.4f})")
    plt.plot([0, 1], [0, 1], "w--", lw=1, alpha=0.5, label="Random Chance")
    plt.xlabel("False Positive Rate", fontsize=12, fontweight="bold")
    plt.ylabel("True Positive Rate (Recall)", fontsize=12, fontweight="bold")
    plt.title("ROC Curves Comparison - DDoS Detection Models", fontsize=14, fontweight="bold", pad=12)
    plt.legend(loc="lower right", frameon=True, facecolor="#161b22")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "roc_curves.png", dpi=300)
    plt.close()

    # 2. Plot PR Curves
    plt.figure(figsize=(9, 7))
    for name, (rec_c, prec_c, pr_auc_val) in pr_data.items():
        plt.plot(rec_c, prec_c, lw=2, label=f"{name} (PR-AUC = {pr_auc_val:.4f})")
    plt.xlabel("Recall", fontsize=12, fontweight="bold")
    plt.ylabel("Precision", fontsize=12, fontweight="bold")
    plt.title("Precision-Recall Curves Comparison", fontsize=14, fontweight="bold", pad=12)
    plt.legend(loc="lower left", frameon=True, facecolor="#161b22")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "pr_curves.png", dpi=300)
    plt.close()

    # 3. Plot Confusion Matrices
    fig, axes = plt.subplots(2, 2, figsize=(11, 9))
    axes = axes.flatten()
    for idx, (name, m) in enumerate(test_results.items()):
        cm = np.array(m["confusion_matrix"])
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=axes[idx], cbar=False,
                    xticklabels=["Benign", "DDoS"], yticklabels=["Benign", "DDoS"])
        axes[idx].set_title(f"{name}", fontsize=12, fontweight="bold")
        axes[idx].set_xlabel("Predicted Label")
        axes[idx].set_ylabel("Actual Label")
    plt.suptitle("Confusion Matrices on Test Set (1,800 samples)", fontsize=14, fontweight="bold", y=0.98)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "confusion_matrices.png", dpi=300)
    plt.close()

    # 4. Model Metric Comparison Bar Chart
    df_metrics = pd.DataFrame([
        {
            "Model": name,
            "Accuracy": m["accuracy"],
            "F1-Score": m["f1"],
            "ROC-AUC": m["roc_auc"],
            "MCC": m["mcc"]
        } for name, m in test_results.items()
    ])
    df_melted = df_metrics.melt(id_vars="Model", var_name="Metric", value_name="Score")

    plt.figure(figsize=(10, 6))
    sns.barplot(data=df_melted, x="Metric", y="Score", hue="Model", palette="coolwarm")
    plt.ylim(0.70, 1.02)
    plt.title("Model Performance Metrics Comparison", fontsize=14, fontweight="bold", pad=12)
    plt.ylabel("Score", fontsize=12, fontweight="bold")
    plt.legend(loc="lower right", frameon=True, facecolor="#161b22")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "model_comparison.png", dpi=300)
    plt.close()

    # 5. Attack Category Performance (for Best Model: Random Forest)
    best_model = models["Random Forest"]
    df_test["predicted"] = best_model.predict(X_test_scaled)
    category_acc = {}
    for cat, group in df_test.groupby("category"):
        acc = (group["predicted"] == group["is_ddos"]).mean()
        category_acc[cat] = acc

    plt.figure(figsize=(10, 5))
    cats = list(category_acc.keys())
    scores = list(category_acc.values())
    colors = ["#22c55e" if "benign" in c else "#38bdf8" for c in cats]
    plt.barh(cats, [s * 100 for s in scores], color=colors)
    plt.xlim(70, 105)
    plt.xlabel("Detection Accuracy (%)", fontsize=12, fontweight="bold")
    plt.title("Detection Accuracy by Attack Category (Random Forest)", fontsize=14, fontweight="bold", pad=12)
    for i, v in enumerate(scores):
        plt.text(v * 100 + 0.5, i, f"{v*100:.2f}%", va="center", fontweight="bold")
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "category_performance.png", dpi=300)
    plt.close()

    # Old baseline comparison
    baseline_old = {
        "KNN": {"Accuracy": 0.9083, "F1": 0.9077, "ROC-AUC": 0.9768, "FPR": 0.0844}
    }
    comparison_data = []
    for name, m in test_results.items():
        old_acc = baseline_old.get(name, {}).get("Accuracy", "-")
        old_f1 = baseline_old.get(name, {}).get("F1", "-")
        old_roc = baseline_old.get(name, {}).get("ROC-AUC", "-")
        old_fpr = baseline_old.get(name, {}).get("FPR", "-")

        comparison_data.append({
            "Model": name,
            "Old Baseline Acc": f"{old_acc*100:.2f}%" if isinstance(old_acc, float) else old_acc,
            "New Test Acc": f"{m['accuracy']*100:.2f}%",
            "Old Baseline F1": f"{old_f1:.4f}" if isinstance(old_f1, float) else old_f1,
            "New Test F1": f"{m['f1']:.4f}",
            "Old Baseline ROC-AUC": f"{old_roc:.4f}" if isinstance(old_roc, float) else old_roc,
            "New Test ROC-AUC": f"{m['roc_auc']:.4f}",
            "Old Baseline FPR": f"{old_fpr*100:.2f}%" if isinstance(old_fpr, float) else old_fpr,
            "New Test FPR": f"{m['fpr']*100:.2f}%",
            "Imbalanced Set F1": f"{imb_results[name]['f1']:.4f}",
            "Unseen Attack F1": f"{unseen_results[name]['f1']:.4f}" if name in unseen_results else "N/A",
            "Latency (ms)": f"{m['latency_ms']:.3f} ms"
        })

    df_comp = pd.DataFrame(comparison_data)
    df_comp.to_csv(RESULTS_DIR / "baseline_vs_new_comparison.csv", index=False)
    print("\n" + "="*70)
    print("BASELINE VS NEW RESULTS COMPARISON TABLE")
    print("="*70)
    print(df_comp.to_string(index=False))

    # Save full JSON report
    report = {
        "test_results": test_results,
        "imbalanced_results": imb_results,
        "unseen_results": unseen_results,
        "category_accuracy": category_acc
    }
    with open(RESULTS_DIR / "evaluation_report.json", "w") as f:
        json.dump(report, f, indent=2)

    return report

if __name__ == "__main__":
    run_evaluation()
