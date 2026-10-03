"""
Models Route - Returns model performance, comparisons, and architecture details
"""
import os
import json
from fastapi import APIRouter
from src.config import RESULTS_DIR, MODELS_DIR, FEATURE_NAMES

router = APIRouter(prefix="/api/models", tags=["Models"])

@router.get("")
def get_models_overview():
    eval_report_path = RESULTS_DIR / "evaluation_report.json"
    cv_summary_path = RESULTS_DIR / "cv_training_summary.json"
    whole_report_path = RESULTS_DIR / "whole_dataset_full_report.json"

    eval_data = {}
    if os.path.exists(eval_report_path):
        with open(eval_report_path) as f:
            eval_data = json.load(f)

    cv_data = {}
    if os.path.exists(cv_summary_path):
        with open(cv_summary_path) as f:
            cv_data = json.load(f)

    whole_data = {}
    if os.path.exists(whole_report_path):
        with open(whole_report_path) as f:
            whole_data = json.load(f)

    whole_eval_path = RESULTS_DIR / "whole_dataset_evaluation.json"
    whole_eval_data = {}
    if os.path.exists(whole_eval_path):
        with open(whole_eval_path) as f:
            whole_eval_data = json.load(f)

    old_baseline = {
        "KNN": {"accuracy": 0.9083, "f1": 0.9077, "roc_auc": 0.9768, "fpr": 0.0844},
        "Random Forest": {"accuracy": 0.9750, "f1": 0.9740, "roc_auc": 0.9980, "fpr": 0.0120}
    }

    return {
        "current_active_model": "Random Forest (Best Val F1: 0.9843)",
        "feature_count": len(FEATURE_NAMES),
        "features": FEATURE_NAMES,
        "test_results": eval_data.get("test_results", {}),
        "imbalanced_results": eval_data.get("imbalanced_results", {}),
        "unseen_results": eval_data.get("unseen_results", {}),
        "category_accuracy": eval_data.get("category_accuracy", {}),
        "cv_summary": cv_data,
        "whole_dataset_9m_training": whole_data,
        "large_scale_150k_evaluation": whole_eval_data,
        "old_baseline_comparison": old_baseline
    }
