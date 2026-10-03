"""
Automated End-to-End Experimentation Runner
Executes the full pipeline:
1. Validates raw dataset
2. Extracts benchmark splits & full-scale splits
3. Fits Preprocessing Pipeline & StandardScaler
4. Trains the 4 ML models with 5-Fold Stratified Cross Validation
5. Runs Whole-Dataset 9.2M streaming training
6. Evaluates models on Test, Imbalanced, and Unseen datasets
7. Generates charts and summary comparison tables
"""
import os
import sys
import time
import json
from src.config import RAW_DATASET_CSV, BASELINE_12K_CSV, RESULTS_DIR
from src.dataset_loader import build_benchmark_datasets
from src.preprocessing import prepare_train_val_test_matrices
from src.train_models import train_and_cross_validate
from src.evaluate_models import run_evaluation
from src.train_whole_dataset_stream import stream_train_whole_dataset

def main():
    print("=" * 80)
    print("  AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION IN SDN")
    print("  AUTOMATED END-TO-END REPRODUCIBLE EXPERIMENT RUNNER")
    print("=" * 80)
    t0 = time.time()

    # Step 1: Validate Dataset
    print("\n[Step 1/6] Validating Raw Dataset...")
    if not os.path.exists(RAW_DATASET_CSV):
        print(f"Error: {RAW_DATASET_CSV} not found! Extract ready_dataset.zip first.")
        sys.exit(1)
    file_size_gb = os.path.getsize(RAW_DATASET_CSV) / (1024**3)
    print(f"  Dataset file verified: {RAW_DATASET_CSV} ({file_size_gb:.2f} GB)")

    # Step 2: Build / Verify Benchmark Splits
    print("\n[Step 2/6] Preparing Benchmark 12,000 Dataset & Splits...")
    if not os.path.exists(BASELINE_12K_CSV):
        build_benchmark_datasets()
    else:
        print(f"  Benchmark dataset already cached at {BASELINE_12K_CSV}")

    # Step 3: Feature Preprocessing
    print("\n[Step 3/6] Preprocessing and Fitting Scaler on Training Partition...")
    data_matrices = prepare_train_val_test_matrices()
    print(f"  Train: {data_matrices['X_train'].shape} | Val: {data_matrices['X_val'].shape} | Test: {data_matrices['X_test'].shape}")

    # Step 4: Model Training & 5-Fold Cross Validation
    print("\n[Step 4/6] Executing 5-Fold Stratified Cross Validation for 4 Models...")
    cv_results = train_and_cross_validate(data_matrices)
    print(f"  Training complete! Best Model: {cv_results['best_model_name']}")

    # Step 5: Comprehensive Model Evaluation & Plot Generation
    print("\n[Step 5/6] Evaluating on Standard, Imbalanced, and Unseen Test Sets...")
    eval_report = run_evaluation()

    # Step 6: Whole Dataset 9.2M Scaled Training
    print("\n[Step 6/6] Whole Dataset 9.2M Online Streaming Learning...")
    whole_report_path = RESULTS_DIR / "whole_dataset_full_report.json"
    if not os.path.exists(whole_report_path):
        stream_train_whole_dataset()
    else:
        print(f"  Whole dataset training report already verified at {whole_report_path}")

    elapsed = time.time() - t0
    print("\n" + "=" * 80)
    print(f"EXPERIMENT RUN COMPLETE IN {elapsed:.2f} SECONDS!")
    print(f"Artifacts saved in: {RESULTS_DIR}")
    print("=" * 80)

if __name__ == "__main__":
    main()
