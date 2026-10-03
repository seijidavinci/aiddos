"""
Unit Tests for Dataset Loading and Split Verification
"""
import os
import pandas as pd
import pytest
from src.config import BASELINE_12K_CSV, TRAIN_CSV, VAL_CSV, TEST_CSV, FEATURE_NAMES

def test_baseline_dataset_exists():
    assert os.path.exists(BASELINE_12K_CSV), "baseline_12k.csv must exist"
    df = pd.read_csv(BASELINE_12K_CSV)
    assert len(df) == 12000, f"Expected 12,000 baseline rows, got {len(df)}"
    assert df["is_ddos"].value_counts().get(0) == 6000, "Expected 6,000 benign flows"
    assert df["is_ddos"].value_counts().get(1) == 6000, "Expected 6,000 DDoS flows"

def test_dataset_splits_and_ratios():
    assert os.path.exists(TRAIN_CSV), "train.csv must exist"
    assert os.path.exists(VAL_CSV), "val.csv must exist"
    assert os.path.exists(TEST_CSV), "test.csv must exist"

    train_df = pd.read_csv(TRAIN_CSV)
    val_df = pd.read_csv(VAL_CSV)
    test_df = pd.read_csv(TEST_CSV)

    assert len(train_df) == 8400, f"Train set must have 8,400 rows (70%), got {len(train_df)}"
    assert len(val_df) == 1800, f"Val set must have 1,800 rows (15%), got {len(val_df)}"
    assert len(test_df) == 1800, f"Test set must have 1,800 rows (15%), got {len(test_df)}"

def test_no_nulls_or_infs():
    for csv_file in [TRAIN_CSV, VAL_CSV, TEST_CSV]:
        df = pd.read_csv(csv_file)
        for col in FEATURE_NAMES:
            assert df[col].isnull().sum() == 0, f"Nulls found in {col} in {csv_file}"
            assert not (df[col] == float("inf")).any(), f"Positive inf found in {col}"
            assert not (df[col] == float("-inf")).any(), f"Negative inf found in {col}"
