"""
Preprocessing Module for AI-Driven DDoS Detection Framework
Handles feature scaling, pipeline serialization, and live vector transformation.
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from typing import Tuple, Dict, Any, Union
from src.config import (
    FEATURE_NAMES, SCALER_PATH, FEATURE_METADATA_PATH,
    TRAIN_CSV, VAL_CSV, TEST_CSV
)

class PreprocessingPipeline:
    def __init__(self, scaler_path: str = str(SCALER_PATH), metadata_path: str = str(FEATURE_METADATA_PATH)):
        self.scaler_path = scaler_path
        self.metadata_path = metadata_path
        self.scaler: StandardScaler = StandardScaler()
        self.feature_names = FEATURE_NAMES
        self.is_fitted = False
        self._load_if_exists()

    def _load_if_exists(self):
        if os.path.exists(self.scaler_path):
            try:
                self.scaler = joblib.load(self.scaler_path)
                self.is_fitted = True
            except Exception as e:
                print(f"Warning: Could not load scaler from {self.scaler_path}: {e}")

    def fit(self, X: Union[pd.DataFrame, np.ndarray]) -> "PreprocessingPipeline":
        """Fit StandardScaler on training features."""
        if isinstance(X, pd.DataFrame):
            X_mat = X[self.feature_names].values
        else:
            X_mat = X
        
        # Replace any infs or nans with 0
        X_clean = np.nan_to_num(X_mat, nan=0.0, posinf=1e6, neginf=-1e6)
        self.scaler.fit(X_clean)
        self.is_fitted = True

        # Save fitted scaler
        joblib.dump(self.scaler, self.scaler_path)

        # Save metadata
        metadata = {
            "feature_names": self.feature_names,
            "feature_count": len(self.feature_names),
            "means": self.scaler.mean_.tolist(),
            "scales": self.scaler.scale_.tolist(),
            "variances": self.scaler.var_.tolist()
        }
        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"Scaler fitted and saved to {self.scaler_path}")
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        """Transform features using fitted StandardScaler."""
        if not self.is_fitted:
            raise ValueError("PreprocessingPipeline is not fitted yet. Call fit() first.")
        if isinstance(X, pd.DataFrame):
            X_mat = X[self.feature_names].values
        else:
            X_mat = X
        X_clean = np.nan_to_num(X_mat, nan=0.0, posinf=1e6, neginf=-1e6)
        return self.scaler.transform(X_clean)

    def fit_transform(self, X: Union[pd.DataFrame, np.ndarray]) -> np.ndarray:
        return self.fit(X).transform(X)

    def transform_live_vector(self, vector: np.ndarray) -> np.ndarray:
        """
        Transform a single live flow feature vector of shape (1, 14).
        """
        if not self.is_fitted:
            self._load_if_exists()
        v_clean = np.nan_to_num(vector, nan=0.0, posinf=1e6, neginf=-1e6)
        return self.scaler.transform(v_clean)

def prepare_train_val_test_matrices() -> Dict[str, Any]:
    """
    Load CSV splits, fit scaler on train set, and return scaled numpy arrays + targets.
    """
    train_df = pd.read_csv(TRAIN_CSV)
    val_df = pd.read_csv(VAL_CSV)
    test_df = pd.read_csv(TEST_CSV)

    pipeline = PreprocessingPipeline()
    X_train_scaled = pipeline.fit_transform(train_df[FEATURE_NAMES])
    X_val_scaled = pipeline.transform(val_df[FEATURE_NAMES])
    X_test_scaled = pipeline.transform(test_df[FEATURE_NAMES])

    y_train = train_df["is_ddos"].values
    y_val = val_df["is_ddos"].values
    y_test = test_df["is_ddos"].values

    return {
        "pipeline": pipeline,
        "X_train": X_train_scaled,
        "y_train": y_train,
        "X_val": X_val_scaled,
        "y_val": y_val,
        "X_test": X_test_scaled,
        "y_test": y_test,
        "train_df": train_df,
        "val_df": val_df,
        "test_df": test_df
    }
