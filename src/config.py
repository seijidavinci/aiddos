"""
Global Configuration for AI-Driven DDoS Detection and Mitigation Framework
"""
import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
RESULTS_DIR = BASE_DIR / "results"
LOGS_DIR = BASE_DIR / "logs"

# Ensure directories exist
for d in [DATA_DIR, MODELS_DIR, RESULTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# Dataset Paths
RAW_DATASET_CSV = BASE_DIR / "ready_dataset.csv"
RAW_DATASET_ZIP = BASE_DIR / "ready_dataset.zip"

BASELINE_12K_CSV = DATA_DIR / "baseline_12k.csv"
TRAIN_CSV = DATA_DIR / "train.csv"
VAL_CSV = DATA_DIR / "val.csv"
TEST_CSV = DATA_DIR / "test.csv"
IMBALANCED_TEST_CSV = DATA_DIR / "imbalanced_test.csv"
UNSEEN_TEST_CSV = DATA_DIR / "unseen_test.csv"

# Model Artifacts
SCALER_PATH = MODELS_DIR / "scaler.joblib"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"
FEATURE_METADATA_PATH = MODELS_DIR / "feature_metadata.json"

RF_MODEL_PATH = MODELS_DIR / "random_forest.joblib"
SVM_MODEL_PATH = MODELS_DIR / "svm_rbf.joblib"
KNN_MODEL_PATH = MODELS_DIR / "knn.joblib"
LR_MODEL_PATH = MODELS_DIR / "logistic_regression.joblib"
BEST_MODEL_PATH = MODELS_DIR / "best_model.joblib"

# Random Seed for Reproducibility
RANDOM_SEED = 42

# 14 Engineered Features (strictly obtainable in LIVE telemetry)
FEATURE_NAMES = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "packet_rate",
    "byte_rate",
    "packet_size_mean",
    "packet_size_std",
    "flow_iat_mean",
    "flow_iat_std",
    "syn_flag_count",
    "ack_flag_count",
    "down_up_ratio",
    "protocol_encoded",
    "dst_port_encoded"
]

# Attack Categories
ATTACK_CATEGORIES = [
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "dns_amplification",
    "http_get_flood",
    "slowloris_low_rate",
    "pulsed_mixed_flood"
]

# Backend & Controller Settings
BACKEND_HOST = os.getenv("BACKEND_HOST", "0.0.0.0")
BACKEND_PORT = int(os.getenv("BACKEND_PORT", "8000"))
CONTROLLER_HOST = os.getenv("CONTROLLER_HOST", "0.0.0.0")
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "6653"))
FLOW_POLL_INTERVAL = float(os.getenv("FLOW_POLL_INTERVAL", "2.0"))

# Mitigation Settings
MITIGATION_ENABLED = os.getenv("MITIGATION_ENABLED", "True").lower() in ("true", "1", "yes")
BLOCK_DURATION = int(os.getenv("BLOCK_DURATION", "60"))
DETECTION_THRESHOLD = float(os.getenv("DETECTION_THRESHOLD", "0.50"))
TARGET_ACCURACY_MODE = os.getenv("TARGET_ACCURACY_MODE", "90_PERCENT")

# Database
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/ddos_framework.db")
