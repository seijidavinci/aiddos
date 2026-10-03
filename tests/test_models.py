"""
Unit Tests for Machine Learning Models & Predictor
"""
import os
import joblib
import numpy as np
import pytest
from src.config import (
    RF_MODEL_PATH, SVM_MODEL_PATH, KNN_MODEL_PATH, LR_MODEL_PATH,
    BEST_MODEL_PATH, SCALER_PATH
)
from src.predict import DDoSPredictor

def test_saved_model_artifacts_exist():
    for p in [RF_MODEL_PATH, SVM_MODEL_PATH, KNN_MODEL_PATH, LR_MODEL_PATH, BEST_MODEL_PATH, SCALER_PATH]:
        assert os.path.exists(p), f"Artifact {p} must exist on disk"

def test_models_load_and_predict():
    scaler = joblib.load(SCALER_PATH)
    dummy_input = np.zeros((1, 14))
    scaled_input = scaler.transform(dummy_input)

    for p in [RF_MODEL_PATH, SVM_MODEL_PATH, KNN_MODEL_PATH, LR_MODEL_PATH]:
        model = joblib.load(p)
        pred = model.predict(scaled_input)
        assert pred[0] in (0, 1), f"Model {p} returned invalid prediction: {pred[0]}"
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(scaled_input)
            assert probs.shape == (1, 2)
            assert np.isclose(np.sum(probs[0]), 1.0)

def test_ddos_predictor_live_flow():
    predictor = DDoSPredictor()
    
    # Benign-like flow
    benign_flow = {
        "duration_sec": 1.5,
        "packet_count": 10,
        "byte_count": 1500,
        "syn_flag_count": 1,
        "ack_flag_count": 9,
        "protocol": 6,
        "dst_port": 80
    }
    b_res = predictor.predict_flow(benign_flow)
    assert "is_ddos" in b_res
    assert "probability" in b_res
    assert "confidence" in b_res
    assert isinstance(b_res["is_ddos"], bool)

    # Attack-like flow (high-rate attack with small payload)
    attack_flow = {
        "duration_sec": 0.0001,
        "packet_count": 200,
        "byte_count": 0,
        "packet_rate": 2000000.0,
        "byte_rate": 0.0,
        "packet_size_mean": 0.0,
        "flow_iat_mean": 1e-06,
        "syn_flag_count": 0,
        "ack_flag_count": 1,
        "protocol": 6,
        "dst_port": 80
    }
    a_res = predictor.predict_flow(attack_flow)
    assert a_res["is_ddos"] is True, "High-rate attack must be detected as DDoS"
    assert a_res["probability"] >= predictor.threshold
