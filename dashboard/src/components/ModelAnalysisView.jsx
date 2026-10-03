import React, { useState, useEffect } from 'react';
import { fetchModels } from '../services/api';

export default function ModelAnalysisView() {
  const [modelData, setModelData] = useState(null);

  useEffect(() => {
    fetchModels().then(setModelData).catch(console.error);
  }, []);

  const testResults = modelData?.test_results || {};
  const whole9m = modelData?.whole_dataset_9m_training || {};
  const oldBaseline = modelData?.old_baseline_comparison || {};

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Overview Card */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '1.2rem', fontWeight: '800', marginBottom: '8px' }}>
          Machine Learning Model Evaluation & Benchmark Comparison
        </h3>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
          Evaluated via 5-Fold Stratified Cross Validation on the benchmark dataset and verified across
          Standard Test, Imbalanced Real-World Test, Unseen Attack Scenarios, and 9.2M Whole-Dataset Stream.
        </p>

        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          <span className="status-pill pill-active">
            ACTIVE MODEL: {modelData?.current_active_model || 'Random Forest'}
          </span>
          <span className="status-pill pill-warning">
            LIVE FEATURES: 14 Telemetry Features
          </span>
          <span className="status-pill pill-active">
            WHOLE DATASET TRAINED: 9,209,309 Rows
          </span>
        </div>
      </div>

      {/* Model Comparison Table */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <h4 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '16px' }}>
          Test Set Performance Matrix (1,800 Holdout Samples)
        </h4>

        <div className="data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Model</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1-Score</th>
                <th>ROC-AUC</th>
                <th>MCC</th>
                <th>FPR</th>
                <th>Inference Latency</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(testResults).map(([name, m]) => (
                <tr key={name}>
                  <td style={{ fontWeight: '700', color: name.includes('Random Forest') ? '#38bdf8' : '#fff' }}>
                    {name}
                  </td>
                  <td>{(m.accuracy * 100).toFixed(2)}%</td>
                  <td>{m.precision.toFixed(4)}</td>
                  <td>{m.recall.toFixed(4)}</td>
                  <td style={{ fontWeight: '700', color: '#34d399' }}>{m.f1.toFixed(4)}</td>
                  <td>{m.roc_auc.toFixed(4)}</td>
                  <td>{m.mcc.toFixed(4)}</td>
                  <td style={{ color: m.fpr > 0.03 ? '#f59e0b' : '#34d399' }}>
                    {(m.fpr * 100).toFixed(2)}%
                  </td>
                  <td>{m.latency_ms?.toFixed(3)} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Baseline Comparison & Whole-Dataset Card */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '20px' }}>
        {/* Old Baseline vs New Results */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h4 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '12px' }}>
            Previous Baseline vs New Implementation
          </h4>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.7' }}>
            <p><strong>KNN Baseline (Old):</strong> Acc = 90.83%, F1 = 0.9077, ROC-AUC = 0.9768, FPR = 8.44%</p>
            <p><strong>KNN New Result:</strong> Acc = 97.72%, F1 = 0.9773, ROC-AUC = 0.9977, FPR = 2.56%</p>
            <hr style={{ borderColor: 'var(--border-glass)', margin: '10px 0' }} />
            <p><strong>Best Model (Random Forest):</strong> Acc = 98.06%, F1 = 0.9805, ROC-AUC = 0.9989, FPR = 1.56%</p>
            <p><strong>Imbalanced Test F1:</strong> 0.9508 | <strong>Unseen Attack F1:</strong> 1.0000</p>
          </div>
        </div>

        {/* Whole Dataset Scaled Training */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h4 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '12px', color: '#06b6d4' }}>
            100% Whole Dataset Online Learning (9,209,309 Rows)
          </h4>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.7' }}>
            <p><strong>Total Flows Processed:</strong> {whole9m.total_rows_trained?.toLocaleString() || '9,209,309'}</p>
            <p><strong>Holdout Test Accuracy:</strong> {(whole9m.accuracy * 100)?.toFixed(2)}%</p>
            <p><strong>Holdout F1-Score:</strong> {whole9m.f1_score?.toFixed(4)} | <strong>ROC-AUC:</strong> {whole9m.roc_auc?.toFixed(4)}</p>
            <p><strong>False Positive Rate:</strong> {(whole9m.fpr * 100)?.toFixed(2)}% (2 FP / 40,000 flows)</p>
            <p><strong>Method:</strong> Incremental Out-of-Core SGD (117s pass)</p>
          </div>
        </div>

        {/* 150k High-Capacity Random Forest */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <h4 style={{ fontSize: '1rem', fontWeight: '700', marginBottom: '12px', color: '#a78bfa' }}>
            Large-Scale Random Forest (150,000 Partitions)
          </h4>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: '1.7' }}>
            <p><strong>Dataset Size:</strong> 150,000 samples (120k train / 30k test)</p>
            <p><strong>Test Accuracy:</strong> 99.61%</p>
            <p><strong>Test F1-Score:</strong> 0.9962 | <strong>ROC-AUC:</strong> 0.9991</p>
            <p><strong>False Positive Rate:</strong> 0.61%</p>
            <p><strong>Model:</strong> 100 Trees, max_depth=12 (whole_dataset_rf.joblib)</p>
          </div>
        </div>
      </div>
    </div>
  );
}
