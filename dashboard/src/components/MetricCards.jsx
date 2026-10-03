import React from 'react';

export default function MetricCards({ stats, systemStatus }) {
  const totalFlows = stats?.total_flows ?? 0;
  const benignFlows = stats?.benign_flows ?? 0;
  const ddosDetections = stats?.ddos_detections ?? 0;
  const activeMitigations = stats?.active_mitigations ?? 0;
  const detectionRate = stats?.detection_rate ?? 0.0;
  const modelName = systemStatus?.current_model || 'Random Forest';

  const cards = [
    {
      title: 'TOTAL NETWORK FLOWS',
      value: totalFlows.toLocaleString(),
      subtitle: 'Ingested Telemetry Records',
      color: '#38bdf8',
      glow: 'rgba(56, 189, 248, 0.25)',
      icon: '📊'
    },
    {
      title: 'BENIGN TRAFFIC',
      value: benignFlows.toLocaleString(),
      subtitle: 'Verified Normal Traffic',
      color: '#34d399',
      glow: 'rgba(52, 211, 153, 0.25)',
      icon: '🛡️'
    },
    {
      title: 'DDOS ATTACK DETECTIONS',
      value: ddosDetections.toLocaleString(),
      subtitle: `${detectionRate}% Attack Prevalence`,
      color: '#fb7185',
      glow: 'rgba(251, 113, 133, 0.25)',
      icon: '🚨'
    },
    {
      title: 'ACTIVE MITIGATION RULES',
      value: activeMitigations,
      subtitle: 'OpenFlow DROP FlowMods Active',
      color: '#fbbf24',
      glow: 'rgba(251, 191, 36, 0.25)',
      icon: '⛔'
    },
    {
      title: 'ACTIVE ML INFERENCE ENGINE',
      value: modelName,
      subtitle: '14 Live-Telemetry Features',
      color: '#a78bfa',
      glow: 'rgba(167, 139, 250, 0.25)',
      icon: '🧠',
      isText: true
    }
  ];

  return (
    <div className="metric-grid">
      {cards.map((c, idx) => (
        <div
          key={idx}
          className="glass-panel metric-card"
          style={{
            position: 'relative',
            overflow: 'hidden',
            borderLeft: `4px solid ${c.color}`
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="metric-title">{c.title}</span>
            <span style={{ fontSize: '1.2rem' }}>{c.icon}</span>
          </div>

          <div
            className="metric-value"
            style={{
              color: c.color,
              fontSize: c.isText ? '1.25rem' : '2.1rem',
              fontWeight: '800'
            }}
          >
            {c.value}
          </div>

          <div className="metric-subtitle">{c.subtitle}</div>

          {/* Subtle background glow */}
          <div
            style={{
              position: 'absolute',
              right: '-10px',
              bottom: '-10px',
              width: '80px',
              height: '80px',
              borderRadius: '50%',
              background: c.glow,
              filter: 'blur(30px)',
              pointerEvents: 'none'
            }}
          />
        </div>
      ))}
    </div>
  );
}
