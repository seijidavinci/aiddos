import React from 'react';

export default function LiveCharts({ stats }) {
  const timeline = stats?.traffic_timeline || [];
  const catDist = stats?.category_distribution || {};
  const topAttackers = stats?.top_attacking_ips || [];

  // Prepare points for SVG traffic rate line chart
  const maxRate = Math.max(...timeline.map(t => t.packet_rate || 0), 10);
  const chartHeight = 140;
  const chartWidth = 500;

  const points = timeline.map((t, idx) => {
    const x = (idx / Math.max(timeline.length - 1, 1)) * chartWidth;
    const y = chartHeight - ((t.packet_rate || 0) / maxRate) * (chartHeight - 20) - 10;
    return `${x},${y}`;
  }).join(' ');

  const areaPath = timeline.length > 1
    ? `M 0,${chartHeight} L ${points} L ${chartWidth},${chartHeight} Z`
    : '';

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
      gap: '20px',
      marginBottom: '24px'
    }}>
      {/* Chart 1: Traffic Rate Over Time */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Live Network Traffic Rate</h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Flow Packets/sec Telemetry Timeline</p>
          </div>
          <span className="status-pill pill-active" style={{ fontSize: '0.7rem' }}>
            <span className="pulse-dot"></span> LIVE POLLING
          </span>
        </div>

        <div style={{ width: '100%', height: '160px', position: 'relative' }}>
          <svg viewBox={`0 0 ${chartWidth} ${chartHeight}`} style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            <defs>
              <linearGradient id="rateGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Area */}
            {areaPath && <path d={areaPath} fill="url(#rateGradient)" />}

            {/* Line */}
            {points && (
              <polyline
                fill="none"
                stroke="#06b6d4"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                points={points}
              />
            )}
          </svg>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>
          <span>T-30 Polling Windows</span>
          <span>Peak: {Math.round(maxRate)} pkts/s</span>
          <span>Current Active</span>
        </div>
      </div>

      {/* Chart 2: Attack Category Distribution */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>DDoS Attack Category Breakdown</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Classified Attack Signatures</p>
        </div>

        {Object.keys(catDist).length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '150px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            🛡️ No attack events detected in the current window.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {Object.entries(catDist).map(([cat, count]) => {
              const total = Object.values(catDist).reduce((a, b) => a + b, 0);
              const pct = Math.round((count / total) * 100);
              return (
                <div key={cat}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '4px' }}>
                    <span style={{ fontWeight: '600', color: 'var(--text-primary)', textTransform: 'capitalize' }}>
                      {cat.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: 'var(--text-secondary)' }}>{count} ({pct}%)</span>
                  </div>
                  <div style={{ width: '100%', height: '6px', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${pct}%`,
                      height: '100%',
                      background: cat.includes('https') ? '#ec4899' : cat.includes('syn') ? '#3b82f6' : cat.includes('udp') ? '#f59e0b' : '#ef4444',
                      borderRadius: '3px',
                      transition: 'width 0.5s ease'
                    }} />
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Chart 3: Top Attacking Sources */}
      <div className="glass-panel" style={{ padding: '20px' }}>
        <div style={{ marginBottom: '16px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Top Attacking Source IPs</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Primary Mitigated Attack Vectors</p>
        </div>

        {topAttackers.length === 0 ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '150px', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            ✅ All client traffic within normal thresholds.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {topAttackers.map((atk, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '8px 12px',
                  background: 'rgba(255, 255, 255, 0.02)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-glass)'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ color: '#f43f5e', fontWeight: '700', fontSize: '0.8rem' }}>#{idx + 1}</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{atk.ip}</span>
                </div>
                <span className="status-pill pill-danger" style={{ fontSize: '0.7rem' }}>
                  {atk.count} VIOLATIONS
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
