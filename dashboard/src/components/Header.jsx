import React, { useState, useEffect } from 'react';

export default function Header({ systemStatus }) {
  const [timeStr, setTimeStr] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const timer = setInterval(() => setTimeStr(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header style={{
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '20px 0',
      borderBottom: '1px solid var(--border-glass)',
      marginBottom: '24px'
    }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'linear-gradient(135deg, #06b6d4, #8b5cf6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: '800',
            fontSize: '1.2rem',
            color: '#fff',
            boxShadow: '0 0 16px rgba(6, 182, 212, 0.5)'
          }}>
            ⚡
          </div>
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: '800', letterSpacing: '-0.02em', background: 'linear-gradient(to right, #f8fafc, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              AI-Driven DDoS Detection & Automated Mitigation
            </h1>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Software Defined Networking (SDN) OpenFlow 1.3 & Multi-Source Telemetry Framework
            </p>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div className="status-pill pill-active">
          <span className="pulse-dot"></span>
          BACKEND: {systemStatus?.backend_status || 'ONLINE'}
        </div>

        <div className="status-pill pill-active">
          <span className="pulse-dot"></span>
          SDN SWITCH: {systemStatus?.switch_status || 'DPID 1'}
        </div>

        <div className="status-pill pill-warning">
          <span className="pulse-dot"></span>
          MITIGATION: {systemStatus?.mitigation_enabled ? 'ENABLED' : 'DISABLED'}
        </div>

        <div style={{
          padding: '6px 12px',
          borderRadius: '6px',
          background: 'rgba(255, 255, 255, 0.04)',
          border: '1px solid var(--border-glass)',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.85rem',
          color: 'var(--text-secondary)'
        }}>
          {timeStr}
        </div>
      </div>
    </header>
  );
}
