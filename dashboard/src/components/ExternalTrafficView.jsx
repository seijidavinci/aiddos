import React, { useState, useEffect } from 'react';
import { fetchExternalStats } from '../services/api';

export default function ExternalTrafficView() {
  const [protocol, setProtocol] = useState('');
  const [service, setService] = useState('');
  const [status, setStatus] = useState('');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadData = async () => {
    try {
      setLoading(true);
      const filters = {};
      if (protocol) filters.protocol = protocol;
      if (service) filters.service = service;
      if (status) filters.status = status;
      const res = await fetchExternalStats(filters);
      setData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, [protocol, service, status]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Filter Control Bar */}
      <div className="glass-panel" style={{ padding: '16px 20px', display: 'flex', gap: '20px', alignItems: 'center', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--accent-cyan)' }}>
          🔍 EXTERNAL FILTERS:
        </span>

        {/* Protocol Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Protocol:</label>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value)}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-glass)',
              color: '#fff',
              padding: '6px 10px',
              borderRadius: '6px',
              fontSize: '0.8rem'
            }}
          >
            <option value="">All Protocols</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </div>

        {/* Service Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Service:</label>
          <select
            value={service}
            onChange={(e) => setService(e.target.value)}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-glass)',
              color: '#fff',
              padding: '6px 10px',
              borderRadius: '6px',
              fontSize: '0.8rem'
            }}
          >
            <option value="">All Services</option>
            <option value="HTTPS">HTTPS (Port 443)</option>
            <option value="HTTP">HTTP (Port 80)</option>
            <option value="DNS">DNS (Port 53)</option>
          </select>
        </div>

        {/* Status Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Status:</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-glass)',
              color: '#fff',
              padding: '6px 10px',
              borderRadius: '6px',
              fontSize: '0.8rem'
            }}
          >
            <option value="">All Traffic</option>
            <option value="NORMAL">Normal</option>
            <option value="DDOS">DDoS Violations</option>
          </select>
        </div>

        <button className="btn-primary" onClick={loadData} style={{ marginLeft: 'auto', fontSize: '0.8rem' }}>
          Apply Filters
        </button>
      </div>

      {/* External Metrics Cards */}
      <div className="metric-grid">
        <div className="glass-panel metric-card" style={{ borderLeft: '4px solid #38bdf8' }}>
          <div className="metric-title">INCOMING FLOW COUNT</div>
          <div className="metric-value" style={{ color: '#38bdf8' }}>
            {data?.incoming_flow_count ?? 0}
          </div>
          <div className="metric-subtitle">External Client Gateways</div>
        </div>

        <div className="glass-panel metric-card" style={{ borderLeft: '4px solid #ec4899' }}>
          <div className="metric-title">HTTPS TRAFFIC (PORT 443)</div>
          <div className="metric-value" style={{ color: '#ec4899' }}>
            {data?.https_traffic ?? 0}
          </div>
          <div className="metric-subtitle">Encrypted TLS Sessions</div>
        </div>

        <div className="glass-panel metric-card" style={{ borderLeft: '4px solid #f43f5e' }}>
          <div className="metric-title">SUSPICIOUS HTTPS BEHAVIOR</div>
          <div className="metric-value" style={{ color: '#f43f5e' }}>
            {data?.https_metrics?.suspicious_https_flows ?? 0}
          </div>
          <div className="metric-subtitle">Transport-Layer Anomaly Identified</div>
        </div>

        <div className="glass-panel metric-card" style={{ borderLeft: '4px solid #10b981' }}>
          <div className="metric-title">HTTP & DNS TRAFFIC</div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            {(data?.http_traffic ?? 0) + (data?.dns_traffic ?? 0)}
          </div>
          <div className="metric-subtitle">Port 80 & Port 53 Traffic</div>
        </div>
      </div>

      {/* Deep-Dive: HTTPS Encrypted Behavioral Detection */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: '800', color: '#ec4899' }}>
              🔒 HTTPS / TLS Behavioral Anomaly Inspection Engine
            </h3>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Non-decrypting metadata analysis compliant with end-to-end TLS encryption privacy
            </p>
          </div>
          <span className="status-pill pill-active">
            ZERO PAYLOAD DECRYPTION REQUIRED
          </span>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
          marginTop: '12px'
        }}>
          <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-glass)' }}>
            <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>Monitored Behaviors</h4>
            <ul style={{ fontSize: '0.8rem', color: 'var(--text-primary)', listStyleType: 'disc', paddingLeft: '20px', lineHeight: '1.8' }}>
              <li>TCP SYN floods targeting Port 443</li>
              <li>TLS connection & handshake exhaustion</li>
              <li>HTTPS request-rate volume flooding</li>
              <li>Low-rate connection holding (Slowloris TLS)</li>
              <li>Pulsed periodic connection bursts</li>
            </ul>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-glass)' }}>
            <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>Observable Transport Metrics</h4>
            <ul style={{ fontSize: '0.8rem', color: 'var(--text-primary)', listStyleType: 'disc', paddingLeft: '20px', lineHeight: '1.8' }}>
              <li>SYN-to-ACK asymmetry ratio</li>
              <li>Incoming connection arrival velocity</li>
              <li>Byte-to-packet payload density ratio</li>
              <li>Flow duration vs transmission throughput</li>
              <li>Inter-arrival time variance & burstiness</li>
            </ul>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '16px', borderRadius: '8px', border: '1px solid var(--border-glass)' }}>
            <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>Protocol Distribution</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                <span>TCP (Proto 6)</span>
                <span style={{ fontWeight: '600', color: '#38bdf8' }}>{data?.protocol_distribution?.TCP ?? 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                <span>UDP (Proto 17)</span>
                <span style={{ fontWeight: '600', color: '#f59e0b' }}>{data?.protocol_distribution?.UDP ?? 0}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
                <span>ICMP (Proto 1)</span>
                <span style={{ fontWeight: '600', color: '#34d399' }}>{data?.protocol_distribution?.ICMP ?? 0}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
