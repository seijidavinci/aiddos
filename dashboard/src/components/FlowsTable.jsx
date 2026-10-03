import React from 'react';

export default function FlowsTable({ flows, onRefresh }) {
  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Live Network Flow Telemetry</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Real-time Ingested Flow Records & ML Classifications
          </p>
        </div>
        <button className="btn-primary" onClick={onRefresh} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          🔄 Refresh Feed
        </button>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Packets/s</th>
              <th>Bytes/s</th>
              <th>Status</th>
              <th>Category</th>
              <th>Source Type</th>
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 ? (
              <tr>
                <td colSpan="9" style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)' }}>
                  Awaiting flow telemetry from SDN controller / packet sniffer...
                </td>
              </tr>
            ) : (
              flows.map((f) => {
                const dateStr = new Date(f.timestamp * 1000).toLocaleTimeString();
                const protoStr = f.protocol === 6 ? 'TCP' : f.protocol === 17 ? 'UDP' : f.protocol === 1 ? 'ICMP' : f.protocol;
                return (
                  <tr key={f.id}>
                    <td>{dateStr}</td>
                    <td style={{ color: f.is_ddos ? '#fb7185' : '#38bdf8', fontWeight: '600' }}>
                      {f.src_ip}
                    </td>
                    <td>{f.dst_ip}:{f.dst_port}</td>
                    <td>
                      <span style={{
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        fontSize: '0.75rem'
                      }}>
                        {protoStr}
                      </span>
                    </td>
                    <td>{Math.round(f.packet_rate)}</td>
                    <td>{(f.byte_rate / 1024).toFixed(1)} KB/s</td>
                    <td>
                      {f.is_ddos ? (
                        <span className="status-pill pill-danger" style={{ fontSize: '0.7rem' }}>
                          <span className="pulse-dot"></span> DDOS
                        </span>
                      ) : (
                        <span className="status-pill pill-active" style={{ fontSize: '0.7rem' }}>
                          NORMAL
                        </span>
                      )}
                    </td>
                    <td style={{ textTransform: 'capitalize' }}>
                      {f.category.replace(/_/g, ' ')}
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>
                      {f.telemetry_source}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
