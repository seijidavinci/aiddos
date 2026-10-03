import React, { useState } from 'react';
import { manualBlock, manualUnblock } from '../services/api';

export default function MitigationsTable({ mitigations, onRefresh }) {
  const [manualIp, setManualIp] = useState('');
  const [loading, setLoading] = useState(false);

  const handleUnblock = async (ip) => {
    try {
      setLoading(true);
      await manualUnblock(ip);
      onRefresh();
    } catch (err) {
      alert('Error unblocking IP: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!manualIp.trim()) return;
    try {
      setLoading(true);
      await manualBlock(manualIp.trim(), 60, 'Manual Security Administrator Block');
      setManualIp('');
      onRefresh();
    } catch (err) {
      alert('Error blocking IP: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const activeRules = mitigations.filter(m => m.status === 'ACTIVE');

  return (
    <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h3 style={{ fontSize: '1rem', fontWeight: '700' }}>Automated OpenFlow Mitigation Rules</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Active Switch DROP FlowMods with Timeout & Duplicate Prevention
          </p>
        </div>

        {/* Manual block form */}
        <form onSubmit={handleManualBlock} style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            placeholder="e.g. 192.168.1.50"
            value={manualIp}
            onChange={(e) => setManualIp(e.target.value)}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-glass)',
              borderRadius: '6px',
              padding: '6px 12px',
              color: '#fff',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem'
            }}
          />
          <button type="submit" className="btn-primary" disabled={loading} style={{ fontSize: '0.8rem' }}>
            + Block IP
          </button>
        </form>
      </div>

      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Target Attacking IP</th>
              <th>Status</th>
              <th>Attack Type</th>
              <th>Reason / Trigger</th>
              <th>Confidence</th>
              <th>Time Remaining</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {activeRules.length === 0 ? (
              <tr>
                <td colSpan="7" style={{ textAlign: 'center', padding: '24px', color: 'var(--text-muted)' }}>
                  No active mitigation rules. All traffic allowed through switch forwarding table.
                </td>
              </tr>
            ) : (
              activeRules.map((m) => (
                <tr key={m.id}>
                  <td style={{ color: '#fb7185', fontWeight: '700' }}>{m.ip_address}</td>
                  <td>
                    <span className="status-pill pill-danger" style={{ fontSize: '0.7rem' }}>
                      <span className="pulse-dot"></span> ACTIVE DROP
                    </span>
                  </td>
                  <td style={{ textTransform: 'capitalize' }}>{m.category.replace(/_/g, ' ')}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{m.reason}</td>
                  <td>{(m.confidence * 100).toFixed(1)}%</td>
                  <td>
                    <span style={{
                      padding: '3px 8px',
                      borderRadius: '4px',
                      background: 'rgba(245, 158, 11, 0.15)',
                      color: '#fbbf24',
                      fontWeight: '600'
                    }}>
                      {m.remaining_sec}s left
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-danger"
                      onClick={() => handleUnblock(m.ip_address)}
                      disabled={loading}
                    >
                      Unblock
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
