import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import MetricCards from './components/MetricCards';
import LiveCharts from './components/LiveCharts';
import FlowsTable from './components/FlowsTable';
import MitigationsTable from './components/MitigationsTable';
import ExternalTrafficView from './components/ExternalTrafficView';
import ModelAnalysisView from './components/ModelAnalysisView';
import { fetchStats, fetchFlows, fetchMitigations, fetchSystemStatus } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [stats, setStats] = useState(null);
  const [flows, setFlows] = useState([]);
  const [mitigations, setMitigations] = useState([]);
  const [systemStatus, setSystemStatus] = useState(null);

  const refreshAll = async () => {
    try {
      const [s, f, m, sys] = await Promise.all([
        fetchStats().catch(() => null),
        fetchFlows(30).catch(() => []),
        fetchMitigations().catch(() => []),
        fetchSystemStatus().catch(() => null)
      ]);
      if (s) setStats(s);
      if (f) setFlows(f);
      if (m) setMitigations(m);
      if (sys) setSystemStatus(sys);
    } catch (err) {
      console.error('Data polling error:', err);
    }
  };

  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '0 24px 40px 24px' }}>
      <Header systemStatus={systemStatus} />

      {/* Navigation Tabs */}
      <nav className="nav-tabs">
        <button
          className={`nav-tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          ⚡ Live SDN Dashboard
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'external' ? 'active' : ''}`}
          onClick={() => setActiveTab('external')}
        >
          🌐 External Traffic & HTTPS
        </button>
        <button
          className={`nav-tab-btn ${activeTab === 'models' ? 'active' : ''}`}
          onClick={() => setActiveTab('models')}
        >
          🧠 ML Models & Benchmark
        </button>
      </nav>

      {/* Tab Content */}
      {activeTab === 'dashboard' && (
        <>
          <MetricCards stats={stats} systemStatus={systemStatus} />
          <LiveCharts stats={stats} />
          <MitigationsTable mitigations={mitigations} onRefresh={refreshAll} />
          <FlowsTable flows={flows} onRefresh={refreshAll} />
        </>
      )}

      {activeTab === 'external' && <ExternalTrafficView />}

      {activeTab === 'models' && <ModelAnalysisView />}
    </div>
  );
}
