/**
 * API Service for Dashboard
 * Communicates with the FastAPI backend
 */

const BASE_URL = 'https://' + 'aiddos.onrender.com';

export async function fetchStats() {
  const res = await fetch(`${BASE_URL}/api/stats`);
  if (!res.ok) throw new Error('Failed to fetch stats');
  return res.json();
}

export async function fetchFlows(limit = 50, filters = {}) {
  const params = new URLSearchParams({ limit, ...filters });
  const res = await fetch(`${BASE_URL}/api/flows?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch flows');
  return res.json();
}

export async function fetchDetections(limit = 20) {
  const res = await fetch(`${BASE_URL}/api/detections?limit=${limit}`);
  if (!res.ok) throw new Error('Failed to fetch detections');
  return res.json();
}

export async function fetchMitigations() {
  const res = await fetch(`${BASE_URL}/api/mitigations`);
  if (!res.ok) throw new Error('Failed to fetch mitigations');
  return res.json();
}

export async function fetchModels() {
  const res = await fetch(`${BASE_URL}/api/models`);
  if (!res.ok) throw new Error('Failed to fetch models');
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${BASE_URL}/api/system`);
  if (!res.ok) throw new Error('Failed to fetch system status');
  return res.json();
}

export async function fetchExternalStats(filters = {}) {
  const params = new URLSearchParams(filters);
  const res = await fetch(`${BASE_URL}/api/external/stats?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch external stats');
  return res.json();
}

export async function manualUnblock(ipAddress) {
  const res = await fetch(`${BASE_URL}/api/mitigations/unblock/${ipAddress}`, {
    method: 'POST'
  });
  if (!res.ok) throw new Error('Failed to unblock IP');
  return res.json();
}

export async function manualBlock(ipAddress, duration = 60, reason = 'Manual Administrator Block') {
  const res = await fetch(`${BASE_URL}/api/mitigations/block`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip_address: ipAddress, duration, reason })
  });
  if (!res.ok) throw new Error('Failed to block IP');
  return res.json();
}
