import axios from "axios";
import mockAlerts from "../test/alerts.json";

// Toggle this when backend is ready:
const USE_MOCK = true;

// If we using backend later, we can call:
// GET /api/alerts
// GET /api/alerts/:id
// and set vite proxy to forward /api to backend.
export async function getAlerts() {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 150));
    return mockAlerts.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  }
  const res = await axios.get("/api/alerts");
  return res.data;
}

export async function getAlertById(id) {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 120));
    const found = mockAlerts.find((a) => a.id === id);
    if (!found) throw new Error("Alert not found");
    return found;
  }
  const res = await axios.get(`/api/alerts/${id}`);
  return res.data;
}

// model health hardcoded
export async function getModelHealth() {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 100));
    return {
      accuracy: 94.7,
      precision: 96.2,
      recall: 40,
      trainingActive: true,
      delta: 2.3,
    };
  }
  const res = await axios.get("/api/model/health");
  return res.data;
}
