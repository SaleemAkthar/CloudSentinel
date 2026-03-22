import axios from "axios";
import mockAlerts from "../test/alerts.json";

// Point to AWS backend
axios.defaults.baseURL = "http://cloud-sentinel-alb-1569061158.us-east-1.elb.amazonaws.com";
axios.defaults.withCredentials = true;


// Toggle this when backend is ready:
const USE_MOCK = false;
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

export async function updateProfile({ username, email }) {
  const res = await axios.put("/api/auth/profile", { username, email });
  return res.data;
}

// Auth Endpoints


export async function authRegister(username, email, password) {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 500));
    return { id: "mock-id", username, email };
  }
  const res = await axios.post("/api/auth/register", { username, email, password });
  return res.data;
}

export async function authLogin(email, password) {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 500));
    return { id: "mock-id", username: "Mock User", email };
  }
  const res = await axios.post("/api/auth/login", { email, password });
  return res.data;
}

export async function getMe() {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 200));
    return { id: "mock-id", username: "Mock User", email: "mock@user.com" };
  }
  const res = await axios.get("/api/auth/me");
  return res.data;
}

export async function authLogout() {
  if (USE_MOCK) {
    await new Promise((r) => setTimeout(r, 200));
    return { success: true };
  }
  const res = await axios.post("/api/auth/logout");
  return res.data;
}
