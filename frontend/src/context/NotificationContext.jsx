import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { getAlerts } from "../services/api";

const STORAGE_KEY = "cloud_sentinel_settings_v1";
const POLL_INTERVAL_MS = 500; // 0.5 s

/**
 * Each notification popup entry:
 * { id, alertId, severity, function, message, ts }
 */
const NotificationContext = createContext(null);

export function NotificationProvider({ children }) {
  const [toasts, setToasts] = useState([]); // active popups
  const seenIds = useRef(new Set());        // already-notified alert IDs
  const initialized = useRef(false);        // skip first-load batch

  const readSettings = useCallback(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { notificationsEnabled: true, notifyCriticalOnly: false };
      const p = JSON.parse(raw);
      return {
        notificationsEnabled: Boolean(p.notificationsEnabled ?? true),
        notifyCriticalOnly:   Boolean(p.notifyCriticalOnly   ?? false),
      };
    } catch {
      return { notificationsEnabled: true, notifyCriticalOnly: false };
    }
  }, []);

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const poll = useCallback(async () => {
    const { notificationsEnabled, notifyCriticalOnly } = readSettings();
    if (!notificationsEnabled) return;

    let alerts;
    try {
      alerts = await getAlerts();
    } catch {
      return; // silently ignore network errors for notifications
    }

    // On very first poll, seed seenIds without firing toasts
    if (!initialized.current) {
      alerts.forEach((a) => seenIds.current.add(a.id));
      initialized.current = true;
      return;
    }

    const newOnes = alerts.filter((a) => !seenIds.current.has(a.id));
    newOnes.forEach((a) => seenIds.current.add(a.id));

    const sev = (a) => (a.severity ?? "").toLowerCase();
    const toShow = notifyCriticalOnly
      ? newOnes.filter((a) => sev(a) === "critical")
      : newOnes;

    if (toShow.length === 0) return;

    setToasts((prev) => [
      ...prev,
      ...toShow.map((a) => ({
        id:       `${a.id}-${Date.now()}-${Math.random()}`,
        alertId:  a.id,
        severity: sev(a),
        fn:       a.function ?? "Unknown function",
        score:    a.anomaly_score,
        ts:       a.timestamp,
      })),
    ]);
  }, [readSettings]);

  useEffect(() => {
    poll(); // immediate first run
    const interval = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [poll]);

  return (
    <NotificationContext.Provider value={{ toasts, dismiss }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  return useContext(NotificationContext);
}
