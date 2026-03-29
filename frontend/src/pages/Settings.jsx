import { useEffect, useMemo, useState } from "react";
import GlassCard from "../components/GlassCard";

import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import TuneRoundedIcon from "@mui/icons-material/TuneRounded";
import ScheduleRoundedIcon from "@mui/icons-material/ScheduleRounded";
import RestartAltRoundedIcon from "@mui/icons-material/RestartAltRounded";
import SaveRoundedIcon from "@mui/icons-material/SaveRounded";

import {
  Alert,
  Button,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Slider,
  Switch,
  Snackbar,
} from "@mui/material";


const STORAGE_KEY = "cloud_sentinel_settings_v1";

const DEFAULTS = {
  monitoringEnabled: true,
  anomalyThreshold: 0.7,
  notificationsEnabled: true,
  notifyCriticalOnly: true,
  timeDisplay: "LOCAL", // LOCAL | UTC
};

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

export default function Settings() {
  const [settings, setSettings] = useState(DEFAULTS);
  const [loaded, setLoaded] = useState(false);

  // UI feedback
  const [toastOpen, setToastOpen] = useState(false);
  const [toastMsg, setToastMsg] = useState("Saved");
  const [toastSeverity, setToastSeverity] = useState("success"); // success | info | warning | error

  // Load from localStorage once
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);

        setSettings({
          monitoringEnabled: Boolean(parsed.monitoringEnabled),
          anomalyThreshold: clamp(Number(parsed.anomalyThreshold ?? 0.7), 0.5, 0.95),
          notificationsEnabled: Boolean(parsed.notificationsEnabled),
          notifyCriticalOnly: Boolean(parsed.notifyCriticalOnly),
          timeDisplay: parsed.timeDisplay === "UTC" ? "UTC" : "LOCAL",
        });
      }
    } catch {
      // ignore and fall back to defaults
      setSettings(DEFAULTS);
    } finally {
      setLoaded(true);
    }
  }, []);

  const dirty = useMemo(() => {
    // compare current to what's stored (or defaults if nothing stored yet)
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      const baseline = raw ? JSON.parse(raw) : DEFAULTS;

      const normalized = {
        monitoringEnabled: Boolean(baseline.monitoringEnabled),
        anomalyThreshold: clamp(Number(baseline.anomalyThreshold ?? 0.7), 0.5, 0.95),
        notificationsEnabled: Boolean(baseline.notificationsEnabled),
        notifyCriticalOnly: Boolean(baseline.notifyCriticalOnly),
        timeDisplay: baseline.timeDisplay === "UTC" ? "UTC" : "LOCAL",
      };

      return JSON.stringify(normalized) !== JSON.stringify(settings);
    } catch {
      return true;
    }
  }, [settings]);

  const setField = (key, value) => {
    setSettings((prev) => ({ ...prev, [key]: value }));
  };

  const save = () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
      setToastMsg("Settings saved");
      setToastSeverity("success");
      setToastOpen(true);
    } catch {
      setToastMsg("Failed to save settings");
      setToastSeverity("error");
      setToastOpen(true);
    }
  };

  const reset = () => {
    setSettings(DEFAULTS);
    setToastMsg("Reset to defaults (not saved yet)");
    setToastSeverity("info");
    setToastOpen(true);
  };

  if (!loaded) {
    return (
      <div className="text-slate-200">
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="mt-2 text-slate-400">Loading…</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-slate-100">Settings</h1>
          <p className="mt-1 text-sm text-slate-300">
            Configure alert sensitivity, notifications, monitoring, and time display.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outlined"
            startIcon={<RestartAltRoundedIcon />}
            onClick={reset}
            sx={{
              borderColor: "rgba(255,255,255,0.15)",
              color: "rgba(255,255,255,0.85)",
            }}
          >
            Reset
          </Button>

          <Button
            variant="contained"
            startIcon={<SaveRoundedIcon />}
            onClick={save}
            disabled={!dirty}
            sx={{
              backgroundColor: "#3B82F6",
              "&:hover": { backgroundColor: "#2563EB" },
            }}
          >
            Save
          </Button>
        </div>
      </div>

      {/* Cards */}
      <div className="grid gap-5 lg:grid-cols-2">
        {/* Detection & Alerts */}
        <GlassCard
          title="Detection & Alerts"
          icon={<TuneRoundedIcon fontSize="small" />}
          right={<SettingsOutlinedIcon fontSize="small" />}
          className="bg-gradient-to-b from-white/5 to-white/0"
        >
          <div className="space-y-5">
            {/* Monitoring enabled */}
            <div className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/0 px-4 py-3">
              <div>
                <div className="text-sm font-semibold text-slate-100">Monitoring enabled</div>
                <div className="text-xs text-slate-300">
                  Master switch to pause runtime monitoring during maintenance/testing.
                </div>
              </div>

              <Switch
                checked={settings.monitoringEnabled}
                onChange={(e) => setField("monitoringEnabled", e.target.checked)}
              />
            </div>


            {/* Notifications */}
            <div className="rounded-xl border border-white/10 bg-white/0 px-4 py-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <NotificationsNoneRoundedIcon fontSize="small" className="text-slate-300" />
                    <div className="text-sm font-semibold text-slate-100">Notifications</div>
                  </div>
                </div>

                <Switch
                  checked={settings.notificationsEnabled}
                  onChange={(e) => setField("notificationsEnabled", e.target.checked)}
                />
              </div>

              <div className="mt-3">
                <FormControlLabel
                  control={
                    <Switch
                      checked={settings.notifyCriticalOnly}
                      onChange={(e) => setField("notifyCriticalOnly", e.target.checked)}
                      disabled={!settings.notificationsEnabled}
                    />
                  }
                  label={
                    <span className="text-sm text-slate-200">
                      Notify only Critical alerts
                    </span>
                  }
                />
                <div className="text-xs text-slate-400">
                  Reduces alert fatigue by notifying only high-confidence/high-impact events.
                </div>
              </div>
            </div>
          </div>
        </GlassCard>

        {/* System Preferences */}
        <GlassCard
          title="System Preferences"
          icon={<ScheduleRoundedIcon fontSize="small" />}
          right={<SettingsOutlinedIcon fontSize="small" />}
          className="bg-gradient-to-b from-white/5 to-white/0"
        >
          <div className="space-y-5">
            {/* Time display */}
            <div className="rounded-xl border border-white/10 bg-white/0 px-4 py-4">
              <div className="text-sm font-semibold text-slate-100">Time display</div>
              <div className="mt-1 text-xs text-slate-300">
                Choose how timestamps are shown across charts and logs.
              </div>

              <div className="mt-3">
                <FormControl fullWidth size="small">
                  <InputLabel sx={{ color: "rgba(255,255,255,0.7)" }}>
                    Timezone
                  </InputLabel>
                  <Select
                    value={settings.timeDisplay}
                    label="Timezone"
                    onChange={(e) => setField("timeDisplay", e.target.value)}
                    sx={{
                      color: "rgba(255,255,255,0.9)",
                      ".MuiOutlinedInput-notchedOutline": {
                        borderColor: "rgba(255,255,255,0.15)",
                      },
                      "&:hover .MuiOutlinedInput-notchedOutline": {
                        borderColor: "rgba(255,255,255,0.25)",
                      },
                      ".MuiSvgIcon-root": { color: "rgba(255,255,255,0.7)" },
                    }}
                  >
                    <MenuItem value="LOCAL">Local time</MenuItem>
                    <MenuItem value="UTC">UTC (recommended for logs)</MenuItem>
                  </Select>
                </FormControl>

                <div className="mt-2 text-xs text-slate-400">
                  UTC avoids confusion when events are stored with <code className="text-slate-200">Z</code> timestamps.
                </div>
              </div>
            </div>

            {/* Summary note - Settings are stored locally in your browser (localStorage). When backend APIs
                are ready, this page can save to a database and apply settings globally. */}

          </div>
        </GlassCard>
      </div>

      {/* Toast */}
      <Snackbar
        open={toastOpen}
        autoHideDuration={2500}
        onClose={() => setToastOpen(false)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <Alert
          onClose={() => setToastOpen(false)}
          severity={toastSeverity}
          variant="filled"
          sx={{ borderRadius: 2 }}
        >
          {toastMsg}
        </Alert>
      </Snackbar>
    </div>
  );
}