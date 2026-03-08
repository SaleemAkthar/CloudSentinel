// MUI icon imports for UI elements
import { useState } from "react";
import PersonOutlineRoundedIcon from "@mui/icons-material/PersonOutlineRounded";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import ShowChartRoundedIcon from "@mui/icons-material/ShowChartRounded";
import GridViewRoundedIcon from "@mui/icons-material/GridViewRounded";

// default user data
const initialUser = {
  name: "Display Name",
  role: "Display Role",
  email: "email@cloudsentinel.io",
  organization: "Cloud Sentinel Security",
  joined: "January 2025",
  avatar: "DN",
  plan: "Team",
  twoFA: true,
  notifications: {
    email: true,
    critical: true,
    weekly: false,
  },
};

// reusable row component for each info field
function InfoRow({ icon, label, value, editing, fieldKey, onChange }) {
  return (
    <div className="flex items-center gap-4 py-3 border-b border-white/5 last:border-0">
      <div className="text-slate-400 w-5 shrink-0">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="text-xs text-slate-500 mb-0.5">{label}</div>
        {editing ? (
          <input
            className="w-full bg-white/5 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-white outline-none focus:border-blue-500/60 transition-colors"
            value={value}
            onChange={(e) => onChange(fieldKey, e.target.value)}
          />
        ) : (
          <div className="text-sm text-white truncate">{value}</div>
        )}
      </div>
    </div>
  );
}

// toggle switch for notification settings
function ToggleSwitch({ enabled, onToggle }) {
  return (
    <button
      onClick={onToggle}
      className={`relative w-10 h-5 rounded-full transition-colors ${
        enabled ? "bg-blue-500" : "bg-white/10"
      }`}
    >
      <span
        className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${
          enabled ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}

// Profile page component
export default function Profile() {
  return (
    <div className="text-white">
      <h1 className="text-3xl font-bold">My Profile</h1>
    </div>
  );
}