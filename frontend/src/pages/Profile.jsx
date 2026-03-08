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
    // state for user data, edit mode, draft changes and save confirmation
    const [user, setUser] = useState(initialUser);
    const [editing, setEditing] = useState(false);
    const [draft, setDraft] = useState(initialUser);
    const [saved, setSaved] = useState(false);

    // enter edit mode
    const handleEdit = () => {
        setDraft(user);
        setEditing(true);
    };

    // save changes and show confirmation
    const handleSave = () => {
        setUser(draft);
        setEditing(false);
        setSaved(true);
        setTimeout(() => setSaved(false), 2500);
    };

    // cancel editing without saving
    const handleCancel = () => {
        setDraft(user);
        setEditing(false);
    };

    // update a single field in draft
    const handleFieldChange = (key, value) => {
        setDraft((prev) => ({ ...prev, [key]: value }));
    };

    // toggle notification preferences
    const toggleNotification = (key) => {
        setUser((prev) => ({
        ...prev,
        notifications: { ...prev.notifications, [key]: !prev.notifications[key] },
     }));
  };
  return (
    <div className="flex flex-col h-full space-y-6 text-white">

      {/* page header with title and save confirmation */}
      <div className="flex items-center justify-between flex-wrap gap-3 shrink-0">
        <div>
          <h1 className="text-3xl font-bold">My Profile</h1>
          <p className="text-slate-400 mt-1">Manage your account information and preferences</p>
        </div>

        {saved && (
          <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 text-sm">
            ✓ Profile updated successfully
          </div>
        )}
      </div>
            {/* grid layout - left sticky, right scrollable */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

        {/* left column - stays in place while right scrolls */}
        <div className="sticky top-6 shrink-0">
            {/* avatar card */}
            <div className="rounded-2xl border border-white/10 bg-white/5 p-6 flex flex-col items-center text-center">
                <div className="relative mb-4">
                    <div className="w-24 h-24 rounded-full bg-gradient-to-br from-blue-500 to-cyan-400 flex items-center justify-center text-3xl font-bold text-white shadow-lg shadow-blue-500/20">
                        {user.avatar}
                    </div>
                    <span className="absolute bottom-1 right-1 w-4 h-4 rounded-full bg-emerald-400 border-2 border-[#050B1A]" />
                    </div>
                        <div className="text-lg font-semibold">{user.name}</div>
                        <div className="text-sm text-slate-400 mb-3">{user.role}</div>

                        {/* plan badge */}
                        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-blue-500/15 border border-blue-500/30 text-blue-300 text-xs font-medium mb-4">
                            ✦ {user.plan} Plan    
                        </div>
                </div>
            </div>
        {/* right column - scrollable */}
        <div className="lg:col-span-2 space-y-4 overflow-y-auto max-h-[80vh] pr-2">
        </div>

      </div>
    </div>
  );
}