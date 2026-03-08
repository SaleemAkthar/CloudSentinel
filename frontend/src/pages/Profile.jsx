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
                        {/* member info rows */}
                        <div className="w-full border-t border-white/5 pt-4 flex flex-col gap-2 text-xs text-slate-400">
                          <div className="flex items-center justify-between">
                            <span>Member since</span>
                            <span className="text-slate-200">{user.joined}</span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>2FA Security</span>
                            <span className={user.twoFA ? "text-emerald-400" : "text-red-400"}>
                              {user.twoFA ? "Enabled" : "Disabled"}
                            </span>
                          </div>
                        </div>
                </div>
            </div>
        {/* right column - scrollable */}
        <div className="lg:col-span-2 space-y-4 overflow-y-auto max-h-[80vh] pr-2">
            {/* account information card */}
            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
                <div className="px-5 py-3 border-b border-white/10 flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-300">
                    <PersonOutlineRoundedIcon fontSize="small" />
                    Account Information
                </div>
                {!editing ? (
                    <button onClick={handleEdit} className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-300 hover:bg-blue-600/30 transition-colors">
                    ✎ Edit
                    </button>
                ) : (
                    <div className="flex gap-2">
                    <button onClick={handleCancel} className="px-3 py-1.5 text-xs rounded-lg bg-white/5 border border-white/10 text-slate-300 hover:bg-white/10 transition-colors">
                        Cancel
                    </button>
                    <button onClick={handleSave} className="px-3 py-1.5 text-xs rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 transition-colors">
                        Save
                    </button>
                    </div>
                )}
                </div>
                <div className="p-5">
                <InfoRow icon={<PersonOutlineRoundedIcon fontSize="small" />} label="Full Name" value={editing ? draft.name : user.name} editing={editing} fieldKey="name" onChange={handleFieldChange} />
                <InfoRow icon={<GridViewRoundedIcon fontSize="small" />} label="Role" value={editing ? draft.role : user.role} editing={editing} fieldKey="role" onChange={handleFieldChange} />
                <InfoRow icon={<DescriptionOutlinedIcon fontSize="small" />} label="Email Address" value={editing ? draft.email : user.email} editing={editing} fieldKey="email" onChange={handleFieldChange} />
                <InfoRow icon={<ShowChartRoundedIcon fontSize="small" />} label="Organization" value={editing ? draft.organization : user.organization} editing={editing} fieldKey="organization" onChange={handleFieldChange} />
                <InfoRow icon={<AutoAwesomeRoundedIcon fontSize="small" />} label="Member Since" value={user.joined} editing={false} fieldKey="joined" onChange={() => {}} />
                </div>
            </div>
                {/* notification preferences card */}
                <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
                    <div className="px-5 py-3 border-b border-white/10 flex items-center gap-2 text-sm font-semibold text-slate-300">
                        <NotificationsNoneRoundedIcon fontSize="small" />
                        Notification Preferences
                    </div>
                    <div className="p-5 space-y-4">
                        {[
                            { key: "email", label: "Email Alerts", desc: "Receive security alerts via email" },
                            { key: "critical", label: "Critical Threat Alerts", desc: "Instant notifications for CRITICAL severity threats" },
                            { key: "weekly", label: "Weekly Summary", desc: "Weekly security digest and performance report" },
                        ].map(({ key, label, desc }) => (
                            <div key={key} className="flex items-center justify-between">
                                <div>
                                    <div className="text-sm text-slate-200">{label}</div>
                                    <div className="text-xs text-slate-500">{desc}</div>
                                </div>
                                <ToggleSwitch enabled={user.notifications[key]} onToggle={() => toggleNotification(key)} />
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
                            {/* security card */}
            <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
              <div className="px-5 py-3 border-b border-white/10 flex items-center gap-2 text-sm font-semibold text-slate-300">
                <WarningAmberRoundedIcon fontSize="small" />
                Security
              </div>
              <div className="p-5 space-y-3">
                <div className="flex items-center justify-between py-2 border-b border-white/5">
                  <div>
                    <div className="text-sm text-slate-200">Two-Factor Authentication</div>
                    <div className="text-xs text-slate-500">Extra layer of security on your account</div>
                  </div>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${user.twoFA ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30" : "bg-red-500/15 text-red-400 border border-red-500/30"}`}>
                    {user.twoFA ? "Enabled" : "Disabled"}
                  </span>
                </div>
                <div className="flex items-center justify-between py-2">
                  <div>
                    <div className="text-sm text-slate-200">Password</div>
                    <div className="text-xs text-slate-500">Last changed 30 days ago</div>
                  </div>
                  <button className="px-3 py-1.5 text-xs rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-300 hover:bg-blue-600/30 transition-colors">
                    Change
                  </button>
                </div>
              </div>
            </div>
            </div>  
        </div>
    </div>
  );
}  