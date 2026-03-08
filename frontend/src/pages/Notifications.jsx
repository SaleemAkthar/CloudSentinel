import { useState } from "react";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import CheckCircleOutlineRoundedIcon from "@mui/icons-material/CheckCircleOutlineRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import PushPinOutlinedIcon from "@mui/icons-material/PushPinOutlined";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

// Notifications page component

// static chart data for last 7 days
const chartData = [
  { day: "Mon", notifications: 3 },
  { day: "Tue", notifications: 7 },
  { day: "Wed", notifications: 2 },
  { day: "Thu", notifications: 9 },
  { day: "Fri", notifications: 5 },
  { day: "Sat", notifications: 1 },
  { day: "Sun", notifications: 4 },
];

// styles for each notification type
const typeStyles = {
  CRITICAL: {
    icon: <WarningAmberRoundedIcon fontSize="small" />,
    badge: "bg-red-500/15 text-red-400 border border-red-500/30",
    dot: "bg-red-400",
    border: "border-l-red-500",
  },
  WARNING: {
    icon: <WarningAmberRoundedIcon fontSize="small" />,
    badge: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
    dot: "bg-orange-400",
    border: "border-l-orange-400",
  },
  INFO: {
    icon: <InfoOutlinedIcon fontSize="small" />,
    badge: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
    dot: "bg-blue-400",
    border: "border-l-blue-400",
  },
};

// mock notification data
const mockNotifications = [
  { id: 1, type: "CRITICAL", title: "Critical alert triggered", message: "paymentHandler exceeded anomaly threshold", time: "5 minutes ago", read: false, pinned: false },
  { id: 2, type: "WARNING", title: "Warning detected", message: "dataSync showed unusual outbound calls", time: "1 hour ago", read: false, pinned: false },
  { id: 3, type: "INFO", title: "Weekly summary generated", message: "Your weekly security digest is ready to view", time: "2 days ago", read: true, pinned: false },
  { id: 4, type: "CRITICAL", title: "Critical alert triggered", message: "authCallback flagged with high anomaly score", time: "3 days ago", read: true, pinned: false },
  { id: 5, type: "INFO", title: "Model training complete", message: "AI model retrained with latest data successfully", time: "4 days ago", read: true, pinned: false },
  { id: 6, type: "WARNING", title: "Elevated error rate", message: "imageResize function error rate above normal", time: "5 days ago", read: true, pinned: false },
];

export default function Notifications() {
  // state for notifications list and active filter
  const [notifications, setNotifications] = useState(mockNotifications);
  const [filter, setFilter] = useState("ALL");
  // mark all notifications as read
  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };
  // mark a single notification as read
  const markRead = (id) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };
  // toggle pin status of a notification
  const togglePin = (id) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, pinned: !n.pinned } : n))
    );
  };
  // derived values
  const unreadCount = notifications.filter((n) => !n.read).length;
  const pinnedNotifications = notifications.filter((n) => n.pinned);
  const filtered = notifications.filter((n) =>
    filter === "ALL" ? true : n.type === filter
  );
  return (
    <div className="space-y-6 text-white">
      {/* page header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold">Notifications</h1>
          <p className="text-slate-400 mt-1">
            Stay updated on security events and system activity
          </p>
        </div>
        {unreadCount > 0 && (
          <button
            onClick={markAllRead}
            className="flex items-center gap-2 px-4 py-2 text-sm rounded-xl bg-blue-600/20 border border-blue-500/40 text-blue-300 hover:bg-blue-600/30 transition-colors"
          >
            <CheckCircleOutlineRoundedIcon fontSize="small" />
            Mark all as read
          </button>
        )}
      </div>
        {/* summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
                { label: "Total", value: notifications.length, color: "text-slate-200" },
                { label: "Unread", value: unreadCount, color: "text-blue-400" },
                { label: "Critical", value: notifications.filter((n) => n.type === "CRITICAL").length, color: "text-red-400" },
                { label: "Warnings", value: notifications.filter((n) => n.type === "WARNING").length, color: "text-orange-400" },
            ].map(({ label, value, color }) => (
                <div key={label} className="rounded-2xl border border-white/10 bg-white/5 p-4">
                    <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">{label}</div>
                    <div className={`text-3xl font-bold ${color}`}>{value}</div>
                </div>
            ))}
        </div>
            {/* pinned notifications section */}
            {pinnedNotifications.length > 0 && (
                <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
                    <div className="px-5 py-3 border-b border-white/10 flex items-center gap-2 text-sm font-semibold text-slate-300">
                        <PushPinRoundedIcon fontSize="small" className="text-yellow-400" />
                        <span>Pinned</span>
                        <span className="ml-auto text-xs text-slate-500">{pinnedNotifications.length} pinned</span>
                    </div>
                    <div className="divide-y divide-white/5">
                        {pinnedNotifications.map((n) => {
                            const style = typeStyles[n.type];
                            return (
                                <div
                                    key={n.id}
                                    className={`flex items-start gap-4 px-5 py-4 border-l-4 ${style.border} bg-yellow-500/5`}
                                >
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap mb-1">
                                            <span className="text-sm font-semibold text-white">{n.title}</span>
                                            <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${style.badge}`}>
                                                {n.type}
                                            </span>
                                        </div>
                                        <p className="text-sm text-slate-400">{n.message}</p>
                                        <p className="text-xs text-slate-500 mt-1">{n.time}</p>
                                    </div>
                                    <button
                                        onClick={() => togglePin(n.id)}
                                        className="shrink-0 mt-1 text-yellow-400 hover:text-slate-400 transition-colors"
                                        title="Unpin"
                                    >
                                        <PushPinRoundedIcon fontSize="small" />
                                    </button>
                                </div>
                            );
                        })}
                    </div>
                </div>
            )}
                {/* chart and notification list grid */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

                    {/* bar chart card */}
                    <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
                        <div className="px-5 py-3 border-b border-white/10 text-sm font-semibold text-slate-300">
                            Notifications — Last 7 Days
                        </div>
                    <div className="p-4 h-[220px]">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                                <XAxis dataKey="day" stroke="rgba(255,255,255,0.4)" tick={{ fontSize: 11 }} />
                                <YAxis stroke="rgba(255,255,255,0.4)" tick={{ fontSize: 11 }} />
                                <Tooltip
                                    contentStyle={{
                                        background: "rgba(10, 20, 45, 0.95)",
                                        border: "1px solid rgba(255,255,255,0.12)",
                                        borderRadius: 10,
                                        color: "white",
                                        fontSize: 12,
                                    }}
                                />
                            <Bar dataKey="notifications" fill="#3B82F6" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                    </div>
                </div>

            </div>
    </div>
  );
}