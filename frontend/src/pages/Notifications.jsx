import { useEffect, useState, useCallback } from "react";
import axios from "axios";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import CheckCircleOutlineRoundedIcon from "@mui/icons-material/CheckCircleOutlineRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import PushPinOutlinedIcon from "@mui/icons-material/PushPinOutlined";
import PushPinRoundedIcon from "@mui/icons-material/PushPinRounded";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

// Polling interval — refresh every 500ms (Matches RealTimeAlerts) 
const POLL_INTERVAL = 5000;

//  Static Chart Data (Historical Context) 
const chartData = [
  { day: "Mon", notifications: 3 },
  { day: "Tue", notifications: 7 },
  { day: "Wed", notifications: 2 },
  { day: "Thu", notifications: 9 },
  { day: "Fri", notifications: 5 },
  { day: "Sat", notifications: 1 },
  { day: "Sun", notifications: 4 },
];

//  Styles for each notification type 
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

//  Helper Functions 
function timeAgo(iso) {
  const t = new Date(iso).getTime();
  const now = Date.now();
  const diff = Math.max(0, now - t);

  const mins = Math.floor(diff / (60 * 1000));
  if (mins < 60) return `${mins} minutes ago`;

  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} hours ago`;

  const days = Math.floor(hours / 24);
  return `${days} days ago`;
}

function buildMessageFromAlert(a) {
  const f = a.features || {};
  const score = typeof a.anomaly_score === "number" ? a.anomaly_score : 0;

  if (a.severity === "CRITICAL") {
    if ((f.outbound_calls || 0) >= 4) {
      return `${a.function} made unusually high outbound calls (${f.outbound_calls}).`;
    }
    if ((f.error_count || 0) >= 1) {
      return `${a.function} triggered critical errors (error_count=${f.error_count}).`;
    }
    return `${a.function} exceeded anomaly threshold (score=${score.toFixed(2)}).`;
  }

  if (a.severity === "WARNING") {
    if ((f.unique_destinations || 0) >= 2) {
      return `${a.function} contacted multiple destinations (${f.unique_destinations}).`;
    }
    if ((f.duration_ms || 0) >= 800) {
      return `${a.function} execution time is higher than normal (${f.duration_ms}ms).`;
    }
    if ((f.outbound_calls || 0) >= 2) {
      return `${a.function} showed unusual outbound calls (${f.outbound_calls}).`;
    }
    return `${a.function} showed unusual behaviour (score=${score.toFixed(2)}).`;
  }

  if ((f.duration_ms || 0) > 0) {
    return `${a.function} ran normally (duration ${f.duration_ms}ms).`;
  }
  return `${a.function} informational event recorded.`;
}

function buildTitleFromAlert(a) {
  if (a.severity === "CRITICAL") return "Critical alert triggered";
  if (a.severity === "WARNING") return "Warning detected";
  return "System update";
}

function alertsToNotifications(alerts) {
  if (!Array.isArray(alerts)) return [];

  // Sort newest first
  const sorted = alerts
    .slice()
    .sort((x, y) => new Date(y.timestamp) - new Date(x.timestamp));

  return sorted.map((a, idx) => ({
    id: a.id || idx + 1,
    type: a.severity || "INFO",
    title: buildTitleFromAlert(a),
    message: buildMessageFromAlert(a),
    time: timeAgo(a.timestamp),
    read: false,
    pinned: false,
    _raw: a, // keep original alert if you need details later
  }));
}

export default function Notifications() {
  //  Local State (UI Preferences & Transformations) 
  const [notifications, setNotifications] = useState([]);
  const [filter, setFilter] = useState("ALL");

  //  Backend Connection States 
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  //  Fetch Alerts from Live Backend 
  const fetchNotifications = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const res = await axios.get("/api/alerts?limit=500");
      const data = Array.isArray(res.data) ? res.data : [];

      // Transform and Set State
      const transformed = alertsToNotifications(data);
      setNotifications(transformed);
    } catch (err) {
      console.error("Failed to fetch notifications:", err);
      setError("Backend unavailable — please ensure the server is running");
      // Optional: Keep showing old data instead of clearing on error
      // Or clear data to indicate disconnect
      // setNotifications([]); 
    } finally {
      setLoading(false);
    }
  }, []);

  //  Initial Fetch + Polling Loop 
  useEffect(() => {
    fetchNotifications();

    const interval = setInterval(fetchNotifications, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  //  UI Interaction Handlers 
  const markAllRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  };

  const markRead = (id) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n))
    );
  };

  const togglePin = (id) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, pinned: !n.pinned } : n))
    );
  };

  //  Derived Values 
  const unreadCount = notifications.filter((n) => !n.read).length;
  const pinnedNotifications = notifications.filter((n) => n.pinned);
  const filtered = notifications.filter((n) =>
    filter === "ALL" ? true : n.type === filter
  );

  return (
    <div className="space-y-6 text-white">
      {/* HEADER */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-3xl font-bold">Notifications</h1>
          <p className="text-slate-400 mt-1">
            Stay updated on security events and system activity
          </p>
        </div>

        {/* Live Status Indicator (Mirroring RealTimeAlerts) */}
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${error ? "bg-red-400" : "bg-emerald-400 animate-pulse"
              }`}
          />
          <span className="text-xs text-slate-400">
            {error ? "Disconnected" : `Live • Polling ${POLL_INTERVAL / 1000}s`}
          </span>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          {
            label: "Total",
            value: notifications.length,
            color: "text-slate-200",
          },
          {
            label: "Unread",
            value: unreadCount,
            color: "text-blue-400",
          },
          {
            label: "Critical",
            value: notifications.filter((n) => n.type === "CRITICAL").length,
            color: "text-red-400",
          },
          {
            label: "Warnings",
            value: notifications.filter((n) => n.type === "WARNING").length,
            color: "text-orange-400",
          },
        ].map(({ label, value, color }) => (
          <div
            key={label}
            className="rounded-2xl border border-white/10 bg-white/5 p-4"
          >
            <div className="text-xs text-slate-400 uppercase tracking-wide mb-1">
              {label}
            </div>
            <div className={`text-3xl font-bold ${color}`}>{value}</div>
          </div>
        ))}
      </div>

      {/* Pinned Notifications Section */}
      {pinnedNotifications.length > 0 && (
        <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
          <div className="px-5 py-3 border-b border-white/10 flex items-center gap-2 text-sm font-semibold text-slate-300">
            <PushPinRoundedIcon fontSize="small" className="text-yellow-400" />
            <span>Pinned</span>
            <span className="ml-auto text-xs text-slate-500">
              {pinnedNotifications.length} pinned
            </span>
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
                      <span className="text-sm font-semibold text-white">
                        {n.title}
                      </span>
                      <span
                        className={`px-2 py-0.5 text-xs rounded-full font-medium ${style.badge}`}
                      >
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

      {/* Main Content Grid: Chart (Static) + Notifications List (Dynamic) */}
      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6 items-start">

        {/* Notification List Container */}
        <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden h-[70vh] flex flex-col">

          {/* Filter Tabs Header */}
          <div className="sticky top-0 z-10 border-b border-white/10 bg-[#0a1328]/90 backdrop-blur">
            <div className="flex items-center gap-3 px-5 py-3">
              {/* Icon Badge */}
              <div className="grid h-9 w-9 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10 text-slate-300">
                <NotificationsNoneRoundedIcon fontSize="small" />
              </div>

              {/* Pills */}
              <div className="flex flex-wrap items-center gap-2">
                {["ALL", "CRITICAL", "WARNING", "INFO"].map((tab) => {
                  const active = filter === tab;
                  const activeCls =
                    "bg-white/15 text-white ring-1 ring-white/20 shadow-[0_0_0_1px_rgba(255,255,255,0.08)]";
                  const idleCls =
                    "text-slate-300 hover:text-white hover:bg-white/5 ring-1 ring-white/10";

                  return (
                    <button
                      key={tab}
                      onClick={() => setFilter(tab)}
                      className={[
                        "px-4 py-1.5 rounded-full text-xs font-semibold tracking-wide",
                        "transition-colors",
                        active ? activeCls : idleCls,
                      ].join(" ")}
                    >
                      {tab}
                    </button>
                  );
                })}
              </div>

              {/* Count */}
              <div className="ml-auto text-xs text-slate-400">
                Showing{" "}
                <span className="text-slate-200 font-semibold">
                  {filtered.length}
                </span>{" "}
                notifications
              </div>
            </div>
          </div>

          {/* Notification Items Area */}
          <div className="flex-1 overflow-y-auto relative">
            {/* Top Action Button for Unreads */}
            {unreadCount > 0 && (
              <div className="absolute top-0 right-0 z-20 px-4 pt-2 hidden lg:block">
                <button
                  onClick={markAllRead}
                  className="flex items-center gap-2 px-3 py-1.5 text-xs rounded-lg bg-blue-600/20 border border-blue-500/40 text-blue-300 hover:bg-blue-600/30 transition-colors"
                >
                  <CheckCircleOutlineRoundedIcon fontSize="small" />
                  Mark all as read
                </button>
              </div>
            )}

            {!loading ? (
              <div className="divide-y divide-white/5 h-full">
                {filtered.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-400 space-y-3">
                    <NotificationsNoneRoundedIcon fontSize="large" className="opacity-20" />
                    <span>No notifications found</span>
                  </div>
                ) : (
                  filtered.map((n) => {
                    const style = typeStyles[n.type];
                    return (
                      <div
                        key={n.id}
                        onClick={() => markRead(n.id)}
                        className={`flex items-start gap-4 px-5 py-4 border-l-4 ${style.border} cursor-pointer transition-colors ${n.read
                            ? "opacity-60 hover:opacity-80"
                            : "bg-white/3 hover:bg-white/5"
                          }`}
                      >
                        {/* Dot Indicator */}
                        <div className="mt-1 shrink-0">
                          {!n.read ? (
                            <span
                              className={`block w-2 h-2 rounded-full ${style.dot}`}
                            />
                          ) : (
                            <span className="block w-2 h-2 rounded-full bg-transparent" />
                          )}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <span className="text-sm font-semibold text-white">
                              {n.title}
                            </span>
                            <span
                              className={`px-2 py-0.5 text-xs rounded-full font-medium ${style.badge}`}
                            >
                              {n.type}
                            </span>
                          </div>
                          <p className="text-sm text-slate-400">{n.message}</p>
                          <p className="text-xs text-slate-500 mt-1">{n.time}</p>
                        </div>

                        {/* Pin Button */}
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            togglePin(n.id);
                          }}
                          className={`shrink-0 mt-1 transition-colors ${n.pinned
                              ? "text-yellow-400"
                              : "text-slate-600 hover:text-slate-300"
                            }`}
                          title={n.pinned ? "Unpin" : "Pin"}
                        >
                          {n.pinned ? (
                            <PushPinRoundedIcon fontSize="small" />
                          ) : (
                            <PushPinOutlinedIcon fontSize="small" />
                          )}
                        </button>
                      </div>
                    );
                  })
                )}
              </div>
            ) : (
              // Loading Skeleton
              <div className="flex flex-col items-center justify-center h-full text-slate-400 space-y-2">
                <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-emerald-400"></div>
                <span>Loading notifications...</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}