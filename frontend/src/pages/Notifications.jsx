import { useState } from "react";
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
import alertsData from "../test/alerts.json"; 


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

  // Message templates based on severity + features
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

  // INFO
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
  // state for notifications list and active filter
  const [notifications, setNotifications] = useState(() =>alertsToNotifications(alertsData));
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

      {/* pinned notifications section */}
      {pinnedNotifications.length > 0 && (
        <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden">
          <div className="px-5 py-3 border-b border-white/10 flex items-center gap-2 text-sm font-semibold text-slate-300">
            <PushPinRoundedIcon
              fontSize="small"
              className="text-yellow-400"
            />
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

      {/* chart and notification list grid */}
      <div className="grid grid-cols-1 lg:grid-cols-1 gap-6 items-start">


        {/* notification list */}
        <div className="rounded-2xl border border-white/10 bg-white/5 overflow-hidden h-[70vh] flex flex-col">

          {/* filter tabs */}
          <div className="sticky top-0 z-10 border-b border-white/10 bg-[#0a1328]/90 backdrop-blur">
            <div className="flex items-center gap-3 px-5 py-3">
              {/* left icon */}
              <div className="grid h-9 w-9 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10 text-slate-300">
                <NotificationsNoneRoundedIcon fontSize="small" />
              </div>

              {/* pills */}
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

              {/* right: optional count */}
              <div className="ml-auto text-xs text-slate-400">
                Showing{" "}
                <span className="text-slate-200 font-semibold">
                  {filtered.length}
                </span>{" "}
                notifications
              </div>
            </div>
          </div>
          
          {/* notification items */}
          <div className="flex-1 overflow-y-auto">
            <div className="divide-y divide-white/5"></div>
              {filtered.length === 0 ? (
                <div className="p-8 text-center text-slate-400">
                  No notifications found
                </div>
              ) : (
                filtered.map((n) => {
                  const style = typeStyles[n.type];

                  return (
                    <div
                      key={n.id}
                      onClick={() => markRead(n.id)}
                      className={`flex items-start gap-4 px-5 py-4 border-l-4 ${style.border} cursor-pointer transition-colors ${
                        n.read
                          ? "opacity-60 hover:opacity-80"
                          : "bg-white/3 hover:bg-white/5"
                      }`}
                    >
                      {/* unread dot */}
                      <div className="mt-1 shrink-0">
                        {!n.read ? (
                          <span
                            className={`block w-2 h-2 rounded-full ${style.dot}`}
                          />
                        ) : (
                          <span className="block w-2 h-2 rounded-full bg-transparent" />
                        )}
                      </div>

                      {/* content */}
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

                      {/* pin button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          togglePin(n.id);
                        }}
                        className={`shrink-0 mt-1 transition-colors ${
                          n.pinned
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
          </div>
        </div>
      </div>
    // </div>
  );
}