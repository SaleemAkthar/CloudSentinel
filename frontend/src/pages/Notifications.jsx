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
  return (
    <div>
    </div>
  );
}