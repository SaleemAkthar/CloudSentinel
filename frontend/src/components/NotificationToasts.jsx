import { useEffect, useState } from "react";
import { useNotifications } from "../context/NotificationContext";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import ErrorOutlineRoundedIcon from "@mui/icons-material/ErrorOutlineRounded";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";

const AUTO_DISMISS_MS = 10000;

const SEVERITY_CONFIG = {
  critical: {
    border:  "border-red-500/70",
    glow:    "shadow-[0_0_24px_rgba(239,68,68,0.25)]",
    bg:      "bg-gradient-to-r from-red-950/80 to-[#0d0f1f]/90",
    badge:   "bg-red-500/20 text-red-400 border border-red-500/40",
    icon:    <ErrorOutlineRoundedIcon fontSize="small" />,
    iconCls: "text-red-400",
    label:   "CRITICAL",
    bar:     "bg-red-500",
  },
  high: {
    border:  "border-orange-400/60",
    glow:    "shadow-[0_0_24px_rgba(251,146,60,0.20)]",
    bg:      "bg-gradient-to-r from-orange-950/80 to-[#0d0f1f]/90",
    badge:   "bg-orange-400/15 text-orange-300 border border-orange-400/40",
    icon:    <WarningAmberRoundedIcon fontSize="small" />,
    iconCls: "text-orange-400",
    label:   "HIGH",
    bar:     "bg-orange-400",
  },
  warning: {
    border:  "border-yellow-400/60",
    glow:    "shadow-[0_0_24px_rgba(250,204,21,0.18)]",
    bg:      "bg-gradient-to-r from-yellow-950/80 to-[#0d0f1f]/90",
    badge:   "bg-yellow-400/15 text-yellow-300 border border-yellow-400/40",
    icon:    <WarningAmberRoundedIcon fontSize="small" />,
    iconCls: "text-yellow-400",
    label:   "WARNING",
    bar:     "bg-yellow-400",
  },
  medium: {
    border:  "border-yellow-400/60",
    glow:    "shadow-[0_0_24px_rgba(250,204,21,0.18)]",
    bg:      "bg-gradient-to-r from-yellow-950/80 to-[#0d0f1f]/90",
    badge:   "bg-yellow-400/15 text-yellow-300 border border-yellow-400/40",
    icon:    <WarningAmberRoundedIcon fontSize="small" />,
    iconCls: "text-yellow-400",
    label:   "MEDIUM",
    bar:     "bg-yellow-400",
  },
  info: {
    border:  "border-cyan-400/50",
    glow:    "shadow-[0_0_20px_rgba(34,211,238,0.12)]",
    bg:      "bg-gradient-to-r from-cyan-950/80 to-[#0d0f1f]/90",
    badge:   "bg-cyan-400/15 text-cyan-300 border border-cyan-400/40",
    icon:    <InfoOutlinedIcon fontSize="small" />,
    iconCls: "text-cyan-400",
    label:   "INFO",
    bar:     "bg-cyan-400",
  },
};

const fallbackConfig = SEVERITY_CONFIG.info;

function ToastCard({ toast, onDismiss }) {
  const cfg = SEVERITY_CONFIG[toast.severity] ?? fallbackConfig;
  const [visible, setVisible] = useState(false);
  const [progress, setProgress] = useState(100);

  // Slide-in
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 30);
    return () => clearTimeout(t);
  }, []);

  // Progress bar drain
  useEffect(() => {
    const start = Date.now();
    const tick = () => {
      const elapsed = Date.now() - start;
      const remaining = Math.max(0, 100 - (elapsed / AUTO_DISMISS_MS) * 100);
      setProgress(remaining);
      if (remaining > 0) requestAnimationFrame(tick);
    };
    const raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  // Auto-dismiss
  useEffect(() => {
    const t = setTimeout(() => onDismiss(toast.id), AUTO_DISMISS_MS);
    return () => clearTimeout(t);
  }, [toast.id, onDismiss]);

  const time = toast.ts
    ? new Date(toast.ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
    : "";

  return (
    <div
      style={{
        transform: visible ? "translateX(0)" : "translateX(110%)",
        opacity: visible ? 1 : 0,
        transition: "transform 0.35s cubic-bezier(.22,1,.36,1), opacity 0.3s ease",
      }}
      className={`
        relative w-80 overflow-hidden rounded-2xl border backdrop-blur-md
        ${cfg.border} ${cfg.glow} ${cfg.bg}
      `}
    >
      {/* Progress bar */}
      <div
        className={`absolute top-0 left-0 h-[2.5px] ${cfg.bar} transition-none`}
        style={{ width: `${progress}%` }}
      />

      <div className="flex items-start gap-3 px-4 pt-4 pb-3">
        {/* Icon */}
        <div className={`mt-0.5 shrink-0 ${cfg.iconCls}`}>{cfg.icon}</div>

        {/* Body */}
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 mb-1">
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${cfg.badge}`}>
              {cfg.label}
            </span>
            <span className="text-[10px] text-slate-400">{time}</span>
          </div>

          <div className="text-sm font-semibold text-slate-100 leading-snug truncate">
            Anomaly Detected
          </div>
          <div className="text-xs text-slate-400 mt-0.5 truncate">
            {toast.fn}
          </div>
          {toast.score != null && (
            <div className="text-[10px] text-slate-500 mt-1">
              Anomaly score: <span className="text-slate-300 font-medium">{Number(toast.score).toFixed(2)}</span>
            </div>
          )}
        </div>

        {/* Close */}
        <button
          onClick={() => onDismiss(toast.id)}
          className="shrink-0 mt-0.5 text-slate-500 hover:text-slate-200 transition-colors"
        >
          <CloseRoundedIcon sx={{ fontSize: 16 }} />
        </button>
      </div>
    </div>
  );
}

export default function NotificationToasts() {
  const { toasts, dismiss } = useNotifications();

  if (!toasts || toasts.length === 0) return null;

  return (
    <div className="fixed bottom-5 right-5 z-[9999] flex flex-col-reverse gap-3 items-end">
      {toasts.map((toast) => (
        <ToastCard key={toast.id} toast={toast} onDismiss={dismiss} />
      ))}
    </div>
  );
}
