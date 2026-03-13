import { useState } from "react";
import GlassCard from "../components/GlassCard";
import StatusDot from "../components/StatusDot";
import AlertItem from "../components/AlertItem";
import mockAlerts from "../test/alerts.json";
import { Tab, Tabs, TabList, TabPanel } from "react-tabs";
import "react-tabs/style/react-tabs.css";

/**
 * Investigation modal popup for a single alert
 * Tabs: Metadata / Telemetry
 * Pin + Block buttons
 * Floating modal over dashboard
 */
export default function Investigation({ alertId, onClose }) {
  const alert = mockAlerts.find((a) => a.id === alertId);
  const [pinned, setPinned] = useState(false);

  if (!alert) return null;

  const runtime = alert.features || {};
  const timeString = new Date(alert.timestamp).toLocaleString();

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur">
      <div className="bg-[#0a1328] rounded-2xl w-[90%] max-w-4xl h-[80%] flex flex-col shadow-xl border border-white/10 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/10 sticky top-0 bg-[#0a1328]/95 z-10">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-white truncate">
              {alert.function} — {alert.severity} Alert
            </h2>
            <span className="text-xs text-slate-300">ID: {alert.id}</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPinned((prev) => !prev)}
              className={`px-3 py-1 text-xs rounded-lg ${
                pinned
                  ? "bg-yellow-400 text-black"
                  : "bg-white/5 text-yellow-400"
              }`}
            >
              {pinned ? "Pinned" : "Pin"}
            </button>
            <button
              onClick={onClose}
              className="px-3 py-1 text-xs rounded-lg bg-red-600/20 border border-red-500 text-red-400 hover:bg-red-600/30"
            >
              Close
            </button>
          </div>
        </div>

        {/* Tabs */}
        <Tabs className="flex-1 flex flex-col">
          <TabList className="flex border-b border-white/10 bg-[#071A3A] sticky top-[48px] z-10">
            <Tab className="px-4 py-2 text-sm cursor-pointer text-slate-300 selected:text-white">
              Metadata
            </Tab>
            <Tab className="px-4 py-2 text-sm cursor-pointer text-slate-300 selected:text-white">
              Telemetry
            </Tab>
          </TabList>

          {/* Tab content */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {/* Metadata */}
            <TabPanel>
              <GlassCard title="Alert Metadata">
                <div className="space-y-2 text-sm text-slate-300">
                  <div>
                    <span className="font-semibold text-white">Alert ID:</span>{" "}
                    {alert.id}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Function:</span>{" "}
                    {alert.function}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Severity:</span>{" "}
                    {alert.severity}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Status:</span>{" "}
                    {alert.status}
                  </div>
                  <div>
                    <span className="font-semibold text-white">
                      Anomaly Score:
                    </span>{" "}
                    {(alert.anomaly_score * 100).toFixed(1)}%
                  </div>
                  <div>
                    <span className="font-semibold text-white">Timestamp:</span>{" "}
                    {timeString}
                  </div>
                </div>
              </GlassCard>
            </TabPanel>

            {/* Telemetry */}
            <TabPanel>
              <GlassCard title="Runtime Data">
                <div className="space-y-2 text-sm text-slate-300">
                  <div>
                    <span className="font-semibold text-white">Duration:</span>{" "}
                    {runtime.duration_ms || 0} ms
                  </div>
                  <div>
                    <span className="font-semibold text-white">Outbound Calls:</span>{" "}
                    {runtime.outbound_calls || 0}
                  </div>
                  <div>
                    <span className="font-semibold text-white">
                      Unique Destinations:
                    </span>{" "}
                    {runtime.unique_destinations || 0}
                  </div>
                  <div>
                    <span className="font-semibold text-white">Errors:</span>{" "}
                    {runtime.error_count || 0}
                  </div>
                  <div>
                    <span className="font-semibold text-white">CPU:</span> Placeholder
                  </div>
                  <div>
                    <span className="font-semibold text-white">Memory:</span> Placeholder
                  </div>
                </div>
              </GlassCard>

              <GlassCard title="Network Data">
                <div className="space-y-2 text-sm text-slate-300">
                  <div>
                    <span className="font-semibold text-white">IP Addresses:</span>{" "}
                    Placeholder
                  </div>
                  <div>
                    <span className="font-semibold text-white">Request Headers:</span>{" "}
                    Placeholder
                  </div>
                  <div>
                    <span className="font-semibold text-white">Payload:</span>{" "}
                    Placeholder
                  </div>
                  <div>
                    <span className="font-semibold text-white">Packet Info:</span>{" "}
                    Placeholder
                  </div>
                </div>
              </GlassCard>
            </TabPanel>
          </div>
        </Tabs>

        {/* Block button */}
        <div className="absolute bottom-5 right-5">
          <button className="px-4 py-2 rounded-lg bg-red-600/20 border border-red-500 text-red-400 hover:bg-red-600/30">
            Block
          </button>
        </div>
      </div>
    </div>
  );
}