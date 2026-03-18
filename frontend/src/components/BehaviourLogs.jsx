import { useEffect, useState, useCallback, useMemo } from "react";
import axios from "axios";


// ── Polling interval ────────────────────────────────────────────────────
const POLL_INTERVAL = 2000;
const PAGE_SIZE = 20;


export default function BehaviourLogs() {
  const [allLogs, setAllLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);

  // ── Fetch logs from backend ─────────────────────────────────────────
  const fetchLogs = useCallback(async () => {
    try {
      const res = await axios.get("/api/logs?limit=5000");
      const data = Array.isArray(res.data) ? res.data : [];
      // Newest first
      data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      setAllLogs(data);
      setError(null);
    } catch (err) {
      console.error("Failed to fetch logs:", err);
      setError("Backend unavailable — please ensure the server is running");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchLogs]);

  // ── Computed stats from real data ───────────────────────────────────
  const stats = useMemo(() => {
    const total = allLogs.length;
    const success = allLogs.filter((l) => l.status === "success").length;
    const failed = allLogs.filter((l) => l.status === "failed" || l.status === "error").length;
    const blocked = allLogs.filter((l) => l.status === "blocked").length;
    return { total, success, failed, blocked };
  }, [allLogs]);

  // ── Filter + search ─────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let result = allLogs;

    // Status filter
    if (statusFilter !== "all") {
      result = result.filter((l) => l.status === statusFilter);
    }

    // Search across all fields
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (l) =>
          (l.timestamp || "").toLowerCase().includes(q) ||
          (l.function || "").toLowerCase().includes(q) ||
          (l.event || "").toLowerCase().includes(q) ||
          (l.user || "").toLowerCase().includes(q) ||
          (l.ip_address || "").toLowerCase().includes(q) ||
          (l.status || "").toLowerCase().includes(q) ||
          (l.duration || "").toLowerCase().includes(q)
      );
    }

    return result;
  }, [allLogs, search, statusFilter]);

  // ── Pagination ──────────────────────────────────────────────────────
  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paginated = filtered.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE
  );

  // Reset to page 1 when filter/search changes
  useEffect(() => {
    setPage(1);
  }, [search, statusFilter]);

  // ── Status badge style ──────────────────────────────────────────────
  const statusStyle = (status) => {
    switch (status) {
      case "success":
        return "bg-green-500/20 text-green-400";
      case "failed":
      case "error":
        return "bg-red-500/20 text-red-400";
      case "blocked":
        return "bg-yellow-500/20 text-yellow-400";
      case "throttled":
        return "bg-orange-500/20 text-orange-400";
      default:
        return "bg-gray-500/20 text-gray-300";
    }
  };

  // ── Format timestamp ────────────────────────────────────────────────
  const formatTs = (ts) => {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString();
    } catch {
      return ts;
    }
  };

  // ── Export as CSV ───────────────────────────────────────────────────
  const handleExport = () => {
    if (filtered.length === 0) return;

    const headers = "Timestamp,Function,Event,User,IP Address,Status,Duration\n";
    const rows = filtered
      .map(
        (l) =>
          `"${l.timestamp || ""}","${l.function || ""}","${l.event || ""}","${l.user || ""}","${l.ip_address || ""}","${l.status || ""}","${l.duration || ""}"`
      )
      .join("\n");

    const blob = new Blob([headers + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `behaviour-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Render ──────────────────────────────────────────────────────────
  return (
    <div className="space-y-6">

      {/* Error banner */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Top Stats — computed from real data */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Total Events</p>
          <h2 className="text-3xl font-bold">{stats.total.toLocaleString()}</h2>
        </div>
        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Success</p>
          <h2 className="text-3xl font-bold text-green-400">{stats.success.toLocaleString()}</h2>
        </div>
        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Failed</p>
          <h2 className="text-3xl font-bold text-red-400">{stats.failed.toLocaleString()}</h2>
        </div>
        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Blocked</p>
          <h2 className="text-3xl font-bold text-yellow-400">{stats.blocked.toLocaleString()}</h2>
        </div>
      </div>

      {/* Table card */}
      <div className="bg-[#0f1b3d] rounded-xl p-5">

        {/* Search + Filter + Export */}
        <div className="flex justify-between mb-4">
          <input
            type="text"
            placeholder="Search logs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="bg-[#081028] px-3 py-2 rounded-lg text-sm outline-none w-64 text-white placeholder-gray-500"
          />

          <div className="flex items-center gap-2">
            {/* Status filter dropdown */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-[#1e3a8a] pl-3 pr-7 py-2 rounded-lg text-sm text-white outline-none cursor-pointer appearance-none bg-[length:12px] bg-[right_8px_center] bg-no-repeat"
              style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='white' stroke-width='1.5' fill='none'/%3E%3C/svg%3E\")" }}
            >
              <option value="all">All Status</option>
              <option value="success">Success</option>
              <option value="failed">Failed</option>
              <option value="blocked">Blocked</option>
              <option value="throttled">Throttled</option>
            </select>

            <button
              onClick={handleExport}
              className="bg-green-600 hover:bg-green-700 px-3 py-2 rounded-lg text-sm transition-colors"
            >
              Export
            </button>
          </div>
        </div>

        {/* Table */}
        {loading ? (
          <div className="py-12 text-center text-slate-400">Loading logs…</div>
        ) : paginated.length === 0 ? (
          <div className="py-12 text-center text-slate-400">
            {allLogs.length === 0
              ? "No logs yet — send packets to /process_log to generate logs"
              : "No logs match your search"}
          </div>
        ) : (
          <table className="w-full text-sm text-left">
            <thead className="text-gray-400 border-b border-gray-700">
              <tr>
                <th className="py-2">Timestamp</th>
                <th>Function</th>
                <th>Event</th>
                <th>User</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Duration</th>
              </tr>
            </thead>
            <tbody>
              {paginated.map((log, i) => (
                <tr key={i} className="border-b border-gray-800 hover:bg-white/5 transition-colors">
                  <td className="py-3 text-slate-300">{formatTs(log.timestamp)}</td>
                  <td className="text-slate-200">{log.function || "—"}</td>
                  <td className="text-slate-300">{log.event || "—"}</td>
                  <td className="text-slate-400">{log.user || "—"}</td>
                  <td className="text-slate-400">{log.ip_address || "—"}</td>
                  <td>
                    <span className={`px-2 py-1 rounded-full text-xs ${statusStyle(log.status)}`}>
                      {log.status || "—"}
                    </span>
                  </td>
                  <td className="text-slate-300">{log.duration || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {filtered.length > 0 && (
          <div className="flex justify-between mt-4 text-sm">
            <p className="text-gray-400">
              Showing {(currentPage - 1) * PAGE_SIZE + 1}–
              {Math.min(currentPage * PAGE_SIZE, filtered.length)} of{" "}
              {filtered.length.toLocaleString()} entries
            </p>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={currentPage <= 1}
                className="bg-[#1e3a8a] px-3 py-1 rounded disabled:opacity-40 hover:bg-[#2548a8] transition-colors"
              >
                Previous
              </button>
              <span className="text-gray-400 text-xs">
                {currentPage} / {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                className="bg-[#1e3a8a] px-3 py-1 rounded disabled:opacity-40 hover:bg-[#2548a8] transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}