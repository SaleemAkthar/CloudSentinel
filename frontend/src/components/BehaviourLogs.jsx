export default function BehaviourLogs() {
  const logs = [
    {
      time: "2024-11-23 14:32:15",
      func: "user-auth-lambda",
      event: "Authentication Success",
      user: "admin@cloudsentinel.com",
      ip: "192.168.1.45",
      status: "success",
      duration: "245ms",
    },
    {
      time: "2024-11-23 14:31:58",
      func: "data-processor",
      event: "Data Processing Complete",
      user: "system",
      ip: "10.0.0.12",
      status: "success",
      duration: "1.2s",
    },
    {
      time: "2024-11-23 14:31:42",
      func: "threat-detector",
      event: "Threat Detected — SQL Injection",
      user: "unknown",
      ip: "192.168.1.45",
      status: "blocked",
      duration: "89ms",
    },
    {
      time: "2024-11-23 14:31:30",
      func: "file-validator",
      event: "File Upload Validation Failed",
      user: "user@example.com",
      ip: "172.16.0.89",
      status: "failed",
      duration: "156ms",
    },
    {
      time: "2024-11-23 14:31:15",
      func: "api-gateway",
      event: "Rate Limit Exceeded",
      user: "api-client-5",
      ip: "192.168.2.101",
      status: "throttled",
      duration: "12ms",
    },
    {
      time: "2024-11-23 14:30:58",
      func: "user-auth-lambda",
      event: "Failed Login Attempt",
      user: "unknown",
      ip: "10.0.45.23",
      status: "failed",
      duration: "342ms",
    },
    {
      time: "2024-11-23 14:30:45",
      func: "data-sync",
      event: "Database Sync Complete",
      user: "system",
      ip: "10.0.0.8",
      status: "success",
      duration: "2.4s",
    },
    {
      time: "2024-11-23 14:30:32",
      func: "alert-handler",
      event: "Alert Notification Sent",
      user: "system",
      ip: "10.0.0.15",
      status: "success",
      duration: "567ms",
    },
  ];

  const statusStyle = (status) => {
    switch (status) {
      case "success":
        return "bg-green-500/20 text-green-400";
      case "failed":
        return "bg-red-500/20 text-red-400";
      case "blocked":
        return "bg-yellow-500/20 text-yellow-400";
      case "throttled":
        return "bg-orange-500/20 text-orange-400";
      default:
        return "bg-gray-500/20 text-gray-300";
    }
  };

  return (
    <div className="space-y-6">

      {/* Top Stats */}
      <div className="grid grid-cols-4 gap-4">

        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Total Events</p>
          <h2 className="text-3xl font-bold">12,458</h2>
        </div>

        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Success</p>
          <h2 className="text-3xl font-bold text-green-400">11,234</h2>
        </div>

        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Failed</p>
          <h2 className="text-3xl font-bold text-red-400">892</h2>
        </div>

        <div className="bg-[#0f1b3d] p-5 rounded-xl">
          <p className="text-gray-400 text-sm">Blocked</p>
          <h2 className="text-3xl font-bold text-yellow-400">332</h2>
        </div>

      </div>

      {/* Table */}
      <div className="bg-[#0f1b3d] rounded-xl p-5">

        {/* Search + Actions */}
        <div className="flex justify-between mb-4">
          <input
            type="text"
            placeholder="Search logs..."
            className="bg-[#081028] px-3 py-2 rounded-lg text-sm outline-none"
          />

          <div className="space-x-2">
            <button className="bg-[#1e3a8a] px-3 py-2 rounded-lg text-sm">
              Date Range
            </button>
            <button className="bg-[#1e3a8a] px-3 py-2 rounded-lg text-sm">
              Filter
            </button>
            <button className="bg-green-600 px-3 py-2 rounded-lg text-sm">
              Export
            </button>
          </div>
        </div>

        {/* Table */}
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
            {logs.map((log, i) => (
              <tr key={i} className="border-b border-gray-800">
                <td className="py-3">{log.time}</td>
                <td>{log.func}</td>
                <td>{log.event}</td>
                <td>{log.user}</td>
                <td>{log.ip}</td>

                <td>
                  <span
                    className={`px-2 py-1 rounded-full text-xs ${statusStyle(
                      log.status
                    )}`}
                  >
                    {log.status}
                  </span>
                </td>

                <td>{log.duration}</td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="flex justify-between mt-4 text-sm">
          <p className="text-gray-400">Showing 8 of 12,458 entries</p>

          <div className="space-x-2">
            <button className="bg-[#1e3a8a] px-3 py-1 rounded">
              Previous
            </button>
            <button className="bg-[#1e3a8a] px-3 py-1 rounded">
              Next
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
