import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend,
} from "recharts";

// ── Mock invocation data for the last 24 hours ──────────────────────────
// Simulates hourly invocation counts (actual) alongside SARIMA predictions.
// In production, fetch from: GET /api/lambda/invocations?range=24h
const generateInvocationData = () => {
  const data = [];
  const now = new Date();

  for (let i = 23; i >= 0; i--) {
    const hour = new Date(now.getTime() - i * 60 * 60 * 1000);
    const h = hour.getHours();
    const label = `${h.toString().padStart(2, "0")}:00`;

    // Simulate a realistic daily traffic curve (peak during business hours)
    const baseLine =
      h >= 9 && h <= 17
        ? 1400 + Math.sin(((h - 9) / 8) * Math.PI) * 600 // business hours peak
        : 400 + Math.random() * 200; // off-hours baseline

    const actual = Math.round(baseLine + (Math.random() - 0.5) * 300);
    const predicted = Math.round(baseLine); // SARIMA predicted (smooth curve)

    data.push({
      time: label,
      actual,
      predicted,
    });
  }
  return data;
};

const invocationData = generateInvocationData();

// ── Custom tooltip ──────────────────────────────────────────────────────
const InvocationTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-[#0a1628] border border-gray-700 rounded-lg px-4 py-3 shadow-lg">
      <p className="text-gray-400 text-xs mb-1">{label}</p>
      {payload.map((entry, idx) => (
        <p key={idx} className="text-sm" style={{ color: entry.color }}>
          {entry.name}: <span className="font-semibold">{entry.value.toLocaleString()}</span>
        </p>
      ))}
    </div>
  );
};


export default function AWSLambdaMonitorPage() {

  // Mock data for Lambda functions
  const functions = [
    {
      name: "ProcessImage",
      status: "active",
      invocations: 12000,
      duration: "450ms",
      error: "0.5%",
      memory: "256MB",
      cpu: "35%",
    },
    {
      name: "SendNotification",
      status: "warning",
      invocations: 8000,
      duration: "600ms",
      error: "2.1%",
      memory: "128MB",
      cpu: "50%",
    },
    {
      name: "DataIngest",
      status: "error",
      invocations: 500,
      duration: "1.2s",
      error: "12%",
      memory: "512MB",
      cpu: "80%",
    },
    {
      name: "UserAuth",
      status: "active",
      invocations: 9000,
      duration: "300ms",
      error: "0.2%",
      memory: "128MB",
      cpu: "25%",
    },
    {
      name: "Cleanup",
      status: "active",
      invocations: 1984,
      duration: "700ms",
      error: "0.0%",
      memory: "64MB",
      cpu: "10%",
    },
    {
      name: "ArchiveLogs",
      status: "active",
      invocations: 1000,
      duration: "900ms",
      error: "0.1%",
      memory: "256MB",
      cpu: "20%",
    },
  ];

  const statusBorder = (status) => {
    if (status === "active") return "border-green-500 bg-green-500/10";
    if (status === "warning") return "border-yellow-500 bg-yellow-500/10";
    if (status === "error") return "border-red-500 bg-red-500/10";
    return "border-blue-500";
  };

  const statusBadge = (status) => {
    if (status === "active") return "bg-green-500/20 text-green-400";
    if (status === "warning") return "bg-yellow-500/20 text-yellow-400";
    if (status === "error") return "bg-red-500/20 text-red-400";
    return "bg-blue-500/20 text-blue-400";
  };

  return (
    <div className="p-6 space-y-6">

      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold">
          AWS Lambda Monitor
        </h1>
        <p className="text-gray-400">
          Real-time monitoring of serverless functions
        </p>
      </div>

      {/* Main Component */}
      <div className="space-y-6">

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4">

          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Total Invocations</p>
            <h2 className="text-3xl font-bold">38,484</h2>
            <p className="text-green-400 text-sm">+12.5%</p>
          </div>

          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Avg Response Time</p>
            <h2 className="text-3xl font-bold">487ms</h2>
            <p className="text-green-400 text-sm">-8.2%</p>
          </div>

          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Error Rate</p>
            <h2 className="text-3xl font-bold">1.2%</h2>
            <p className="text-red-400 text-sm">+0.3%</p>
          </div>

          <div className="bg-[#0f1b3d] p-5 rounded-xl">
            <p className="text-gray-400 text-sm">Active Functions</p>
            <h2 className="text-3xl font-bold">5/6</h2>
            <p className="text-yellow-400 text-sm">1 error</p>
          </div>

        </div>

        {/* Charts */}
        <div className="grid grid-cols-2 gap-6">

          {/* ── Invocations — Last 24 Hours (SARIMA) ────────────── */}
          <div className="bg-[#0f1b3d] rounded-xl p-5 h-64">
            <h3 className="text-sm text-gray-400 mb-3">Invocations — Last 24 Hours</h3>
            <ResponsiveContainer width="100%" height="85%">
              <AreaChart data={invocationData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradActual" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gradPredicted" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={{ stroke: "#1e2d4a" }}
                  tickLine={false}
                  interval={3}
                />
                <YAxis
                  tick={{ fill: "#6b7280", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={45}
                />
                <Tooltip content={<InvocationTooltip />} />
                <Legend
                  verticalAlign="top"
                  align="right"
                  iconType="circle"
                  iconSize={8}
                  wrapperStyle={{ fontSize: 11, color: "#9ca3af" }}
                />
                <Area
                  type="monotone"
                  dataKey="predicted"
                  name="SARIMA Predicted"
                  stroke="#22c55e"
                  strokeWidth={2}
                  strokeDasharray="5 3"
                  fill="url(#gradPredicted)"
                  dot={false}
                />
                <Area
                  type="monotone"
                  dataKey="actual"
                  name="Actual"
                  stroke="#3b82f6"
                  strokeWidth={2}
                  fill="url(#gradActual)"
                  dot={false}
                  activeDot={{ r: 4, fill: "#3b82f6", stroke: "#0f1b3d", strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Avg Duration by Function — placeholder kept */}
          <div className="bg-[#0f1b3d] rounded-xl p-5 h-64 flex items-center justify-center text-gray-400">
            Avg Duration by Function
          </div>

        </div>

        {/* Function Details */}
        <div className="space-y-4">
          <h2 className="text-xl font-semibold">Function Details</h2>

          {functions.map((fn) => (
            <div
              key={fn.name}
              className={`border rounded-xl p-5 flex justify-between items-center ${statusBorder(
                fn.status
              )}`}
            >
              <div className="space-y-2">

                <div className="flex items-center gap-3">
                  <h3 className="font-semibold">{fn.name}</h3>

                  <span
                    className={`text-xs px-2 py-1 rounded-full ${statusBadge(
                      fn.status
                    )}`}
                  >
                    {fn.status}
                  </span>
                </div>

                <div className="grid grid-cols-5 gap-6 text-sm text-gray-300">
                  <div>
                    <p className="text-gray-400">Invocations</p>
                    <p>{fn.invocations}</p>
                  </div>

                  <div>
                    <p className="text-gray-400">Avg Duration</p>
                    <p>{fn.duration}</p>
                  </div>

                  <div>
                    <p className="text-gray-400">Error Rate</p>
                    <p>{fn.error}</p>
                  </div>

                  <div>
                    <p className="text-gray-400">Memory</p>
                    <p>{fn.memory}</p>
                  </div>

                  <div>
                    <p className="text-gray-400">CPU Usage</p>
                    <p>{fn.cpu}</p>
                  </div>
                </div>
              </div>

              <button className="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm">
                View Details
              </button>
            </div>
          ))}
        </div>

      </div>
    </div>
  );
}
