export default function AWSLambdaMonitor() {
  const functions = [
    {
      name: "user-auth-lambda",
      status: "active",
      invocations: "12,458",
      duration: "245ms",
      error: "0.2%",
      memory: "512MB",
      cpu: "45%",
    },
    {
      name: "threat-detector",
      status: "active",
      invocations: "8,932",
      duration: "189ms",
      error: "0.1%",
      memory: "1024MB",
      cpu: "68%",
    },
    {
      name: "data-processor",
      status: "warning",
      invocations: "6,547",
      duration: "1.2s",
      error: "1.5%",
      memory: "2048MB",
      cpu: "82%",
    },
    {
      name: "file-validator",
      status: "active",
      invocations: "4,521",
      duration: "156ms",
      error: "0.3%",
      memory: "512MB",
      cpu: "35%",
    },
    {
      name: "alert-handler",
      status: "active",
      invocations: "3,892",
      duration: "567ms",
      error: "0.4%",
      memory: "256MB",
      cpu: "28%",
    },
    {
      name: "data-sync",
      status: "error",
      invocations: "2,134",
      duration: "2.4s",
      error: "5.2%",
      memory: "1024MB",
      cpu: "15%",
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

      {/* Chart placeholders */}
      <div className="grid grid-cols-2 gap-6">

        <div className="bg-[#0f1b3d] rounded-xl p-5 h-64 flex items-center justify-center text-gray-400">
          Invocations — Last 24 Hours
        </div>

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
  );
}
