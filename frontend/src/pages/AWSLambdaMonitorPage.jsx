import AWSLambdaMonitor from "../components/AWSLambdaMonitor";

export default function AWSLambdaMonitorPage() {
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
      <AWSLambdaMonitor />

    </div>
  );
}
