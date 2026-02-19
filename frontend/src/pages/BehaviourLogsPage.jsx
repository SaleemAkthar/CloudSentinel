import BehaviourLogs from "../components/BehaviourLogs";

export default function BehaviourLogsPage() {
  return (
    <div className="p-6 space-y-6">

      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold">
          Behaviour Logs
        </h1>
        <p className="text-gray-400">
          Comprehensive audit trail of all system activities
        </p>
      </div>

      {/* Main Component */}
      <BehaviourLogs />

    </div>
  );
}

