export default function InsightCard({ insight }) {
  const tagColors = {
    high: "border-red-500 text-red-400",
    medium: "border-yellow-400 text-yellow-300",
    low: "border-blue-400 text-blue-300",
    info: "border-purple-400 text-purple-300",
  };

  return (
    <div className="rounded-xl bg-white/5 border border-white/10 p-5">
      <div className="flex justify-between items-start">
        <div>
          {/* Title */}
          <div className="flex items-center gap-3">
            <h3 className="text-white font-semibold">
              {insight.title}
            </h3>

            <span
              className={`text-xs px-2 py-1 rounded-full border ${tagColors[insight.level]}`}
            >
              {insight.level}
            </span>
          </div>

          {/* Description */}
          <p className="text-sm text-slate-400 mt-2">
            {insight.description}
          </p>

          {/* Confidence */}
          <div className="mt-3">
            <div className="text-xs text-slate-400 mb-1">
              Confidence: {insight.confidence}%
            </div>

            <div className="w-full h-2 bg-slate-700 rounded-full">
              <div
                className="h-2 bg-blue-500 rounded-full"
                style={{ width: `${insight.confidence}%` }}
              ></div>
            </div>
          </div>

          {/* Action + Time */}
          <div className="text-xs text-slate-500 mt-3">
            Action: {insight.action} • {insight.time}
          </div>
        </div>

        {/* Button */}
        <button className="px-4 py-2 text-sm rounded-lg bg-blue-600/20 border border-blue-500 text-blue-300 hover:bg-blue-600/30">
          View Details
        </button>
      </div>
    </div>
  );
}
