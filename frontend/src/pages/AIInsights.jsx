import { useEffect, useState } from "react";
import InsightStatCard from "../components/InsightStatCard";
import InsightCard from "../components/InsightCard";

export default function AIInsights() {
  const [insights, setInsights] = useState([]);

  useEffect(() => {
    setInsights([
      {
        id: 1,
        title: "Anomalous Traffic Pattern Detected",
        level: "high",
        description:
          "AI detected unusual spike in API requests from Eastern European IPs. Pattern matches known botnet behavior.",
        confidence: 94.2,
        action: "Auto-blocked 45 IPs",
        time: "5 minutes ago",
      },
      {
        id: 2,
        title: "New Attack Vector Identified",
        level: "high",
        description:
          "Machine learning model identified a novel SQL injection technique not seen before in training data.",
        confidence: 89.7,
        action: "Added to blocklist",
        time: "23 minutes ago",
      },
      {
        id: 3,
        title: "Performance Optimization Opportunity",
        level: "info",
        description:
          "AI suggests consolidating 3 Lambda functions could reduce latency by 35% and costs by 20%.",
        confidence: 91.5,
        action: "Review recommended",
        time: "1 hour ago",
      },
      {
        id: 4,
        title: "Behavioral Pattern Change",
        level: "medium",
        description:
          "User authentication patterns have shifted. Detected 12% increase in failed login attempts during off-hours.",
        confidence: 88.3,
        action: "Monitoring enhanced",
        time: "2 hours ago",
      },
    ]);
  }, []);

  return (
    <div className="space-y-8 text-white">

      {/* HEADER */}
      <div>
        <h1 className="text-3xl font-bold">
          AI Insights
        </h1>
        <p className="text-slate-400 mt-1">
          AI-generated security intelligence and performance insights
        </p>
      </div>

      {/* TOP STATS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <InsightStatCard
          title="Model Accuracy"
          value="98.4%"
          subtext="+2.1% ↑"
          color="green"
        />
        <InsightStatCard
          title="Threats Detected"
          value="1,247"
          subtext="Last 24h"
          color="blue"
        />
        <InsightStatCard
          title="False Positives"
          value="1.6%"
          subtext="-0.4%"
          color="yellow"
        />
        <InsightStatCard
          title="AI Training"
          value="Active"
          subtext="Continuous"
          color="purple"
        />
      </div>

      {/* INSIGHTS LIST */}
      <div className="space-y-4">
        {insights.map(insight => (
          <InsightCard key={insight.id} insight={insight} />
        ))}
      </div>

    </div>
  );
}
