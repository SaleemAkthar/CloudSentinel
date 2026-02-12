import { createBrowserRouter } from "react-router-dom";
import AppShell from "./components/Appshell";
import Dashboard from "./pages/Dashboard";
import RealTimeAlerts from "./components/Real-Time-Alerts";


const Placeholder = ({ title }) => (
  <div className="text-slate-200">
    <h2 className="text-2xl font-semibold">{title}</h2>
    <p className="mt-2 text-lime-600">Page coming soon…</p>
  </div>
);

export const router = createBrowserRouter([
  {
    path: "/",
    element: <AppShell />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: "alerts", element: <RealTimeAlerts /> },
      { path: "logs", element: <Placeholder title="Behaviour Logs" /> },
      { path: "lambda", element: <Placeholder title="AWS Lambda Monitor" /> },
      { path: "insights", element: <Placeholder title="AI Insights" /> },
      { path: "team", element: <Placeholder title="Team" /> },
      { path: "settings", element: <Placeholder title="Settings" /> },
    ],
  },
]);
