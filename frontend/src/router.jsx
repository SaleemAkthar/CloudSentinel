import { createBrowserRouter } from "react-router-dom";
import AppShell from "./components/Appshell";
import Dashboard from "./pages/Dashboard";
import Profile from "./pages/Profile";
import Notifications from "./pages/Notifications";
import RealTimeAlerts from "./pages/RealTimeAlerts";
import AIInsights from "./pages/AIInsights";
import Team from "./pages/Team";
import BehaviourLogs from "./components/BehaviourLogs";
import AWSLambdaMonitorPage from "./pages/AWSLambdaMonitorPage";


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
      { path: "logs", element: <BehaviourLogs /> },
      { path: "lambda", element: <AWSLambdaMonitorPage /> },
      { path: "insights", element: <AIInsights /> },
      { path: "team", element: <Team /> },
      { path: "settings", element: <Placeholder title="Settings" /> },
      { path: "profile", element: <Profile /> },
    ],
  },
]);
