import { createBrowserRouter, Navigate } from "react-router-dom";
import AppShell from "./components/Appshell";
import Dashboard from "./pages/Dashboard";
import Profile from "./pages/Profile";
import Notifications from "./pages/Notifications";
import RealTimeAlerts from "./pages/RealTimeAlerts";
import AIInsights from "./pages/AIInsights";
import BehaviourLogs from "./components/BehaviourLogs";
import AWSLambdaMonitorPage from "./pages/AWSLambdaMonitorPage";
import Settings from "./pages/Settings";
import SignIn from "./pages/Signin";
import SignUp from "./pages/Signup";
import ProtectedRoute from "./components/ProtectedRoute";

const Placeholder = ({ title }) => (
  <div className="text-slate-200">
    <h2 className="text-2xl font-semibold">{title}</h2>
    <p className="mt-2 text-lime-600">Page coming soon…</p>
  </div>
);

export const router = createBrowserRouter([
  // ── Auth pages — full screen, no sidebar ─────────────────────────────────
  { path: "/signup",  element: <SignUp /> },
  { path: "/signin",  element: <SignIn /> },

  // ── App shell — sidebar + dashboard ──────────────────────────────────────
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <Navigate to="/dashboard" replace /> },
      { path: "dashboard", element: <Dashboard /> },
      { path: "alerts", element: <RealTimeAlerts /> },
      { path: "logs", element: <BehaviourLogs /> },
      { path: "lambda", element: <AWSLambdaMonitorPage /> },
      { path: "insights", element: <AIInsights /> },
      { path: "settings", element: <Settings /> },
      { path: "profile", element: <Profile /> },
      { path: "notifications", element: <Notifications /> },
    ],
  },

  // Fallback: anything unknown → sign in
  { path: "*", element: <Navigate to="/signin" replace /> }, 
  
]);
