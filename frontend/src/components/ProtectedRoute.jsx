import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  // Still checking session — show a blank screen rather than flashing /signin
  if (loading) {
    return (
      <div className="min-h-screen bg-[#020817] flex items-center justify-center">
        <svg className="w-8 h-8 animate-spin text-blue-500" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a8 8 0 00-8 8h4z" />
        </svg>
      </div>
    );
  }

  // No valid session — send to signin
  if (!user) {
    return <Navigate to="/signin" replace />;
  }

  return children;
}
