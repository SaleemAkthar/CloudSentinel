import { NavLink, Outlet, useNavigate } from "react-router-dom";
import csLogo from "../assets/CS LOGO.png";
import { useAuth } from "../context/AuthContext";

// MUI Icons
import GridViewRoundedIcon from "@mui/icons-material/GridViewRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import ShowChartRoundedIcon from "@mui/icons-material/ShowChartRounded";
import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";
import GroupOutlinedIcon from "@mui/icons-material/GroupOutlined";
import SettingsOutlinedIcon from "@mui/icons-material/SettingsOutlined";
import NotificationsNoneRoundedIcon from '@mui/icons-material/NotificationsNoneRounded';
import PersonOutlineRoundedIcon from "@mui/icons-material/PersonOutlineRounded";

function SideItem({ to, icon, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        [
          "flex items-center gap-3 rounded-xl px-3 py-2 text-sm",
          "transition-colors",
          isActive
            ? "bg-white/10 text-white ring-1 ring-white/15"
            : "text-slate-300 hover:bg-white/5 hover:text-white",
        ].join(" ")
      }
    >
      <span className="opacity-90">{icon}</span>
      <span className="font-medium">{label}</span>
    </NavLink>
  );
}

export default function AppShell() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  return (
    <div className="h-screen overflow-hidden bg-[#050B1A] text-white">
      <div className="mx-auto flex h-full w-full">
        {/* Sidebar */}
        <aside className="w-[260px] h-full shrink-0 flex flex-col border-r border-white/10 bg-gradient-to-b from-[#071A3A] via-[#06122B] to-[#050B1A]">          {/* Brand */}
          <div className="flex items-center gap-3 px-5 py-5">
            <div className="grid h-11 w-11 place-items-center rounded-2xl ring-1 ring-white/15">
              <img src={csLogo} alt="CS Logo" className="h-7 w-7" />
            </div>
            <div className="leading-tight">
              <div className="text-base font-semibold">Cloud Sentinel</div>
              <div className="text-xs text-slate-300">Security Platform</div>
            </div>
          </div>

          {/* Nav — scrollable main links */}
          <nav className="px-3 pt-2 flex-1 overflow-y-auto">
            <div className="space-y-1">
              <SideItem to="/dashboard" icon={<GridViewRoundedIcon fontSize="small" />} label="Overview" />
              <SideItem to="/alerts" icon={<WarningAmberRoundedIcon fontSize="small" />} label="Real-Time Alerts" />
              <SideItem to="/logs" icon={<DescriptionOutlinedIcon fontSize="small" />} label="Behaviour Logs" />
              <SideItem to="/lambda" icon={<ShowChartRoundedIcon fontSize="small" />} label="AWS Lambda Monitor" />
              <SideItem to="/insights" icon={<AutoAwesomeRoundedIcon fontSize="small" />} label="AI Insights" />
            </div>
          </nav>

          {/* Bottom section — always pinned to the bottom */}
          <div className="px-3 pb-5 pt-4 border-t border-white/10 space-y-1">
            <SideItem to="/settings" icon={<SettingsOutlinedIcon fontSize="small" />} label="Settings" />
            <button
              onClick={async () => {
                await logout();
                navigate("/signin");
              }}
              className="flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm text-slate-300 hover:bg-white/5 hover:text-white transition-colors"
            >
              <GroupOutlinedIcon fontSize="small" className="opacity-90" />
              <span className="font-medium">Sign Out</span>
            </button>

            {/* Status Card */}
            <div className="mt-3 rounded-2xl bg-white/5 p-4 ring-1 ring-white/10">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
                <div className="text-sm font-semibold text-white">System Online</div>
              </div>
              <div className="mt-1 text-xs text-slate-300">All services operational</div>
            </div>
          </div>
        </aside>

        {/* Main */}
        <div className="flex min-w-0 flex-1 flex-col h-full">
          {/* Top bar */}
          <header className="flex h-16 items-center justify-between border-b border-white/10 bg-gradient-to-r from-[#071A3A] via-[#071534] to-[#050B1A] px-6">
            <h1 className="text-xl font-semibold tracking-wide">Cloud Sentinel Dashboard</h1>

            <div className="flex items-center gap-3">
              {/* Top bar btns */}
              <button
                className="relative grid h-10 w-10 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10 hover:bg-white/10"
                title="Notifications"
                onClick={() => navigate("/notifications")}
              >
                <NotificationsNoneRoundedIcon />
                
              </button>

              <button
                className="grid h-10 w-10 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10 hover:bg-white/10"
                title="Settings"
                onClick={() => navigate("/settings")}
              >
                <SettingsOutlinedIcon />
              </button>

              <div className="flex items-center gap-2 pl-2 border-l border-white/10 ml-1">
                <div className="text-right hidden sm:block">
                  <div className="text-sm font-medium leading-none">{user?.username}</div>
                  <div className="text-[0.65rem] text-slate-400 mt-1 leading-none">{user?.email}</div>
                </div>
                <button
                  className="grid h-10 w-10 place-items-center rounded-xl bg-white/5 ring-1 ring-white/10 hover:bg-white/10"
                  title="Profile"
                  onClick={() => navigate("/profile")}
                >
                  <PersonOutlineRoundedIcon />
                </button>
              </div>
            </div>
          </header>

          {/* Page content */}
          <main className="min-w-0 flex-1 overflow-y-auto p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
