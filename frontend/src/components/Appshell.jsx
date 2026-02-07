import { NavLink, Outlet } from "react-router-dom";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import DashboardOutlinedIcon from "@mui/icons-material/DashboardOutlined";
import WarningAmberOutlinedIcon from "@mui/icons-material/WarningAmberOutlined";

function NavItem({ to, icon, label }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-medium ${
          isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-100"
        }`
      }
    >
      {icon}
      {label}
    </NavLink>
  );
}

export default function Appshell() {
  return (
    <div >
      <header >
        <div >
          <div >
            <div >
              <ShieldOutlinedIcon />
            </div>
            <div>
              <div >Cloud Sentinel</div>
              <div >Runtime Security Dashboard</div>
            </div>
          </div>

          <div >
            MVP UI · React + MUI + Tailwind
          </div>
        </div>
      </header>

      <div >
        <aside>
          <div >
            <div >Navigation</div>
            <div >
              <NavItem to="/" icon={<DashboardOutlinedIcon fontSize="small" />} label="Dashboard" />
              <NavItem to="/alerts" icon={<WarningAmberOutlinedIcon fontSize="small" />} label="Alerts" />
            </div>
          </div>

          <div >
            <div >What this shows</div>
            <p >
              Alerts detected from runtime behaviour. Replace mock data with backend API later.
            </p>
          </div>
        </aside>

        <main >
          <Outlet />
        </main>
      </div>
    </div>
  );
}
