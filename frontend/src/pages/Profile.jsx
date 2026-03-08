// MUI icon imports for UI elements
import { useState } from "react";
import PersonOutlineRoundedIcon from "@mui/icons-material/PersonOutlineRounded";
import NotificationsNoneRoundedIcon from "@mui/icons-material/NotificationsNoneRounded";
import WarningAmberRoundedIcon from "@mui/icons-material/WarningAmberRounded";
import AutoAwesomeRoundedIcon from "@mui/icons-material/AutoAwesomeRounded";
import DescriptionOutlinedIcon from "@mui/icons-material/DescriptionOutlined";
import ShowChartRoundedIcon from "@mui/icons-material/ShowChartRounded";
import GridViewRoundedIcon from "@mui/icons-material/GridViewRounded";

// default user data
const initialUser = {
  name: "Display Name",
  role: "Display Role",
  email: "email@cloudsentinel.io",
  organization: "Cloud Sentinel Security",
  joined: "January 2025",
  avatar: "DN",
  plan: "Team",
  twoFA: true,
  notifications: {
    email: true,
    critical: true,
    weekly: false,
  },
};

// Profile page component
export default function Profile() {
  return (
    <div className="text-white">
      <h1 className="text-3xl font-bold">My Profile</h1>
    </div>
  );
}