import { createBrowserRouter } from "react-router-dom";
import Appshell from "./components/Appshell";
import Dashboard from "./pages/dashboard";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Appshell />,
    children: [
      { index: true, element: <Dashboard /> },
    //   { path: "pathname", element: <filename /> }
    ]
  },
]);
