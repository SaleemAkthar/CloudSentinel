import React, { createContext, useContext, useState, useEffect } from "react";
import { getMe, authLogin, authRegister, authLogout } from "../services/api";

const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  
  // loading defaults to true so we don't flash the login screen
  // while checking if the httpOnly cookie is valid on first load
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkSession();
  }, []);

  const checkSession = async () => {
    try {
      const data = await getMe();
      setUser(data);
    } catch (err) {
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = async (email, password) => {
    const data = await authLogin(email, password);
    setUser(data);
    return data;
  };

  const register = async (username, email, password) => {
    const data = await authRegister(username, email, password);
    setUser(data);
    return data;
  };

  const logout = async () => {
    try {
      await authLogout();
    } finally {
      setUser(null);
    }
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
