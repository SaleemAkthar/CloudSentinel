import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import csLogo from "../assets/CS LOGO.png";
import { useAuth } from "../context/AuthContext";

export default function Signin() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [form, setForm] = useState({ email: "", password: "" });
  const [showPass, setShowPass] = useState(false);
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const validate = () => {
    const v = {};
    if (!form.email.trim()) v.email = "Email is required";
    else if (!/\S+@\S+\.\S+/.test(form.email)) v.email = "Enter a valid email";
    if (!form.password) v.password = "Password is required";
    else if (form.password.length < 6) v.password = "Password must be at least 6 characters";
    return v;
  };

  const handleChange = (field) => (e) => {
    setForm((f) => ({ ...f, [field]: e.target.value }));
    if (errors[field]) setErrors((err) => ({ ...err, [field]: undefined }));
    if (errors.server) setErrors((err) => ({ ...err, server: undefined }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const v = validate();
    if (Object.keys(v).length) { setErrors(v); return; }
    
    try {
      setLoading(true);
      await login(form.email, form.password);
      setSubmitted(true);
      setTimeout(() => navigate("/dashboard"), 1000);
    } catch (err) {
      setErrors({ server: err.response?.data?.detail || "Failed to sign in. Check credentials." });
    } finally {
      setLoading(false);
    }
  };

  const EyeIcon = ({ open }) => (
    <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
      {open ? (
        <><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" /><circle cx="12" cy="12" r="3" /></>
      ) : (
        <><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94" /><path d="M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19" /><line x1="1" y1="1" x2="23" y2="23" /></>
      )}
    </svg>
  );

  const inputCls = (field) =>
    `w-full rounded-xl px-4 py-3 text-white text-[0.95rem] placeholder-white/20 outline-none transition-all ${
      errors[field]
        ? "border border-red-500/60 bg-red-500/5 shadow-[0_0_0_3px_rgba(239,68,68,0.1)]"
        : "border border-white/10 bg-white/5 focus:border-blue-500/60 focus:bg-blue-500/5 focus:shadow-[0_0_0_3px_rgba(59,130,246,0.12)]"
    }`;



  return (
    <div className="min-h-screen bg-[#020817] flex items-center justify-center px-4 py-10 relative overflow-hidden">

      {/* Background grid */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px)",
          backgroundSize: "60px 60px",
        }}
      />

      {/* Ambient blobs — mirrored corners vs Signup */}
      <div className="absolute -top-32 -right-20 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(59,130,246,0.18) 0%, transparent 70%)", filter: "blur(80px)" }} />
      <div className="absolute -bottom-20 -left-16 w-[420px] h-[420px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(139,92,246,0.16) 0%, transparent 70%)", filter: "blur(80px)" }} />
      <div className="absolute top-1/3 right-[8%] w-[260px] h-[260px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(59,130,246,0.09) 0%, transparent 70%)", filter: "blur(70px)" }} />

      {/* Card */}
      <div
        className="relative z-10 w-full max-w-[460px] rounded-3xl px-10 py-11"
        style={{
          background: "rgba(255,255,255,0.035)",
          border: "1px solid rgba(255,255,255,0.09)",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          boxShadow: "0 0 0 1px rgba(59,130,246,0.08), 0 32px 64px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.07)",
        }}
      >
        {submitted ? (
          <div className="flex flex-col items-center text-center gap-4 py-4">
            <div
              className="w-16 h-16 rounded-full flex items-center justify-center"
              style={{ background: "linear-gradient(135deg, rgba(59,130,246,0.2), rgba(139,92,246,0.2))", border: "1px solid rgba(59,130,246,0.35)" }}
            >
              <svg width="28" height="28" fill="none" stroke="#60a5fa" strokeWidth="2.5" viewBox="0 0 24 24" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            </div>
            <h3 className="text-white text-2xl font-bold tracking-tight">Welcome back!</h3>
            <p className="text-white/40 text-sm leading-relaxed">
              You've signed in successfully.<br />Redirecting to your dashboard…
            </p>
            <button
              onClick={() => (setSubmitted(false))}
              className="mt-2 px-8 py-3 rounded-xl text-white font-bold text-sm transition-all hover:opacity-90 hover:-translate-y-0.5"
              style={{ background: "linear-gradient(135deg, #3B82F6, #8B5CF6)", boxShadow: "0 4px 24px rgba(59,130,246,0.35)" }}
            >
              Back to Sign In
            </button>
          </div>
        ) : (
          <>
            {/* Brand row */}
            <div className="flex items-center justify-center">
              <img src={csLogo} alt="Cloud Sentinel" className="w-16 h-16 object-contain flex-shrink-0" />
              
            </div>
            <div className="flex items-center justify-center gap-2.5 mb-7">
              <span className="text-white font-bold text-xl tracking-tight">Cloud Sentinel</span>
            </div>

            <h2 className="text-white text-[1.7rem] font-extrabold text-center tracking-tight mb-1">
              Welcome back
            </h2>
            <p className="text-white/40 text-sm text-center font-light mb-8">
              Sign in to your account to continue
            </p>

            <form  onSubmit={handleSubmit} noValidate className="space-y-4">

              {/* Server Error Banner */}
              {errors.server && (
                <div className="bg-red-500/10 border border-red-500/20 text-red-400 text-sm px-4 py-3 rounded-xl flex items-start gap-3">
                  <svg className="w-5 h-5 flex-shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <p>{errors.server}</p>
                </div>
              )}

              {/* Email */}
              <div>
                <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest mb-1.5">
                  Email
                </label>
                <input
                  type="email"
                  placeholder="you@company.com"
                  value={form.email}
                  onChange={handleChange("email")}
                  autoComplete="email"
                  className={inputCls("email")}
                />
                {errors.email && <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.email}</p>}
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest">
                    Password
                  </label>
                  <a href="#" className="text-[0.78rem] text-blue-400 hover:text-blue-300 hover:underline transition-colors">
                    Forgot password?
                  </a>
                </div>
                <div className="relative">
                  <input
                    type={showPass ? "text" : "password"}
                    placeholder="Enter your password"
                    value={form.password}
                    onChange={handleChange("password")}
                    autoComplete="current-password"
                    className={`${inputCls("password")} pr-11`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPass((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/70 transition-colors"
                  >
                    <EyeIcon open={showPass} />
                  </button>
                </div>
                {errors.password && <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.password}</p>}
              </div>

              {/* Remember me
              <div className="flex items-center gap-2.5">
                <input
                  type="checkbox"
                  id="remember"
                  className="w-4 h-4 accent-blue-500 cursor-pointer rounded"
                />
                <label htmlFor="remember" className="text-white/40 text-sm cursor-pointer select-none">
                  Remember me for 30 days
                </label>
              </div> */}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className=" mt-50 pt-50 w-full mt-2 py-3.5 rounded-xl text-white font-bold text-[1rem] tracking-wide transition-all hover:opacity-90 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                style={{
                  background: "linear-gradient(135deg, #3B82F6, #8B5CF6)",
                  boxShadow: "0 4px 24px rgba(59,130,246,0.35)",
                }}
              >
                {loading ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="white" strokeWidth="4" />
                      <path className="opacity-75" fill="white" d="M4 12a8 8 0 018-8v4l3-3-3-3v4a8 8 0 00-8 8h4z" />
                    </svg>
                    Signing in…
                  </>
                ) : (
                  <>Sign In →</>
                )}
              </button>
            </form>

            {/* Divider
            <div className="flex items-center gap-3 my-6">
              <span className="flex-1 h-px bg-white/[0.08]" />
              <p className="text-white/[0.22] text-[0.75rem] whitespace-nowrap">or continue with</p>
              <span className="flex-1 h-px bg-white/[0.08]" />
            </div> */}

            {/* Google OAuth
            <button
              type="button"
              className="w-full py-3 rounded-xl text-white/70 text-sm flex items-center justify-center gap-2.5 transition-all hover:bg-white/[0.07]"
              style={{ border: "1px solid rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.04)" }}
            >
              <svg width="18" height="18" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
                <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
                <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
                <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
              </svg>
              Continue with Google
            </button> */}

            <p className="text-center text-white/35 text-sm mt-6">
              Don't have an account?{" "}
              <a href="/signup" className="text-blue-400 font-medium hover:underline">
                Sign up free
              </a>
            </p>


          </>
        )}
      </div>
    </div>
  );
}