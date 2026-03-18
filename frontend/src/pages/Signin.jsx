import React, { useState } from "react";

export default function Signin() {
  const [form, setForm] = useState({ email: "", password: "" });
  const [showPass, setShowPass] = useState(false);
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);



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
        className="relative z-10 w-full max-w-[420px] rounded-3xl px-10 py-11"
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
              onClick={() => (false)}
              className="mt-2 px-8 py-3 rounded-xl text-white font-bold text-sm transition-all hover:opacity-90 hover:-translate-y-0.5"
              style={{ background: "linear-gradient(135deg, #3B82F6, #8B5CF6)", boxShadow: "0 4px 24px rgba(59,130,246,0.35)" }}
            >
              Back to Sign In
            </button>
          </div>
        ) : (
          <>
            {/* Brand row */}
            <div className="flex items-center justify-center gap-2.5 mb-7">
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ background: "linear-gradient(135deg, #3B82F6, #8B5CF6)" }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>
              <span className="text-white font-bold text-xl tracking-tight">Cloud Sentinel</span>
            </div>

            <h2 className="text-white text-[1.7rem] font-extrabold text-center tracking-tight mb-1">
              Welcome back
            </h2>
            <p className="text-white/40 text-sm text-center font-light mb-8">
              Sign in to your account to continue
            </p>

            <form  className="space-y-4">

              {/* Email */}
              <div>
                <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest mb-1.5">
                  Email
                </label>
                <input
                  type="email"
                  placeholder="you@company.com"
                  value={form.email}
                  onChange={("email")}
                  autoComplete="email"
                  className={("email")}
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
                    onChange={("password")}
                    autoComplete="current-password"
                    className={`${("password")} pr-11`}
                  />
                  <button
                    type="button"
                    onClick={() => ((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/70 transition-colors"
                  >
                    
                  </button>
                </div>
                {errors.password && <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.password}</p>}
              </div>

              {/* Remember me */}
              <div className="flex items-center gap-2.5">
                <input
                  type="checkbox"
                  id="remember"
                  className="w-4 h-4 accent-blue-500 cursor-pointer rounded"
                />
                <label htmlFor="remember" className="text-white/40 text-sm cursor-pointer select-none">
                  Remember me for 30 days
                </label>
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full mt-2 py-3.5 rounded-xl text-white font-bold text-[1rem] tracking-wide transition-all hover:opacity-90 hover:-translate-y-0.5 active:translate-y-0 disabled:opacity-70 disabled:cursor-not-allowed flex items-center justify-center gap-2"
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


          </>
        )}
      </div>
    </div>
  );
}