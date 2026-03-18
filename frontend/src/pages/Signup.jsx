import React, { useState } from "react";

export default function Signup() {
  const [form, setForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [showPass, setShowPass] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [errors, setErrors] = useState({});
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

      {/* Ambient blobs */}
      <div className="absolute -top-32 -left-24 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(59,130,246,0.18) 0%, transparent 70%)", filter: "blur(80px)" }} />
      <div className="absolute -bottom-20 -right-16 w-[420px] h-[420px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(circle, rgba(139,92,246,0.16) 0%, transparent 70%)", filter: "blur(80px)" }} />
      <div className="absolute bottom-1/3 left-[5%] w-[280px] h-[280px] rounded-full pointer-events-none"
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
            <h3 className="text-white text-2xl font-bold tracking-tight">Account Created!</h3>
            <p className="text-white/40 text-sm leading-relaxed">
              Welcome to Cloud Sentinel.<br />Check your email to verify your account.
            </p>
            <button
              onClick={() => setSubmitted(false)}
              className="mt-2 px-8 py-3 rounded-xl text-white font-bold text-sm transition-all hover:opacity-90 hover:-translate-y-0.5"
              style={{ background: "linear-gradient(135deg, #3B82F6, #8B5CF6)", boxShadow: "0 4px 24px rgba(59,130,246,0.35)" }}
            >
              Back to Sign Up
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
              Create your account
            </h2>
            <p className="text-white/40 text-sm text-center font-light mb-8">
              Start securing your Lambda functions today
            </p>

            <form onSubmit={handleSubmit} noValidate className="space-y-4">

              {/* Username */}
              <div>
                <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  placeholder="your_username"
                  value={form.username}
                  onChange={handleChange("username")}
                  autoComplete="username"
                  className={inputCls("username")}
                />
                {errors.username && <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.username}</p>}
              </div>

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
                <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPass ? "text" : "password"}
                    placeholder="Min. 8 characters"
                    value={form.password}
                    onChange={handleChange("password")}
                    autoComplete="new-password"
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
                {form.password.length > 0 && (
                  <div className="flex gap-1 mt-2">
                    {[1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className={`flex-1 h-[3px] rounded-full transition-all duration-300 ${
                          i <= strength ? strengthColors[strength] : "bg-white/10"
                        }`}
                      />
                    ))}
                  </div>
                )}
                {errors.password && <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.password}</p>}
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-[0.72rem] font-medium text-white/50 uppercase tracking-widest mb-1.5">
                  Confirm Password
                </label>
                <div className="relative">
                  <input
                    type={showConfirm ? "text" : "password"}
                    placeholder="Repeat your password"
                    value={form.confirmPassword}
                    onChange={handleChange("confirmPassword")}
                    autoComplete="new-password"
                    className={`${inputCls("confirmPassword")} pr-11`}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirm((v) => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-white/30 hover:text-white/70 transition-colors"
                  >
                    <EyeIcon open={showConfirm} />
                  </button>
                </div>
                {errors.confirmPassword && (
                  <p className="text-red-400 text-[0.75rem] mt-1.5">⚠ {errors.confirmPassword}</p>
                )}
              </div>

              {/* Submit */}
              <button
                type="submit"
                className="w-full mt-2 py-3.5 rounded-xl text-white font-bold text-[1rem] tracking-wide transition-all hover:opacity-90 hover:-translate-y-0.5 active:translate-y-0"
                style={{
                  background: "linear-gradient(135deg, #3B82F6, #8B5CF6)",
                  boxShadow: "0 4px 24px rgba(59,130,246,0.35)",
                }}
              >
                Create Account →
              </button>
            </form>


          </>
        )}
      </div>
    </div>
  );
}