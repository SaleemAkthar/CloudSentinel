import React, { useState } from "react";
import csLogo from "../assets/CS LOGO.png";

export default function Signup() {
  const [form, setForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [showPass, setShowPass] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [errors, setErrors] = useState({});
  const [submitted, setSubmitted] = useState(false);


  const validate = () => {
  const e = {};
  if (!form.username.trim()) e.username = "Username is required";
  else if (form.username.length < 3) e.username = "At least 3 characters";
  if (!form.email.trim()) e.email = "Email is required";
  else if (!/\S+@\S+\.\S+/.test(form.email)) e.email = "Invalid email address";
  if (!form.password) e.password = "Password is required";
  else if (form.password.length < 8) e.password = "At least 8 characters";
  if (!form.confirmPassword) e.confirmPassword = "Please confirm your password";
  else if (form.password !== form.confirmPassword) e.confirmPassword = "Passwords do not match";
  return e;
  };

  const handleChange = (field) => (e) => {
    setForm((f) => ({ ...f, [field]: e.target.value }));
    if (errors[field]) setErrors((err) => ({ ...err, [field]: undefined }));
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const v = validate();
    if (Object.keys(v).length) { setErrors(v); return; }
    setSubmitted(true);
  };

  const getStrength = (pw) => {
    if (!pw) return 0;
    if (pw.length < 8) return 1;
    if (pw.length >= 12 && /[^a-zA-Z0-9]/.test(pw)) return 4;
    if (pw.length >= 10) return 3;
    return 2;
  };

  const strengthColors = ["", "bg-red-500", "bg-yellow-500", "bg-blue-500", "bg-emerald-500"];
  const strength = getStrength(form.password);

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
            <div className="flex items-center justify-center">
              <img src={csLogo} alt="Cloud Sentinel" className="w-16 h-16 object-contain flex-shrink-0" />
              
            </div>
            <div className="flex items-center justify-center gap-2.5 mb-7">
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

            <p className="text-center text-white/35 text-sm mt-6">
              Already have an account?{" "}
              <a href="/signin" className="text-blue-400 font-medium hover:underline">
                Log in
              </a>
            </p>


          </>
        )}
      </div>
    </div>
  );
}