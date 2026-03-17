import React from "react";
import csLogo from "../assets/CS LOGO.png"; // Your Cloud Sentinel logo

export default function Signup() {
  return (
    <div className="relative min-h-screen flex items-center justify-center bg-gradient-to-br from-[#0d1b2a] via-[#06122b] to-[#0a1328]">
      {/* Background logo */}
      <img
        src={csLogo}
        alt="Cloud Sentinel Logo"
        className="absolute inset-0 m-auto w-60 h-60 object-contain opacity-50 pointer-events-none"
      />

      {/* Sign-up box */}
      <div className="relative z-10 bg-[#0a0e2766]/50 backdrop-blur-md border border-white/20 rounded-3xl shadow-lg w-full max-w-md p-10">
        <h1 className="text-3xl font-bold text-white text-center mb-6">
          Create Your Account
        </h1>

        <form className="space-y-5">
          {/* Username */}
          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-1">
              Username
            </label>
            <input
              type="text"
              placeholder="Enter username"
              className="w-full px-4 py-2 rounded-lg bg-white/10 text-white border border-white/20 focus:outline-none focus:ring-2 focus:ring-sky-400"
            />
          </div>

          {/* Email */}
          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-1">
              Email
            </label>
            <input
              type="email"
              placeholder="Enter email"
              className="w-full px-4 py-2 rounded-lg bg-white/10 text-white border border-white/20 focus:outline-none focus:ring-2 focus:ring-sky-400"
            />
          </div>

          {/* Password */}
          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-1">
              Password
            </label>
            <input
              type="password"
              placeholder="Enter password"
              className="w-full px-4 py-2 rounded-lg bg-white/10 text-white border border-white/20 focus:outline-none focus:ring-2 focus:ring-sky-400"
            />
          </div>

          {/* Confirm Password */}
          <div>
            <label className="block text-sm font-semibold text-slate-200 mb-1">
              Confirm Password
            </label>
            <input
              type="password"
              placeholder="Confirm password"
              className="w-full px-4 py-2 rounded-lg bg-white/10 text-white border border-white/20 focus:outline-none focus:ring-2 focus:ring-sky-400"
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="w-full py-3 rounded-xl bg-sky-500 text-white font-semibold hover:bg-sky-600 transition-colors"
          >
            Sign Up
          </button>
        </form>

        <p className="text-center text-slate-400 text-sm mt-5">
          Already have an account?{" "}
          <a href="/signin" className="text-sky-400 hover:underline">
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
}