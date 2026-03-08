export default function GlassCard({ title, icon, children, className = "" }) {
  return (
    <div
      className={[
        "rounded-2xl p-5",
        "bg-white/5 ring-1 ring-white/10",
        "shadow-[0_10px_30px_rgba(0,0,0,0.25)]",
        "backdrop-blur",
        className,
      ].join(" ")}>
        
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        </div>
        {icon ? <div className="text-sky-300">{icon}</div> : null}
      </div>
      {children}
    </div>
  );
}
