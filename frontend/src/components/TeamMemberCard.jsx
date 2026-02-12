export default function TeamMemberCard({ member }) {
  return (
    <div className="rounded-xl bg-white/5 border border-white/10 p-5">
      {/* Avatar + Name */}
      <div className="flex items-center gap-4">
        <div className="w-12 h-12 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold">
          {member.initials}
        </div>

        <div>
          <h3 className="text-white font-semibold">
            {member.name}
          </h3>
          <p className="text-xs text-slate-400">
            {member.role}
          </p>
        </div>
      </div>

      {/* Contact */}
      <div className="mt-4 text-xs text-slate-400 space-y-1">
        <div>{member.email}</div>
        <div>{member.phone}</div>
        <div>{member.location}</div>
      </div>

      {/* Stats */}
      <div className="mt-4 border-t border-white/10 pt-3 text-xs text-slate-400">
        <div className="flex justify-between">
          <span>Specialty:</span>
          <span className="text-white">{member.specialty}</span>
        </div>

        <div className="flex justify-between mt-1">
          <span>Tasks Done:</span>
          <span className="text-white">{member.tasks}</span>
        </div>

        <div className="flex justify-between mt-1">
          <span>Joined:</span>
          <span className="text-white">{member.joined}</span>
        </div>
      </div>

      {/* Button */}
      <button className="w-full mt-4 py-2 rounded-lg bg-blue-600/20 border border-blue-500 text-blue-300 hover:bg-blue-600/30 text-sm">
        View Profile
      </button>
    </div>
  );
}
