import { useEffect, useState } from "react";
import TeamStatCard from "../components/TeamStatCard";
import TeamMemberCard from "../components/TeamMemberCard";

export default function Team() {
  const [members, setMembers] = useState([]);

  useEffect(() => {
    setMembers([
      {
        id: 1,
        initials: "SA",
        name: "Saleem Akthar",
        role: "Backend Manager",
        email: "saleem@cloudsentinel.com",
        phone: "+94 77 123 4567",
        location: "Colombo, Sri Lanka",
        specialty: "Backend Manager",
        tasks: 56,
        joined: "Nov 2023",
      },
      {
        id: 2,
        initials: "KB",
        name: "Kithmini Bandusena",
        role: "Frontend Manager",
        email: "kithmini@cloudsentinel.com",
        phone: "+94 77 234 5678",
        location: "Gampaha, Sri Lanka",
        specialty: "Frontend Manager",
        tasks: 43,
        joined: "Jan 2023",
      },
      {
        id: 3,
        initials: "RK",
        name: "Rushen Kavundu",
        role: "Backend Manager",
        email: "rushen@cloudsentinel.com",
        phone: "+94 77 555 2202",
        location: "Chilaw, Sri Lanka",
        specialty: "Backend Manager",
        tasks: 37,
        joined: "Nov 2023",
      },
      {
        id: 4,
        initials: "OS",
        name: "Okitha Sandiv",
        role: "Frontend Developer",
        email: "okitha@cloudsentinel.com",
        phone: "+94 77 678 9012",
        location: "Colombo, Sri Lanka",
        specialty: "Frontend Developer",
        tasks: 47,
        joined: "Nov 2023",
      },
    ]);
  }, []);

  return (
    <div className="space-y-8 text-white">

      {/* HEADER */}
      <div>
        <h1 className="text-3xl font-bold">
          Team Management
        </h1>
        <p className="text-slate-400 mt-1">
          Cloud Sentinel Development Team
        </p>
      </div>

      {/* STATS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <TeamStatCard title="Total Members" value={members.length} />
        <TeamStatCard title="Online Now" value={members.length} highlight />
        <TeamStatCard title="Tasks Completed" value="332" />
        <TeamStatCard title="Project Phase" value="Beta" />
      </div>

      {/* TEAM GRID */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {members.map(member => (
          <TeamMemberCard key={member.id} member={member} />
        ))}
      </div>

    </div>
  );
}
