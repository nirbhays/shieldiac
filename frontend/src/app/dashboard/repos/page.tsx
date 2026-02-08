"use client";

import Link from "next/link";
import { SecurityScoreCard } from "@/components/SecurityScoreCard";

const repos = [
  { id: "1", name: "backend-api", fullName: "org/backend-api", score: 72, grade: "C" as const, findings: 45, lastScan: "5 min ago" },
  { id: "2", name: "data-platform", fullName: "org/data-platform", score: 85, grade: "B" as const, findings: 18, lastScan: "1 hour ago" },
  { id: "3", name: "frontend-app", fullName: "org/frontend-app", score: 94, grade: "A" as const, findings: 3, lastScan: "30 min ago" },
  { id: "4", name: "infra-modules", fullName: "org/infra-modules", score: 58, grade: "D" as const, findings: 67, lastScan: "2 hours ago" },
  { id: "5", name: "ml-pipeline", fullName: "org/ml-pipeline", score: 91, grade: "A" as const, findings: 7, lastScan: "3 hours ago" },
];

export default function ReposPage() {
  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Repositories</h1>
          <p className="text-gray-500 mt-1">Security scores for all connected repositories</p>
        </div>
        <button className="bg-shield-600 text-white px-4 py-2 rounded-lg hover:bg-shield-700 transition">
          + Connect Repository
        </button>
      </div>

      <div className="grid gap-4">
        {repos.map((repo) => (
          <Link key={repo.id} href={`/dashboard/repos/${repo.id}`}>
            <div className="bg-white border rounded-xl p-6 flex items-center justify-between hover:border-shield-300 hover:shadow-md transition cursor-pointer">
              <div className="flex items-center gap-6">
                <div className={`w-14 h-14 rounded-xl flex items-center justify-center text-2xl font-bold ${gradeStyles(repo.grade)}`}>
                  {repo.grade}
                </div>
                <div>
                  <h3 className="font-semibold text-lg">{repo.fullName}</h3>
                  <p className="text-sm text-gray-500">Last scan: {repo.lastScan}</p>
                </div>
              </div>
              <div className="flex items-center gap-8 text-right">
                <div>
                  <div className="text-2xl font-bold">{repo.score}</div>
                  <div className="text-xs text-gray-500">Score</div>
                </div>
                <div>
                  <div className="text-2xl font-bold">{repo.findings}</div>
                  <div className="text-xs text-gray-500">Findings</div>
                </div>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

function gradeStyles(grade: string) {
  const map: Record<string, string> = {
    A: "bg-green-100 text-green-700",
    B: "bg-blue-100 text-blue-700",
    C: "bg-yellow-100 text-yellow-700",
    D: "bg-orange-100 text-orange-700",
    F: "bg-red-100 text-red-700",
  };
  return map[grade] || "bg-gray-100 text-gray-700";
}
