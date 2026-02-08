"use client";

import { SecurityScoreCard } from "@/components/SecurityScoreCard";
import { FindingsList } from "@/components/FindingsList";
import { TrendChart } from "@/components/TrendChart";
import { ScanTimeline } from "@/components/ScanTimeline";
import { Shield, GitBranch, AlertTriangle, FileSearch } from "lucide-react";

const mockData = {
  score: 78,
  grade: "C" as const,
  totalRepos: 12,
  totalScans: 156,
  totalFindings: 342,
  severityBreakdown: { critical: 5, high: 28, medium: 89, low: 145, info: 75 },
  recentFindings: [
    {
      id: "1",
      ruleId: "SHLD-EC2-001",
      severity: "CRITICAL" as const,
      description: "Security group allows unrestricted SSH access (0.0.0.0/0 on port 22)",
      resourceName: "aws_security_group.web_sg",
      filePath: "infra/main.tf",
      lineNumber: 42,
      repoName: "backend-api",
    },
    {
      id: "2",
      ruleId: "SHLD-S3-001",
      severity: "HIGH" as const,
      description: "S3 bucket does not have server-side encryption enabled",
      resourceName: "aws_s3_bucket.uploads",
      filePath: "storage/buckets.tf",
      lineNumber: 15,
      repoName: "data-platform",
    },
    {
      id: "3",
      ruleId: "SHLD-K8S-POD-002",
      severity: "HIGH" as const,
      description: "Container runs as root (UID 0)",
      resourceName: "deployment/api-server",
      filePath: "k8s/deployment.yaml",
      lineNumber: 28,
      repoName: "backend-api",
    },
    {
      id: "4",
      ruleId: "SHLD-DOCKER-003",
      severity: "MEDIUM" as const,
      description: "Dockerfile uses 'latest' tag for base image",
      resourceName: "Dockerfile",
      filePath: "Dockerfile",
      lineNumber: 1,
      repoName: "frontend-app",
    },
  ],
  trendData: [
    { date: "Jan 1", score: 65 },
    { date: "Jan 8", score: 68 },
    { date: "Jan 15", score: 72 },
    { date: "Jan 22", score: 70 },
    { date: "Jan 29", score: 75 },
    { date: "Feb 5", score: 78 },
  ],
  recentScans: [
    { id: "s1", repo: "backend-api", branch: "main", status: "completed", findings: 12, time: "5 min ago" },
    { id: "s2", repo: "data-platform", branch: "feature/etl", status: "completed", findings: 8, time: "23 min ago" },
    { id: "s3", repo: "frontend-app", branch: "main", status: "completed", findings: 3, time: "1 hour ago" },
    { id: "s4", repo: "infra-modules", branch: "pr/42", status: "in_progress", findings: 0, time: "2 min ago" },
  ],
};

export default function DashboardPage() {
  const { score, grade, severityBreakdown, recentFindings, trendData, recentScans } = mockData;

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Security Dashboard</h1>
        <p className="text-gray-500 mt-1">Overview of your infrastructure security posture</p>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <SecurityScoreCard score={score} grade={grade} />
        <StatCard icon={<GitBranch />} label="Repositories" value={mockData.totalRepos.toString()} />
        <StatCard icon={<FileSearch />} label="Scans This Month" value={mockData.totalScans.toString()} />
        <StatCard icon={<AlertTriangle />} label="Open Findings" value={mockData.totalFindings.toString()} />
      </div>

      {/* Severity Breakdown */}
      <div className="grid grid-cols-5 gap-4 mb-8">
        {(["critical", "high", "medium", "low", "info"] as const).map((sev) => (
          <div key={sev} className="bg-white border rounded-xl p-4 text-center">
            <div className={`text-2xl font-bold ${severityColor(sev)}`}>
              {severityBreakdown[sev]}
            </div>
            <div className="text-sm text-gray-500 capitalize">{sev}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-8">
        {/* Trend Chart */}
        <div className="lg:col-span-2">
          <div className="bg-white border rounded-2xl p-6">
            <h2 className="text-lg font-semibold mb-4">Security Score Trend</h2>
            <TrendChart data={trendData} />
          </div>
        </div>

        {/* Recent Scans */}
        <div>
          <div className="bg-white border rounded-2xl p-6">
            <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
            <ScanTimeline scans={recentScans} />
          </div>
        </div>
      </div>

      {/* Recent Findings */}
      <div className="mt-8">
        <div className="bg-white border rounded-2xl p-6">
          <h2 className="text-lg font-semibold mb-4">Critical & High Findings</h2>
          <FindingsList findings={recentFindings} />
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="bg-white border rounded-2xl p-6 flex items-center gap-4">
      <div className="w-12 h-12 rounded-xl bg-shield-50 text-shield-600 flex items-center justify-center">
        {icon}
      </div>
      <div>
        <div className="text-2xl font-bold">{value}</div>
        <div className="text-sm text-gray-500">{label}</div>
      </div>
    </div>
  );
}

function severityColor(sev: string) {
  const map: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-500",
    info: "text-gray-400",
  };
  return map[sev] || "text-gray-500";
}
