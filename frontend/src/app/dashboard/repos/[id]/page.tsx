"use client";

import { SecurityScoreCard } from "@/components/SecurityScoreCard";
import { FindingsList } from "@/components/FindingsList";
import { TrendChart } from "@/components/TrendChart";

export default function RepoDetailPage({ params }: { params: { id: string } }) {
  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">org/backend-api</h1>
        <p className="text-gray-500 mt-1">Repository security details</p>
      </div>

      <div className="grid lg:grid-cols-4 gap-6 mb-8">
        <SecurityScoreCard score={72} grade="C" />
        <div className="bg-white border rounded-2xl p-6 text-center">
          <div className="text-3xl font-bold text-red-500">5</div>
          <div className="text-sm text-gray-500">Critical</div>
        </div>
        <div className="bg-white border rounded-2xl p-6 text-center">
          <div className="text-3xl font-bold text-orange-500">12</div>
          <div className="text-sm text-gray-500">High</div>
        </div>
        <div className="bg-white border rounded-2xl p-6 text-center">
          <div className="text-3xl font-bold text-yellow-500">28</div>
          <div className="text-sm text-gray-500">Medium</div>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-8 mb-8">
        <div className="bg-white border rounded-2xl p-6">
          <h2 className="text-lg font-semibold mb-4">Score Trend</h2>
          <TrendChart data={[
            { date: "Week 1", score: 60 },
            { date: "Week 2", score: 65 },
            { date: "Week 3", score: 68 },
            { date: "Week 4", score: 72 },
          ]} />
        </div>
        <div className="bg-white border rounded-2xl p-6">
          <h2 className="text-lg font-semibold mb-4">File Types Scanned</h2>
          <div className="space-y-3">
            {[
              { type: "Terraform (.tf)", count: 24, findings: 32 },
              { type: "Kubernetes (.yaml)", count: 18, findings: 8 },
              { type: "Dockerfile", count: 3, findings: 5 },
            ].map((ft) => (
              <div key={ft.type} className="flex justify-between items-center py-2 border-b">
                <span className="font-medium">{ft.type}</span>
                <span className="text-sm text-gray-500">{ft.count} files • {ft.findings} findings</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-white border rounded-2xl p-6">
        <h2 className="text-lg font-semibold mb-4">All Findings</h2>
        <FindingsList findings={[
          { id: "1", ruleId: "SHLD-EC2-001", severity: "CRITICAL" as const, description: "Security group allows unrestricted SSH", resourceName: "aws_security_group.web", filePath: "main.tf", lineNumber: 42, repoName: "backend-api" },
          { id: "2", ruleId: "SHLD-S3-001", severity: "HIGH" as const, description: "S3 bucket not encrypted", resourceName: "aws_s3_bucket.data", filePath: "storage.tf", lineNumber: 10, repoName: "backend-api" },
        ]} />
      </div>
    </div>
  );
}
