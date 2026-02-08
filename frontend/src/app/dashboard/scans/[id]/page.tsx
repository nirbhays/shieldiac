"use client";

import { FindingsList } from "@/components/FindingsList";

export default function ScanDetailPage({ params }: { params: { id: string } }) {
  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <span className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-sm font-medium">
            Completed
          </span>
          <span className="text-gray-500">Scan #{params.id}</span>
        </div>
        <h1 className="text-3xl font-bold">Scan Results</h1>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-8">
        {[
          { label: "Files Scanned", value: "42" },
          { label: "Duration", value: "3.2s" },
          { label: "Score", value: "72/100" },
          { label: "Critical", value: "2", color: "text-red-500" },
          { label: "High", value: "8", color: "text-orange-500" },
          { label: "Medium", value: "15", color: "text-yellow-500" },
        ].map((stat) => (
          <div key={stat.label} className="bg-white border rounded-xl p-4 text-center">
            <div className={`text-2xl font-bold ${stat.color || ""}`}>{stat.value}</div>
            <div className="text-xs text-gray-500">{stat.label}</div>
          </div>
        ))}
      </div>

      <div className="bg-white border rounded-2xl p-6">
        <h2 className="text-lg font-semibold mb-4">All Findings</h2>
        <FindingsList findings={[
          { id: "1", ruleId: "SHLD-EC2-001", severity: "CRITICAL", description: "Security group allows unrestricted SSH access", resourceName: "aws_security_group.web_sg", filePath: "infra/main.tf", lineNumber: 42, repoName: "backend-api" },
          { id: "2", ruleId: "SHLD-S3-001", severity: "HIGH", description: "S3 bucket not encrypted", resourceName: "aws_s3_bucket.uploads", filePath: "storage/buckets.tf", lineNumber: 15, repoName: "backend-api" },
          { id: "3", ruleId: "SHLD-K8S-POD-002", severity: "HIGH", description: "Container runs as root", resourceName: "deployment/api", filePath: "k8s/deployment.yaml", lineNumber: 28, repoName: "backend-api" },
          { id: "4", ruleId: "SHLD-DOCKER-003", severity: "MEDIUM", description: "Unpinned base image", resourceName: "Dockerfile", filePath: "Dockerfile", lineNumber: 1, repoName: "backend-api" },
        ]} />
      </div>
    </div>
  );
}
