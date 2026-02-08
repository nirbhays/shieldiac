interface Finding {
  id: string;
  ruleId: string;
  severity: string;
  description: string;
  resourceName: string;
  filePath: string;
  lineNumber: number;
  repoName?: string;
}

const severityConfig: Record<string, { badge: string; icon: string }> = {
  CRITICAL: { badge: "bg-red-100 text-red-700", icon: "🔴" },
  HIGH: { badge: "bg-orange-100 text-orange-700", icon: "🟠" },
  MEDIUM: { badge: "bg-yellow-100 text-yellow-700", icon: "🟡" },
  LOW: { badge: "bg-blue-100 text-blue-700", icon: "🔵" },
  INFO: { badge: "bg-gray-100 text-gray-600", icon: "⚪" },
};

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-center py-12 text-gray-400">
        <p className="text-lg">✅ No findings</p>
        <p className="text-sm">Your infrastructure code looks secure!</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {findings.map((finding) => {
        const config = severityConfig[finding.severity] || severityConfig.INFO;
        return (
          <div key={finding.id} className="border rounded-xl p-4 hover:border-shield-300 transition">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${config.badge}`}>
                    {config.icon} {finding.severity}
                  </span>
                  <code className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
                    {finding.ruleId}
                  </code>
                </div>
                <p className="font-medium text-gray-900">{finding.description}</p>
                <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                  <span className="font-mono">{finding.filePath}:{finding.lineNumber}</span>
                  <span>Resource: {finding.resourceName}</span>
                  {finding.repoName && <span className="text-shield-600">{finding.repoName}</span>}
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
