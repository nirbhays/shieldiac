"use client";

export default function RulesPage() {
  const rules = [
    { id: "SHLD-S3-001", desc: "S3 encryption at rest", severity: "HIGH", type: "Terraform", enabled: true },
    { id: "SHLD-EC2-001", desc: "Unrestricted SSH access", severity: "CRITICAL", type: "Terraform", enabled: true },
    { id: "SHLD-K8S-POD-001", desc: "Privileged container", severity: "CRITICAL", type: "Kubernetes", enabled: true },
    { id: "SHLD-DOCKER-001", desc: "No USER instruction", severity: "HIGH", type: "Dockerfile", enabled: true },
    { id: "SHLD-IAM-001", desc: "Wildcard IAM actions", severity: "CRITICAL", type: "Terraform", enabled: true },
  ];

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Security Rules</h1>
          <p className="text-gray-500 mt-1">Manage built-in and custom security rules</p>
        </div>
        <button className="bg-shield-600 text-white px-4 py-2 rounded-lg hover:bg-shield-700">
          + Create Custom Rule
        </button>
      </div>

      <div className="flex gap-4 mb-6">
        {["All", "Terraform", "Kubernetes", "Dockerfile"].map((filter) => (
          <button key={filter} className="px-4 py-2 rounded-lg border text-sm font-medium hover:bg-gray-50">
            {filter}
          </button>
        ))}
      </div>

      <div className="bg-white border rounded-2xl overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule ID</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Enabled</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {rules.map((rule) => (
              <tr key={rule.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 font-mono text-sm">{rule.id}</td>
                <td className="px-6 py-4">{rule.desc}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 rounded-full text-xs font-medium ${severityBadge(rule.severity)}`}>
                    {rule.severity}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-500">{rule.type}</td>
                <td className="px-6 py-4">
                  <div className={`w-10 h-6 rounded-full ${rule.enabled ? "bg-green-500" : "bg-gray-300"} relative`}>
                    <div className={`w-4 h-4 bg-white rounded-full absolute top-1 ${rule.enabled ? "right-1" : "left-1"} transition`} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function severityBadge(sev: string) {
  const map: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700",
    HIGH: "bg-orange-100 text-orange-700",
    MEDIUM: "bg-yellow-100 text-yellow-700",
    LOW: "bg-blue-100 text-blue-700",
    INFO: "bg-gray-100 text-gray-700",
  };
  return map[sev] || "";
}
