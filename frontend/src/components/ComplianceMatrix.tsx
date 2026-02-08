export function ComplianceMatrix() {
  const controls = [
    { id: "CC6.1", title: "Logical Access Controls", framework: "SOC2", status: "fail", findings: 8 },
    { id: "CC6.3", title: "Role-Based Access", framework: "SOC2", status: "pass", findings: 0 },
    { id: "CC7.1", title: "Monitoring Activities", framework: "SOC2", status: "fail", findings: 3 },
    { id: "164.312(a)(1)", title: "Access Control", framework: "HIPAA", status: "fail", findings: 5 },
    { id: "164.312(a)(2)(iv)", title: "Encryption", framework: "HIPAA", status: "fail", findings: 4 },
    { id: "164.312(e)(1)", title: "Transmission Security", framework: "HIPAA", status: "pass", findings: 0 },
    { id: "1.2.1", title: "Restrict Traffic", framework: "PCI-DSS", status: "fail", findings: 6 },
    { id: "3.4", title: "Render PAN Unreadable", framework: "PCI-DSS", status: "fail", findings: 2 },
    { id: "8.3", title: "Multi-Factor Authentication", framework: "PCI-DSS", status: "pass", findings: 0 },
    { id: "10.1", title: "Audit Trails", framework: "PCI-DSS", status: "pass", findings: 0 },
  ];

  return (
    <div className="bg-white border rounded-2xl overflow-hidden">
      <div className="p-6 border-b">
        <h2 className="text-lg font-semibold">Compliance Control Matrix</h2>
        <p className="text-sm text-gray-500 mt-1">Status of individual compliance controls</p>
      </div>
      <table className="w-full">
        <thead className="bg-gray-50">
          <tr>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Framework</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Control ID</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Findings</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {controls.map((c) => (
            <tr key={`${c.framework}-${c.id}`} className="hover:bg-gray-50">
              <td className="px-6 py-4 text-sm font-medium">{c.framework}</td>
              <td className="px-6 py-4 font-mono text-sm">{c.id}</td>
              <td className="px-6 py-4 text-sm">{c.title}</td>
              <td className="px-6 py-4">
                {c.status === "pass" ? (
                  <span className="px-2 py-1 bg-green-100 text-green-700 rounded-full text-xs font-medium">✅ Pass</span>
                ) : (
                  <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-medium">❌ Fail</span>
                )}
              </td>
              <td className="px-6 py-4 text-sm">{c.findings}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
