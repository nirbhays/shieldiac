"use client";

import { ComplianceMatrix } from "@/components/ComplianceMatrix";

const frameworks = [
  { name: "SOC 2 Type II", version: "2017", passing: 14, failing: 4, total: 18, pct: 77.8 },
  { name: "HIPAA", version: "2013", passing: 8, failing: 3, total: 11, pct: 72.7 },
  { name: "PCI DSS", version: "4.0", passing: 18, failing: 6, total: 24, pct: 75.0 },
  { name: "CIS AWS", version: "2.0", passing: 42, failing: 8, total: 50, pct: 84.0 },
];

export default function CompliancePage() {
  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold">Compliance Dashboard</h1>
          <p className="text-gray-500 mt-1">Track compliance across SOC 2, HIPAA, PCI-DSS, and CIS</p>
        </div>
        <button className="bg-shield-600 text-white px-4 py-2 rounded-lg hover:bg-shield-700 transition">
          Generate Report
        </button>
      </div>

      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {frameworks.map((fw) => (
          <div key={fw.name} className="bg-white border rounded-2xl p-6">
            <h3 className="font-semibold mb-1">{fw.name}</h3>
            <p className="text-xs text-gray-400 mb-4">v{fw.version}</p>
            <div className="flex items-end gap-2 mb-3">
              <span className={`text-3xl font-bold ${fw.pct >= 80 ? "text-green-600" : fw.pct >= 60 ? "text-yellow-600" : "text-red-600"}`}>
                {fw.pct.toFixed(0)}%
              </span>
              <span className="text-sm text-gray-500 mb-1">compliant</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className={`h-2 rounded-full ${fw.pct >= 80 ? "bg-green-500" : fw.pct >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                style={{ width: `${fw.pct}%` }}
              />
            </div>
            <div className="flex justify-between mt-3 text-xs text-gray-500">
              <span>✅ {fw.passing} passing</span>
              <span>❌ {fw.failing} failing</span>
            </div>
          </div>
        ))}
      </div>

      <ComplianceMatrix />
    </div>
  );
}
