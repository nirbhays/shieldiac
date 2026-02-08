interface Scan {
  id: string;
  repo: string;
  branch: string;
  status: string;
  findings: number;
  time: string;
}

export function ScanTimeline({ scans }: { scans: Scan[] }) {
  return (
    <div className="space-y-4">
      {scans.map((scan) => (
        <div key={scan.id} className="flex items-center gap-3">
          <div className={`w-3 h-3 rounded-full flex-shrink-0 ${
            scan.status === "completed" ? "bg-green-500" :
            scan.status === "in_progress" ? "bg-blue-500 animate-pulse" :
            "bg-gray-300"
          }`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm truncate">{scan.repo}</span>
              <code className="text-xs text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded">{scan.branch}</code>
            </div>
            <div className="flex items-center gap-3 text-xs text-gray-500 mt-0.5">
              <span>{scan.time}</span>
              {scan.status === "completed" && <span>{scan.findings} findings</span>}
              {scan.status === "in_progress" && <span className="text-blue-600">Scanning...</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
