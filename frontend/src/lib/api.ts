const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...options?.headers },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  // Scans
  createScan: (data: any) => apiFetch("/scans/", { method: "POST", body: JSON.stringify(data) }),
  getScan: (id: string) => apiFetch(`/scans/${id}`),
  listScans: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return apiFetch(`/scans/${qs}`);
  },

  // Dashboard
  getOverview: () => apiFetch("/dashboard/overview"),
  getRepos: () => apiFetch("/dashboard/repos"),
  getRepoDetail: (id: string) => apiFetch(`/dashboard/repos/${id}`),
  getTrends: (days?: number) => apiFetch(`/dashboard/trends?days=${days || 30}`),

  // Rules
  listRules: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return apiFetch(`/rules/${qs}`);
  },
  getRule: (id: string) => apiFetch(`/rules/${id}`),
  getRuleStats: () => apiFetch("/rules/summary/stats"),

  // Reports
  getComplianceReport: (framework: string) => apiFetch(`/reports/compliance/${framework}`),
  getComplianceDashboard: () => apiFetch("/reports/compliance"),

  // Billing
  getPlans: () => apiFetch("/billing/plans"),
  getUsage: () => apiFetch("/billing/usage"),

  // Health
  health: () => apiFetch("/health"),
};
