const BACKEND_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface CVE {
  cve_id: string;
  published?: string;
  description?: string;
  severity_score?: number;
  severity_label?: string;
  cwe?: string;
  references_count?: number;
  is_kev?: boolean;
  has_exploit?: boolean;
  risk_score?: number;
  risk_label?: string;
  cluster_id?: number;
  cluster_label?: string;
  is_anomaly?: boolean;
  explanation?: string;
  requiredAction?: string;
  vulnerabilityName?: string;
  similarity_score?: number;
}

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${BACKEND_URL}${path}`, { cache: "no-store" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || `API error ${res.status}`);
  }
  return res.json();
}

export const getCVE = (id: string) => apiFetch<CVE>(`/cve/${id}`);
export const getSimilar = (id: string, n = 5) =>
  apiFetch<CVE[]>(`/cve/${id}/similar?n=${n}`);
export const getTopRisks = (n = 20) =>
  apiFetch<CVE[]>(`/top-risks?n=${n}`);
export const searchCVEs = (q: string) =>
  apiFetch<CVE[]>(`/search?q=${encodeURIComponent(q)}`);
