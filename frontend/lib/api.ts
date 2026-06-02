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
  vendorProject?: string;
  product?: string;
  dateAdded?: string;
  dueDate?: string;
  ransomware_campaign?: string;
}

export interface VendorItem {
  vendor: string;
  product: string;
}

export interface ThreatActor {
  name: string;
  aliases: string[];
  country: string;
  description: string;
  target_sectors: string[];
  target_vendors: string[];
  associated_cwes: string[];
  notable_campaigns: string[];
  mitre_id: string;
  matched_vendors?: string[];
}

export interface ChatResponse {
  answer: string;
  intent: string;
  sources: string[];
  related_cves: CVE[];
  gemini_enabled: boolean;
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BACKEND_URL}${path}`, {
    cache: "no-store",
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail || `API error ${res.status}`);
  }
  return res.json();
}

export const getCVE = (id: string) => apiFetch<CVE>(`/cve/${id}`);
export const getSimilar = (id: string, n = 5) =>
  apiFetch<CVE[]>(`/cve/${id}/similar?n=${n}`);
export const getTopRisks = (n = 20) => apiFetch<CVE[]>(`/top-risks?n=${n}`);
export const searchCVEs = (q: string) =>
  apiFetch<CVE[]>(`/search?q=${encodeURIComponent(q)}`);

export const chatWithAgent = (message: string, environment_vendors: string[] = []) =>
  apiFetch<ChatResponse>("/agent/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, environment_vendors }),
  });

export const getLatestCVEs = (n = 20) =>
  apiFetch<CVE[]>(`/latest-cves?n=${n}`);

export const getVendors = () =>
  apiFetch<VendorItem[]>(`/vendors`);

export const getThreatActors = (vendor?: string) =>
  apiFetch<ThreatActor[]>(
    vendor ? `/threat-actors?vendor=${encodeURIComponent(vendor)}` : `/threat-actors`,
  );
