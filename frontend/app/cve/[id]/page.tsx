import { getCVE, getSimilar } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";
import SimilarCVEList from "@/components/SimilarCVEList";
import { notFound } from "next/navigation";

export default async function CVEDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  let cve, similar;
  try {
    [cve, similar] = await Promise.all([getCVE(id), getSimilar(id)]);
  } catch {
    notFound();
  }

  return (
    <div className="flex flex-col gap-8">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="text-xs text-zinc-500 mb-1">
            <a href="/" className="hover:text-zinc-300">← Back to search</a>
          </p>
          <h1 className="text-2xl font-mono font-bold text-blue-400">{cve!.cve_id}</h1>
          {cve!.vulnerabilityName && (
            <p className="text-zinc-300 text-sm mt-1">{cve!.vulnerabilityName}</p>
          )}
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {cve!.is_kev && (
            <span className="rounded-md bg-red-900/60 border border-red-700 px-3 py-1 text-sm text-red-300 font-semibold">
              🔴 CISA KEV — Actively Exploited
            </span>
          )}
          {cve!.has_exploit && (
            <span className="rounded-md bg-orange-900/60 border border-orange-700 px-3 py-1 text-sm text-orange-300 font-semibold">
              ⚠️ Public Exploit Available
            </span>
          )}
          {cve!.is_anomaly && (
            <span className="rounded-md bg-purple-900/60 border border-purple-700 px-3 py-1 text-sm text-purple-300 font-semibold">
              🔬 Anomaly Detected
            </span>
          )}
        </div>
      </div>

      {/* Risk score */}
      <div className="rounded-xl border border-zinc-700 bg-zinc-900 p-6 grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div>
          <p className="text-xs text-zinc-500 mb-1">Risk Score</p>
          <div className="flex items-center gap-2">
            <span className="text-3xl font-bold">{cve!.risk_score?.toFixed(1) ?? "—"}</span>
            <span className="text-zinc-500">/10</span>
          </div>
          <RiskBadge label={cve!.risk_label} />
        </div>
        <div>
          <p className="text-xs text-zinc-500 mb-1">CVSS Base Score</p>
          <span className="text-2xl font-bold">{cve!.severity_score?.toFixed(1) ?? "—"}</span>
          {cve!.severity_label && (
            <p className="text-xs text-zinc-400 mt-0.5">{cve!.severity_label}</p>
          )}
        </div>
        <div>
          <p className="text-xs text-zinc-500 mb-1">CWE</p>
          <span className="text-sm font-mono text-zinc-300">{cve!.cwe || "—"}</span>
        </div>
        <div>
          <p className="text-xs text-zinc-500 mb-1">Cluster</p>
          <span className="text-sm text-zinc-300">{cve!.cluster_label || "—"}</span>
        </div>
      </div>

      {/* Description */}
      <div>
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wide mb-2">Description</h2>
        <p className="text-sm text-zinc-300 leading-relaxed">{cve!.description || "No description available."}</p>
      </div>

      {/* AI Explanation */}
      <div className="rounded-xl border border-blue-900 bg-blue-950/30 p-5">
        <h2 className="text-sm font-semibold text-blue-400 uppercase tracking-wide mb-2">
          🤖 Agent Analysis
        </h2>
        <p className="text-sm text-zinc-200 leading-relaxed">{cve!.explanation}</p>
      </div>

      {/* CISA required action */}
      {cve!.requiredAction && (
        <div className="rounded-xl border border-yellow-800 bg-yellow-950/30 p-5">
          <h2 className="text-sm font-semibold text-yellow-400 uppercase tracking-wide mb-2">
            📋 CISA Required Action
          </h2>
          <p className="text-sm text-zinc-200 leading-relaxed">{cve!.requiredAction}</p>
        </div>
      )}

      {/* Similar CVEs */}
      <div>
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wide mb-3">
          Similar CVEs
        </h2>
        <SimilarCVEList cves={similar!} />
      </div>
    </div>
  );
}
