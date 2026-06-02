import Link from "next/link";
import RiskBadge from "./RiskBadge";
import type { CVE } from "@/lib/api";

export default function CVECard({
  cve,
  showSimilarity,
}: {
  cve: CVE;
  showSimilarity?: boolean;
}) {
  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className="block rounded-lg border border-zinc-700 bg-zinc-800 p-4 hover:border-blue-500 transition-colors"
    >
      <div className="flex items-center justify-between gap-2 mb-2">
        <span className="font-mono text-sm font-bold text-blue-400">
          {cve.cve_id}
        </span>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          {cve.ransomware_campaign === "Known" && (
            <span className="rounded bg-yellow-900 px-1.5 py-0.5 text-xs text-yellow-300 font-semibold">
              RANSOM
            </span>
          )}
          {cve.is_kev && (
            <span className="rounded bg-red-900 px-1.5 py-0.5 text-xs text-red-300 font-semibold">
              KEV
            </span>
          )}
          {cve.has_exploit && (
            <span className="rounded bg-orange-900 px-1.5 py-0.5 text-xs text-orange-300 font-semibold">
              {cve.exploit_verified ? "VERIFIED EXPLOIT" : "EXPLOIT"}
            </span>
          )}
          {cve.epss_score != null && cve.epss_score > 0.1 && (
            <span className="rounded bg-purple-900 px-1.5 py-0.5 text-xs text-purple-300 font-semibold" title={`EPSS: ${(cve.epss_score * 100).toFixed(1)}% exploit probability`}>
              EPSS {(cve.epss_percentile != null ? cve.epss_percentile * 100 : 0).toFixed(0)}%ile
            </span>
          )}
          <RiskBadge label={cve.risk_label} score={cve.risk_score} />
        </div>
      </div>

      <p className="text-sm text-zinc-400 line-clamp-2">
        {cve.description || "No description available."}
      </p>

      <div className="mt-2 flex items-center gap-3 text-xs text-zinc-500 flex-wrap">
        {cve.cwe && cve.cwe !== "UNKNOWN" && <span>CWE: {cve.cwe}</span>}
        {cve.severity_score != null && (
          <span>CVSS: {cve.severity_score.toFixed(1)}</span>
        )}
        {cve.vendorProject && (
          <span className="rounded bg-zinc-700 px-1.5 py-0.5 text-zinc-300">
            {cve.vendorProject}
          </span>
        )}
        {cve.published && (
          <span className="ml-auto text-zinc-600">{cve.published.slice(0, 10)}</span>
        )}
        {showSimilarity && cve.similarity_score != null && (
          <span className="text-blue-400">
            Similarity: {(cve.similarity_score * 100).toFixed(0)}%
          </span>
        )}
      </div>
    </Link>
  );
}
