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
      className="group block rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 hover:border-zinc-600 hover:bg-zinc-900 transition-all"
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-2 mb-2.5">
        <span className="font-mono text-sm font-bold text-blue-400 group-hover:text-blue-300 transition-colors leading-none mt-0.5">
          {cve.cve_id}
        </span>
        <div className="flex items-center gap-1.5 flex-wrap justify-end flex-shrink-0">
          {cve.ransomware_campaign === "Known" && (
            <span className="rounded-md bg-yellow-900/70 border border-yellow-800/60 px-1.5 py-0.5 text-xs text-yellow-300 font-semibold leading-none">
              RANSOM
            </span>
          )}
          {cve.is_kev && (
            <span className="rounded-md bg-red-900/70 border border-red-800/60 px-1.5 py-0.5 text-xs text-red-300 font-semibold leading-none">
              KEV
            </span>
          )}
          {cve.has_exploit && (
            <span className="rounded-md bg-orange-900/70 border border-orange-800/60 px-1.5 py-0.5 text-xs text-orange-300 font-semibold leading-none">
              {cve.exploit_verified ? "VERIFIED EXPLOIT" : "EXPLOIT"}
            </span>
          )}
          {cve.epss_score != null && cve.epss_score > 0.1 && (
            <span
              className="rounded-md bg-purple-900/70 border border-purple-800/60 px-1.5 py-0.5 text-xs text-purple-300 font-semibold leading-none"
              title={`EPSS: ${(cve.epss_score * 100).toFixed(1)}% exploit probability`}
            >
              EPSS {(
                cve.epss_percentile != null ? cve.epss_percentile * 100 : 0
              ).toFixed(0)}%ile
            </span>
          )}
          <RiskBadge label={cve.risk_label} score={cve.risk_score} />
        </div>
      </div>

      {/* Description */}
      <p className="text-sm text-zinc-400 line-clamp-2 leading-relaxed mb-3">
        {cve.description || "No description available."}
      </p>

      {/* Footer row */}
      <div className="flex items-center gap-2.5 text-xs text-zinc-600 flex-wrap">
        {cve.cwe && cve.cwe !== "UNKNOWN" && (
          <span className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-zinc-500 font-mono">
            {cve.cwe}
          </span>
        )}
        {cve.severity_score != null && (
          <span>CVSS {cve.severity_score.toFixed(1)}</span>
        )}
        {cve.vendorProject && (
          <span className="rounded bg-zinc-800/80 px-1.5 py-0.5 text-zinc-500">
            {cve.vendorProject}
          </span>
        )}
        {cve.published && (
          <span className="ml-auto text-zinc-700">
            {cve.published.slice(0, 10)}
          </span>
        )}
        {showSimilarity && cve.similarity_score != null && (
          <span className="text-blue-500">
            {(cve.similarity_score * 100).toFixed(0)}% similar
          </span>
        )}
      </div>
    </Link>
  );
}
