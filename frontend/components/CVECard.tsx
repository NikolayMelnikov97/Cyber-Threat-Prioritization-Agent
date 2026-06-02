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
        <div className="flex items-center gap-2">
          {cve.is_kev && (
            <span className="rounded bg-red-900 px-1.5 py-0.5 text-xs text-red-300 font-semibold">
              KEV
            </span>
          )}
          {cve.has_exploit && (
            <span className="rounded bg-orange-900 px-1.5 py-0.5 text-xs text-orange-300 font-semibold">
              EXPLOIT
            </span>
          )}
          <RiskBadge label={cve.risk_label} score={cve.risk_score} />
        </div>
      </div>

      <p className="text-sm text-zinc-400 line-clamp-2">
        {cve.description || "No description available."}
      </p>

      <div className="mt-2 flex items-center gap-3 text-xs text-zinc-500">
        {cve.cwe && cve.cwe !== "UNKNOWN" && <span>CWE: {cve.cwe}</span>}
        {cve.severity_score != null && (
          <span>CVSS: {cve.severity_score.toFixed(1)}</span>
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
