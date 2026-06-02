import CVECard from "./CVECard";
import type { CVE } from "@/lib/api";

export default function SimilarCVEList({ cves }: { cves: CVE[] }) {
  if (!cves.length) return <p className="text-zinc-500 text-sm">No similar CVEs found.</p>;
  return (
    <div className="flex flex-col gap-3">
      {cves.map((c) => (
        <CVECard key={c.cve_id} cve={c} showSimilarity />
      ))}
    </div>
  );
}
