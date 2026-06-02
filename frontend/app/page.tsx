"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import CVECard from "@/components/CVECard";
import { searchCVEs, getTopRisks, type CVE } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CVE[]>([]);
  const [topRisks, setTopRisks] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"top" | "search">("top");

  useEffect(() => {
    getTopRisks(20)
      .then(setTopRisks)
      .catch(() => {});
  }, []);

  const handleSearch = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    setMode("search");
    try {
      const data = await searchCVEs(q);
      setResults(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Search failed");
    } finally {
      setLoading(false);
    }
  }, [query]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      if (/^CVE-\d{4}-\d+$/i.test(query.trim())) {
        router.push(`/cve/${query.trim().toUpperCase()}`);
      } else {
        handleSearch();
      }
    }
  };

  const displayed = mode === "search" ? results : topRisks;

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-bold mb-1">CVE Risk Prioritization</h1>
        <p className="text-zinc-400 text-sm">
          Search vulnerabilities by CVE ID or keyword. Risk scores combine CVSS,
          CISA KEV status, and public exploit availability.
        </p>
      </div>

      <div className="flex gap-3">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search by CVE ID or keyword (e.g. CVE-2025-1234 or 'sql injection')"
          className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2.5 text-sm placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
        />
        <button
          onClick={handleSearch}
          disabled={loading}
          className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold hover:bg-blue-500 disabled:opacity-50 transition-colors"
        >
          {loading ? "Searching…" : "Search"}
        </button>
        <button
          onClick={() => { setMode("top"); setQuery(""); setResults([]); setError(null); }}
          className="rounded-lg border border-zinc-700 px-4 py-2.5 text-sm hover:border-zinc-500 transition-colors"
        >
          Top Risks
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div>
        <h2 className="text-base font-semibold mb-4 text-zinc-300">
          {mode === "search"
            ? `Search results (${results.length})`
            : "Top 20 Highest-Risk CVEs"}
        </h2>

        {displayed.length === 0 && !loading && (
          <p className="text-zinc-500 text-sm">
            {mode === "search" ? "No results found." : "Loading top risks…"}
          </p>
        )}

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {displayed.map((cve) => (
            <CVECard key={cve.cve_id} cve={cve} />
          ))}
        </div>
      </div>
    </div>
  );
}
