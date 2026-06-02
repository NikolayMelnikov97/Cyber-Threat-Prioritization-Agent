"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import CVECard from "@/components/CVECard";
import { searchCVEs, getTopRisks, getLatestCVEs, type CVE } from "@/lib/api";

function FilterChip({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
        active
          ? "bg-blue-700 border-blue-500 text-white"
          : "border-zinc-600 text-zinc-400 hover:border-zinc-400 hover:text-zinc-200"
      }`}
    >
      {label}
    </button>
  );
}

type Mode = "top" | "search" | "latest";
type SortKey = "risk" | "date";
type FilterKey = "kev" | "exploit" | "ransomware" | "anomaly";

export default function HomePage() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CVE[]>([]);
  const [topRisks, setTopRisks] = useState<CVE[]>([]);
  const [latestCVEs, setLatestCVEs] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>("top");
  const [activeFilters, setActiveFilters] = useState<Set<FilterKey>>(new Set());
  const [sortBy, setSortBy] = useState<SortKey>("risk");

  useEffect(() => {
    getTopRisks(50).then(setTopRisks).catch(() => {});
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

  const handleLatest = useCallback(async () => {
    setLoading(true);
    setError(null);
    setMode("latest");
    setQuery("");
    setResults([]);
    try {
      const data = await getLatestCVEs(50);
      setLatestCVEs(data);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load latest CVEs");
    } finally {
      setLoading(false);
    }
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      if (/^CVE-\d{4}-\d+$/i.test(query.trim())) {
        router.push(`/cve/${query.trim().toUpperCase()}`);
      } else {
        handleSearch();
      }
    }
  };

  const toggleFilter = (key: FilterKey) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const baseList =
    mode === "search" ? results : mode === "latest" ? latestCVEs : topRisks;

  const filtered = baseList.filter((cve) => {
    if (activeFilters.has("kev") && !cve.is_kev) return false;
    if (activeFilters.has("exploit") && !cve.has_exploit) return false;
    if (activeFilters.has("ransomware") && cve.ransomware_campaign !== "Known") return false;
    if (activeFilters.has("anomaly") && !cve.is_anomaly) return false;
    return true;
  });

  const displayed = [...filtered].sort((a, b) => {
    if (sortBy === "date") {
      return (b.published ?? "").localeCompare(a.published ?? "");
    }
    return (b.risk_score ?? 0) - (a.risk_score ?? 0);
  });

  const headingText =
    mode === "search"
      ? `Search results (${displayed.length})`
      : mode === "latest"
      ? `Latest CVEs (${displayed.length})`
      : `Top Highest-Risk CVEs (${displayed.length})`;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-bold mb-1">CVE Risk Prioritization</h1>
        <p className="text-zinc-400 text-sm">
          Search vulnerabilities by CVE ID or keyword. Risk scores combine CVSS,
          CISA KEV status, and public exploit availability.
        </p>
      </div>

      {/* Search bar */}
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
          className={`rounded-lg border px-4 py-2.5 text-sm transition-colors ${
            mode === "top" ? "border-blue-500 text-blue-300 bg-blue-900/30" : "border-zinc-700 hover:border-zinc-500"
          }`}
        >
          Top Risks
        </button>
        <button
          onClick={handleLatest}
          className={`rounded-lg border px-4 py-2.5 text-sm transition-colors ${
            mode === "latest" ? "border-blue-500 text-blue-300 bg-blue-900/30" : "border-zinc-700 hover:border-zinc-500"
          }`}
        >
          Latest
        </button>
      </div>

      {/* Filter + sort bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-xs text-zinc-500 uppercase tracking-wide">Filter:</span>
        <FilterChip label="KEV Only" active={activeFilters.has("kev")} onClick={() => toggleFilter("kev")} />
        <FilterChip label="Has Exploit" active={activeFilters.has("exploit")} onClick={() => toggleFilter("exploit")} />
        <FilterChip label="Ransomware" active={activeFilters.has("ransomware")} onClick={() => toggleFilter("ransomware")} />
        <FilterChip label="Anomaly" active={activeFilters.has("anomaly")} onClick={() => toggleFilter("anomaly")} />
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-zinc-500 uppercase tracking-wide">Sort:</span>
          <button
            onClick={() => setSortBy("risk")}
            className={`rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
              sortBy === "risk" ? "bg-zinc-700 border-zinc-500 text-white" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            Risk Score
          </button>
          <button
            onClick={() => setSortBy("date")}
            className={`rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
              sortBy === "date" ? "bg-zinc-700 border-zinc-500 text-white" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
            }`}
          >
            Date Published
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div>
        <h2 className="text-base font-semibold mb-4 text-zinc-300">{headingText}</h2>

        {displayed.length === 0 && !loading && (
          <p className="text-zinc-500 text-sm">
            {mode === "search" ? "No results found." : "Loading…"}
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
