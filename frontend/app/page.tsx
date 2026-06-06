"use client";

import { useState, useEffect, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  Search, Shield, Activity, AlertTriangle, Zap, ArrowRight, ChevronRight,
} from "lucide-react";
import CVECard from "@/components/CVECard";
import { searchCVEs, getTopRisks, getStats, type CVE, type DashboardStats } from "@/lib/api";

type SortKey = "risk" | "date";
type FilterKey = "kev" | "exploit" | "ransomware" | "anomaly";

function FilterChip({
  label, active, onClick,
}: {
  label: string; active: boolean; onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`rounded-full px-3 py-1 text-xs font-semibold border transition-all ${
        active
          ? "bg-blue-600 border-blue-500 text-white shadow-sm shadow-blue-500/20"
          : "border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200"
      }`}
    >
      {label}
    </button>
  );
}

export default function HomePage() {
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<CVE[]>([]);
  const [topRisks, setTopRisks] = useState<CVE[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<"top" | "search">("top");
  const [activeFilters, setActiveFilters] = useState<Set<FilterKey>>(new Set());
  const [sortBy, setSortBy] = useState<SortKey>("risk");
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    getTopRisks(6).then(setTopRisks).catch(() => {});
    getStats().then(setStats).catch(() => {});
  }, []);

  const handleSearch = useCallback(async () => {
    const q = query.trim();
    if (!q) return;
    setLoading(true);
    setError(null);
    setMode("search");
    setShowAll(true);
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

  const toggleFilter = (key: FilterKey) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const baseList = mode === "search" ? results : topRisks;
  const filtered = baseList.filter((cve) => {
    if (activeFilters.has("kev") && !cve.is_kev) return false;
    if (activeFilters.has("exploit") && !cve.has_exploit) return false;
    if (activeFilters.has("ransomware") && cve.ransomware_campaign !== "Known") return false;
    if (activeFilters.has("anomaly") && !cve.is_anomaly) return false;
    return true;
  });
  const sorted = [...filtered].sort((a, b) =>
    sortBy === "date"
      ? (b.published ?? "").localeCompare(a.published ?? "")
      : (b.risk_score ?? 0) - (a.risk_score ?? 0)
  );
  const displayed = showAll ? sorted : sorted.slice(0, 6);

  const isSearch = mode === "search";

  return (
    <div className="flex flex-col">

      {/* ── Hero ──────────────────────────────────────────────────────── */}
      <section className="relative -mx-6 -mt-8 mb-10 overflow-hidden min-h-[400px] flex items-center">
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat"
          style={{
            backgroundImage:
              "url('https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=1920&auto=format&fit=crop&q=80')",
          }}
        />
        {/* Gradient overlays for readability */}
        <div className="absolute inset-0 bg-gradient-to-r from-zinc-950 via-zinc-950/88 to-zinc-950/50" />
        <div className="absolute inset-0 bg-gradient-to-t from-zinc-950 via-zinc-950/20 to-transparent" />

        <div className="relative z-10 w-full max-w-6xl mx-auto px-6 py-16">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-400 uppercase tracking-wider mb-5">
            <Shield size={10} />
            AI & ML Innovation Workshop — Final Project
          </div>
          <h1 className="text-4xl md:text-5xl font-bold text-white leading-tight max-w-2xl mb-4">
            Cyber Threat<br />
            <span className="text-blue-400">Prioritization Agent</span>
          </h1>
          <p className="text-zinc-300 text-base md:text-lg max-w-xl leading-relaxed mb-8">
            AI-powered vulnerability risk intelligence for SOC analysts. Combines CVSS,
            CISA KEV, EPSS, and ML models to surface the threats that matter most.
          </p>
          <div className="flex flex-wrap gap-3">
            <Link
              href="/agent"
              className="inline-flex items-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-500 px-5 py-2.5 text-sm font-semibold text-white transition-all shadow-lg shadow-blue-600/25"
            >
              <Shield size={15} />
              Open AI Agent
              <ChevronRight size={13} className="opacity-70" />
            </Link>
            <a
              href="#threats"
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-600/80 bg-zinc-900/60 backdrop-blur-sm hover:border-zinc-400 px-5 py-2.5 text-sm font-semibold text-zinc-200 hover:text-white transition-all"
            >
              <Activity size={15} />
              Explore CVEs
            </a>
          </div>
        </div>
      </section>

      {/* ── Stats bar ──────────────────────────────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-8">
          {[
            {
              label: "CVEs in Dataset",
              value: stats.total_cves.toLocaleString(),
              icon: <Activity size={16} />,
              color: "text-blue-400",
              border: "border-blue-500/20",
              bg: "bg-blue-500/5",
            },
            {
              label: "Critical Risk",
              value: stats.critical_count.toLocaleString(),
              icon: <AlertTriangle size={16} />,
              color: "text-red-400",
              border: "border-red-500/20",
              bg: "bg-red-500/5",
            },
            {
              label: "Known Exploited",
              value: stats.kev_count.toLocaleString(),
              icon: <Shield size={16} />,
              color: "text-orange-400",
              border: "border-orange-500/20",
              bg: "bg-orange-500/5",
            },
            {
              label: "Public Exploits",
              value: stats.exploit_count.toLocaleString(),
              icon: <Zap size={16} />,
              color: "text-yellow-400",
              border: "border-yellow-500/20",
              bg: "bg-yellow-500/5",
            },
          ].map((s) => (
            <div
              key={s.label}
              className={`rounded-xl border ${s.border} ${s.bg} px-4 py-3 flex items-center gap-3`}
            >
              <span className={`${s.color} flex-shrink-0`}>{s.icon}</span>
              <div>
                <div className="text-lg font-bold text-white leading-none mb-0.5">
                  {s.value}
                </div>
                <div className="text-xs text-zinc-500">{s.label}</div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── CVE List ───────────────────────────────────────────────────── */}
      <div id="threats" className="flex flex-col gap-4">

        {/* Search bar */}
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search
              size={15}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none"
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search by CVE ID or keyword — e.g. CVE-2025-1234 or 'sql injection'"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 pl-9 pr-4 py-2.5 text-sm placeholder-zinc-500 focus:border-blue-500 focus:outline-none transition-colors"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={loading}
            className="rounded-lg bg-blue-600 px-5 py-2.5 text-sm font-semibold hover:bg-blue-500 disabled:opacity-50 transition-colors flex-shrink-0"
          >
            {loading ? "Searching…" : "Search"}
          </button>
          {isSearch && (
            <button
              onClick={() => {
                setMode("top");
                setQuery("");
                setResults([]);
                setError(null);
                setShowAll(false);
              }}
              className="rounded-lg border border-zinc-700 px-4 py-2.5 text-sm text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors flex-shrink-0"
            >
              Clear
            </button>
          )}
        </div>

        {/* Filters + sort */}
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs text-zinc-600 uppercase tracking-wide shrink-0">
            Filter:
          </span>
          <FilterChip
            label="KEV Only"
            active={activeFilters.has("kev")}
            onClick={() => toggleFilter("kev")}
          />
          <FilterChip
            label="Has Exploit"
            active={activeFilters.has("exploit")}
            onClick={() => toggleFilter("exploit")}
          />
          <FilterChip
            label="Ransomware"
            active={activeFilters.has("ransomware")}
            onClick={() => toggleFilter("ransomware")}
          />
          <FilterChip
            label="Anomaly"
            active={activeFilters.has("anomaly")}
            onClick={() => toggleFilter("anomaly")}
          />
          <div className="ml-auto flex items-center gap-2 flex-shrink-0">
            <span className="text-xs text-zinc-600 uppercase tracking-wide">Sort:</span>
            {(["risk", "date"] as const).map((key) => (
              <button
                key={key}
                onClick={() => setSortBy(key)}
                className={`rounded-full px-3 py-1 text-xs font-semibold border transition-colors ${
                  sortBy === key
                    ? "bg-zinc-700 border-zinc-500 text-white"
                    : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
                }`}
              >
                {key === "risk" ? "Risk Score" : "Date"}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-800 bg-red-950/50 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* Section heading */}
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">
            {isSearch
              ? `Search results — ${sorted.length} found`
              : "Highest Priority Threats"}
          </h2>
          {!isSearch && stats && (
            <span className="text-xs text-zinc-600">
              {stats.total_cves.toLocaleString()} total in dataset
            </span>
          )}
        </div>

        {displayed.length === 0 && !loading && (
          <p className="text-zinc-500 text-sm py-4">
            {isSearch ? "No results found." : "Loading threat data…"}
          </p>
        )}

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {displayed.map((cve) => (
            <CVECard key={cve.cve_id} cve={cve} />
          ))}
        </div>

        {/* View All / Show Less */}
        {!showAll && sorted.length > 6 && (
          <div className="flex justify-center mt-2">
            <button
              onClick={() => setShowAll(true)}
              className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900/80 hover:border-blue-500/50 hover:text-blue-300 px-6 py-3 text-sm font-semibold text-zinc-300 transition-all"
            >
              View All CVEs
              <ArrowRight size={14} />
            </button>
          </div>
        )}
        {showAll && sorted.length > 6 && (
          <div className="flex justify-center mt-2">
            <button
              onClick={() => {
                setShowAll(false);
                document
                  .getElementById("threats")
                  ?.scrollIntoView({ behavior: "smooth" });
              }}
              className="text-xs text-zinc-600 hover:text-zinc-400 transition-colors"
            >
              ↑ Show fewer
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
