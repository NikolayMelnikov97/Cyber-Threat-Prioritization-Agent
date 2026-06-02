"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import CVECard from "@/components/CVECard";
import { getVendors, getThreatActors, searchCVEs, type VendorItem, type ThreatActor, type CVE } from "@/lib/api";

const COUNTRY_COLORS: Record<string, string> = {
  Russia: "bg-red-900 text-red-300 border-red-700",
  China: "bg-yellow-900 text-yellow-300 border-yellow-700",
  "North Korea": "bg-purple-900 text-purple-300 border-purple-700",
  Iran: "bg-orange-900 text-orange-300 border-orange-700",
};

function ThreatActorCard({ actor }: { actor: ThreatActor }) {
  const colorClass = Object.entries(COUNTRY_COLORS).find(([country]) =>
    actor.country.includes(country)
  )?.[1] ?? "bg-zinc-800 text-zinc-300 border-zinc-600";

  return (
    <div className="rounded-xl border border-zinc-700 bg-zinc-900 p-5 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <h3 className="font-bold text-zinc-100 text-base">{actor.name}</h3>
          <p className="text-xs text-zinc-500 mt-0.5">{actor.aliases.slice(0, 3).join(" / ")}</p>
        </div>
        <div className="flex flex-col items-end gap-1 flex-shrink-0">
          <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${colorClass}`}>
            {actor.country}
          </span>
          {actor.mitre_id && (
            <span className="text-xs text-zinc-600 font-mono">{actor.mitre_id}</span>
          )}
        </div>
      </div>

      {actor.matched_vendors && actor.matched_vendors.length > 0 && (
        <div className="rounded-lg bg-red-900/20 border border-red-800 px-3 py-2">
          <p className="text-xs font-semibold text-red-400">
            Targets your stack: {actor.matched_vendors.join(", ")}
          </p>
        </div>
      )}

      <p className="text-sm text-zinc-400 leading-relaxed">{actor.description}</p>

      <div className="flex flex-wrap gap-1">
        {actor.target_sectors.slice(0, 5).map((s) => (
          <span key={s} className="rounded-full bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-xs text-zinc-400">
            {s}
          </span>
        ))}
      </div>

      <div>
        <p className="text-xs text-zinc-500 mb-1">Notable campaigns:</p>
        <ul className="space-y-0.5">
          {actor.notable_campaigns.slice(0, 3).map((c) => (
            <li key={c} className="flex gap-2 text-xs text-zinc-400">
              <span className="text-zinc-600 flex-shrink-0">•</span>
              {c}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function EnvironmentPage() {
  const [allVendors, setAllVendors] = useState<VendorItem[]>([]);
  const [selectedVendors, setSelectedVendors] = useState<string[]>([]);
  const [allActors, setAllActors] = useState<ThreatActor[]>([]);
  const [relevantCVEs, setRelevantCVEs] = useState<CVE[]>([]);
  const [vendorSearch, setVendorSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [cveLoading, setCveLoading] = useState(false);

  // Load from localStorage on mount
  useEffect(() => {
    const stored = localStorage.getItem("user_environment_vendors");
    if (stored) {
      try { setSelectedVendors(JSON.parse(stored)); } catch { /* ignore */ }
    }
  }, []);

  // Persist to localStorage when selectedVendors changes
  useEffect(() => {
    localStorage.setItem("user_environment_vendors", JSON.stringify(selectedVendors));
  }, [selectedVendors]);

  // Load vendors and actors from backend
  useEffect(() => {
    Promise.all([getVendors(), getThreatActors()])
      .then(([vendors, actors]) => {
        setAllVendors(vendors);
        setAllActors(actors);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  // Fetch relevant CVEs whenever selectedVendors changes
  useEffect(() => {
    if (selectedVendors.length === 0) {
      setRelevantCVEs([]);
      return;
    }
    setCveLoading(true);
    Promise.all(selectedVendors.map((v) => searchCVEs(v).catch(() => [] as CVE[])))
      .then((results) => {
        const seen = new Set<string>();
        const merged: CVE[] = [];
        for (const list of results) {
          for (const cve of list) {
            if (!seen.has(cve.cve_id)) {
              seen.add(cve.cve_id);
              merged.push(cve);
            }
          }
        }
        merged.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
        setRelevantCVEs(merged.slice(0, 30));
      })
      .finally(() => setCveLoading(false));
  }, [selectedVendors]);

  // Derive relevant actors (bidirectional substring match)
  const relevantActors = useMemo(() => {
    return allActors
      .map((ta) => {
        const matched = ta.target_vendors.filter((tv) =>
          selectedVendors.some(
            (sv) => sv.toLowerCase().includes(tv.toLowerCase()) || tv.toLowerCase().includes(sv.toLowerCase())
          )
        );
        return matched.length > 0 ? { ...ta, matched_vendors: matched } : null;
      })
      .filter(Boolean) as ThreatActor[];
  }, [allActors, selectedVendors]);

  const toggleVendor = useCallback((vendor: string) => {
    setSelectedVendors((prev) =>
      prev.includes(vendor) ? prev.filter((v) => v !== vendor) : [...prev, vendor]
    );
  }, []);

  const filteredVendors = allVendors.filter(
    (v) =>
      v.vendor.toLowerCase().includes(vendorSearch.toLowerCase()) ||
      v.product.toLowerCase().includes(vendorSearch.toLowerCase())
  );

  return (
    <div className="flex flex-col gap-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold mb-1">My Environment</h1>
        <p className="text-zinc-400 text-sm">
          Select the vendors and products you use. The agent will identify which threat actors target your stack
          and surface relevant CVEs.
        </p>
      </div>

      {/* Vendor selector */}
      <div className="rounded-xl border border-zinc-700 bg-zinc-900 p-6">
        <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wide mb-4">
          My Tech Stack
        </h2>
        <input
          type="text"
          value={vendorSearch}
          onChange={(e) => setVendorSearch(e.target.value)}
          placeholder="Filter vendors…"
          className="mb-4 w-full max-w-sm rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm placeholder-zinc-500 focus:border-blue-500 focus:outline-none"
        />

        {loading ? (
          <p className="text-zinc-500 text-sm">Loading vendors…</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {filteredVendors.map((v) => {
              const isSelected = selectedVendors.includes(v.vendor);
              return (
                <button
                  key={`${v.vendor}-${v.product}`}
                  onClick={() => toggleVendor(v.vendor)}
                  className={`rounded-full border px-3 py-1.5 text-xs font-medium transition-colors ${
                    isSelected
                      ? "bg-blue-700 border-blue-500 text-white"
                      : "border-zinc-600 text-zinc-400 hover:border-zinc-400 hover:text-zinc-200 bg-zinc-800"
                  }`}
                >
                  {v.vendor}
                  {v.product && v.product !== v.vendor && (
                    <span className="ml-1 opacity-60">/ {v.product}</span>
                  )}
                </button>
              );
            })}
            {filteredVendors.length === 0 && (
              <p className="text-zinc-500 text-sm">No vendors match your filter.</p>
            )}
          </div>
        )}

        {selectedVendors.length > 0 && (
          <div className="mt-4 flex items-center gap-3">
            <p className="text-xs text-zinc-500">
              Selected: {selectedVendors.join(", ")}
            </p>
            <button
              onClick={() => setSelectedVendors([])}
              className="text-xs text-zinc-500 hover:text-red-400 transition-colors"
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* Threat actors targeting my stack */}
      {selectedVendors.length > 0 && (
        <div>
          <h2 className="text-base font-semibold mb-1 text-zinc-200">
            Threat Actors Targeting My Stack
          </h2>
          <p className="text-xs text-zinc-500 mb-4">
            {relevantActors.length > 0
              ? `${relevantActors.length} known groups target software in your environment.`
              : "No known threat actors specifically target your selected vendors."}
          </p>
          {relevantActors.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {relevantActors.map((actor) => (
                <ThreatActorCard key={actor.name} actor={actor} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* All threat actors (when nothing selected) */}
      {selectedVendors.length === 0 && !loading && (
        <div>
          <h2 className="text-base font-semibold mb-1 text-zinc-200">Known Threat Actors</h2>
          <p className="text-xs text-zinc-500 mb-4">
            Select vendors above to see which groups target your environment. All tracked groups are shown below.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {allActors.map((actor) => (
              <ThreatActorCard key={actor.name} actor={actor} />
            ))}
          </div>
        </div>
      )}

      {/* Relevant CVEs */}
      {selectedVendors.length > 0 && (
        <div>
          <h2 className="text-base font-semibold mb-1 text-zinc-200">
            Relevant CVEs for Your Environment
          </h2>
          <p className="text-xs text-zinc-500 mb-4">
            CVEs mentioning your selected vendors, sorted by risk score.
          </p>
          {cveLoading && <p className="text-zinc-500 text-sm">Searching CVEs…</p>}
          {!cveLoading && relevantCVEs.length === 0 && (
            <p className="text-zinc-500 text-sm">
              No CVEs found for the selected vendors in the current dataset.
            </p>
          )}
          {!cveLoading && relevantCVEs.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {relevantCVEs.map((cve) => (
                <CVECard key={cve.cve_id} cve={cve} />
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
