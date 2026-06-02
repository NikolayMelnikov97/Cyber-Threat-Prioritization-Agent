const colors: Record<string, string> = {
  Critical: "bg-red-600 text-white",
  High: "bg-orange-500 text-white",
  Medium: "bg-yellow-400 text-black",
  Low: "bg-green-600 text-white",
};

export default function RiskBadge({
  label,
  score,
}: {
  label?: string | null;
  score?: number | null;
}) {
  const l = label || "Unknown";
  const cls = colors[l] ?? "bg-gray-600 text-white";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold ${cls}`}
    >
      {l}
      {score != null && <span className="opacity-80">({score.toFixed(1)})</span>}
    </span>
  );
}
