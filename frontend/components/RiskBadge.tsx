const RISK_STYLES: Record<string, string> = {
  Critical:
    "bg-red-950/80 border border-red-700/70 text-red-400",
  High:
    "bg-orange-950/80 border border-orange-700/70 text-orange-400",
  Medium:
    "bg-yellow-950/80 border border-yellow-700/70 text-yellow-400",
  Low:
    "bg-green-950/80 border border-green-700/70 text-green-400",
};

export default function RiskBadge({
  label,
  score,
}: {
  label?: string | null;
  score?: number | null;
}) {
  const l = label || "Unknown";
  const cls =
    RISK_STYLES[l] ?? "bg-zinc-800/80 border border-zinc-700 text-zinc-400";
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-semibold leading-none ${cls}`}
    >
      {l}
      {score != null && (
        <span className="opacity-60 font-normal">{score.toFixed(1)}</span>
      )}
    </span>
  );
}
