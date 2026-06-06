"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import {
  Shield, Activity, Target, Database, BookOpen, Sparkles,
  Ban, FileSearch, TrendingUp, AlertTriangle, Send, ArrowLeft,
} from "lucide-react";
import { chatWithAgent, type CVE, type ChatResponse } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";

// ── Suggested prompts ─────────────────────────────────────────────────────────

const SUGGESTED_PROMPTS: { text: string; category: string; icon: React.ReactNode }[] = [
  {
    text: "What are the current threats on my environment?",
    category: "My Environment",
    icon: <Shield size={14} />,
  },
  {
    text: "What are the top threats I should focus on today?",
    category: "Top Risks",
    icon: <TrendingUp size={14} />,
  },
  {
    text: "What anomalies did the model detect?",
    category: "ML Insights",
    icon: <Activity size={14} />,
  },
  {
    text: "Tell me about LockBit",
    category: "Threat Actor",
    icon: <Target size={14} />,
  },
  {
    text: "Which CVEs are in the CISA KEV catalog?",
    category: "KEV Intel",
    icon: <AlertTriangle size={14} />,
  },
  {
    text: "Explain how the risk score is calculated",
    category: "Project",
    icon: <BookOpen size={14} />,
  },
  {
    text: "Show CVEs with highest EPSS exploit probability",
    category: "EPSS Intel",
    icon: <FileSearch size={14} />,
  },
  {
    text: "What CVEs affect Apache?",
    category: "System Query",
    icon: <Database size={14} />,
  },
];

// ── Agent SVG icon ────────────────────────────────────────────────────────────

function AgentReticle({ size = 32 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <circle cx="16" cy="16" r="14" stroke="#60A5FA" strokeWidth="0.75" strokeOpacity="0.25" />
      <circle cx="16" cy="16" r="10" stroke="#60A5FA" strokeWidth="0.75" strokeOpacity="0.45" />
      <circle cx="16" cy="16" r="5.5" stroke="#60A5FA" strokeWidth="1.5" strokeOpacity="0.85" />
      <circle cx="16" cy="16" r="1.75" fill="#60A5FA" />
      <line x1="16" y1="1.5" x2="16" y2="8.5" stroke="#60A5FA" strokeWidth="1.25" strokeLinecap="round" />
      <line x1="16" y1="23.5" x2="16" y2="30.5" stroke="#60A5FA" strokeWidth="1.25" strokeLinecap="round" />
      <line x1="1.5" y1="16" x2="8.5" y2="16" stroke="#60A5FA" strokeWidth="1.25" strokeLinecap="round" />
      <line x1="23.5" y1="16" x2="30.5" y2="16" stroke="#60A5FA" strokeWidth="1.25" strokeLinecap="round" />
    </svg>
  );
}

// ── Evidence badge ────────────────────────────────────────────────────────────

const EVIDENCE_CONFIG: Record<
  string,
  { label: string; className: string; icon: React.ReactNode }
> = {
  LOCAL_DB: {
    label: "Local DB",
    className: "bg-emerald-950/60 border-emerald-700/60 text-emerald-400",
    icon: <Database size={10} />,
  },
  ML_OUTPUT: {
    label: "ML Output",
    className: "bg-blue-950/60 border-blue-700/60 text-blue-400",
    icon: <Activity size={10} />,
  },
  THREAT_ACTOR_KB: {
    label: "Threat Actor KB",
    className: "bg-orange-950/60 border-orange-700/60 text-orange-400",
    icon: <Target size={10} />,
  },
  PROJECT_CONTEXT: {
    label: "Project Context",
    className: "bg-purple-950/60 border-purple-700/60 text-purple-400",
    icon: <BookOpen size={10} />,
  },
  GEMINI_GENERAL: {
    label: "Gemini General",
    className: "bg-yellow-950/60 border-yellow-700/60 text-yellow-400",
    icon: <Sparkles size={10} />,
  },
  OUT_OF_SCOPE: {
    label: "Out of Scope",
    className: "bg-red-950/60 border-red-700/60 text-red-400",
    icon: <Ban size={10} />,
  },
};

function EvidenceBadge({ evidenceType }: { evidenceType: string }) {
  const cfg = EVIDENCE_CONFIG[evidenceType] ?? {
    label: evidenceType,
    className: "bg-zinc-800 border-zinc-600 text-zinc-400",
    icon: null,
  };
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium ${cfg.className}`}
    >
      {cfg.icon}
      {cfg.label}
    </span>
  );
}

// ── Intent badge ──────────────────────────────────────────────────────────────

const INTENT_LABELS: Record<string, string> = {
  top_risks: "Top Risks",
  cve_explanation: "CVE Analysis",
  similar_cves: "Similarity",
  kev_query: "KEV Intel",
  exploit_query: "Exploit Intel",
  anomaly_query: "Anomaly Detection",
  recommendation_query: "Recommendations",
  search_query: "Search",
  summary_query: "Summary",
  open_project_question: "Project Q&A",
  latest_query: "Latest CVEs",
  system_query: "System Query",
  ransomware_query: "Ransomware Intel",
  threat_actor_query: "Threat Actor",
  environment_query: "My Environment",
  epss_query: "EPSS Intel",
  exploit_detail_query: "Exploit Detail",
  cvss_filter_query: "CVSS Filter",
  out_of_scope: "Out of Scope",
};

function IntentBadge({ intent }: { intent: string }) {
  return (
    <span className="inline-flex items-center rounded border border-zinc-700/80 bg-zinc-800/60 px-2 py-0.5 text-xs font-medium text-zinc-400">
      {INTENT_LABELS[intent] ?? intent}
    </span>
  );
}

// ── Message types ─────────────────────────────────────────────────────────────

interface Message {
  id: number;
  role: "user" | "agent";
  text: string;
  data?: ChatResponse;
  loading?: boolean;
}

// ── Agent text renderer ───────────────────────────────────────────────────────

function AgentText({ text }: { text: string }) {
  const paragraphs = text.split(/\n\n+/);
  return (
    <div className="text-sm text-zinc-200 leading-relaxed space-y-3">
      {paragraphs.map((para, i) => {
        const lines = para.split("\n").filter((l) => l.trim());
        const isList =
          lines.length > 1 &&
          lines.every(
            (l) => /^\s*[•\-\*]/.test(l) || /^\s*\d+[.)]\s/.test(l)
          );
        if (isList) {
          return (
            <ul key={i} className="space-y-1.5 pl-0">
              {lines.map((l, j) => (
                <li key={j} className="flex gap-2.5 items-start">
                  <span className="text-blue-500 flex-shrink-0 mt-0.5 text-xs">▸</span>
                  <span className="text-zinc-300">
                    {l
                      .replace(/^\s*[•\-\*]\s*/, "")
                      .replace(/^\s*\d+[.)]\s*/, "")}
                  </span>
                </li>
              ))}
            </ul>
          );
        }
        return (
          <p key={i} className="whitespace-pre-wrap text-zinc-300">
            {para}
          </p>
        );
      })}
    </div>
  );
}

// ── Mini CVE card (in chat) ───────────────────────────────────────────────────

function MiniCVECard({ cve }: { cve: CVE }) {
  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className="flex flex-col gap-1.5 rounded-lg border border-zinc-700/70 bg-zinc-900/60 p-3 hover:border-blue-500/50 hover:bg-zinc-900 transition-all group"
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className="font-mono text-xs font-bold text-blue-400 group-hover:text-blue-300">
          {cve.cve_id}
        </span>
        {cve.is_kev && (
          <span className="rounded bg-red-900/80 px-1.5 py-0.5 text-xs text-red-300 font-semibold leading-none">
            KEV
          </span>
        )}
        {cve.has_exploit && (
          <span className="rounded bg-orange-900/80 px-1.5 py-0.5 text-xs text-orange-300 font-semibold leading-none">
            EXPLOIT
          </span>
        )}
        {cve.is_anomaly && (
          <span className="rounded bg-purple-900/80 px-1.5 py-0.5 text-xs text-purple-300 font-semibold leading-none">
            ANOMALY
          </span>
        )}
        <RiskBadge label={cve.risk_label} score={cve.risk_score} />
      </div>
      <p className="text-xs text-zinc-500 line-clamp-2 leading-relaxed">
        {cve.description ?? "No description"}
      </p>
      {cve.similarity_score != null && (
        <p className="text-xs text-blue-500">
          {(cve.similarity_score * 100).toFixed(0)}% similar
        </p>
      )}
    </Link>
  );
}

// ── Agent bubble ──────────────────────────────────────────────────────────────

function AgentBubble({ msg }: { msg: Message }) {
  if (msg.loading) {
    return (
      <div className="flex gap-3 items-start">
        <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-700/60 flex items-center justify-center flex-shrink-0 mt-0.5">
          <AgentReticle size={20} />
        </div>
        <div className="flex-1 rounded-2xl rounded-tl-sm bg-zinc-900 border border-zinc-800 px-4 py-3.5 max-w-2xl">
          <div className="flex gap-1.5 items-center h-4">
            {[0, 150, 300].map((delay) => (
              <span
                key={delay}
                className="w-1.5 h-1.5 rounded-full bg-blue-500/70 animate-bounce"
                style={{ animationDelay: `${delay}ms` }}
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  const { data } = msg;

  return (
    <div className="flex gap-3 items-start">
      <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-700/60 flex items-center justify-center flex-shrink-0 mt-0.5">
        <AgentReticle size={20} />
      </div>
      <div className="flex-1 min-w-0">
        {/* Metadata badges */}
        {data && (
          <div className="flex items-center gap-1.5 mb-2 flex-wrap">
            <IntentBadge intent={data.intent} />
            {data.evidence_type && (
              <EvidenceBadge evidenceType={data.evidence_type} />
            )}
            {data.gemini_enabled && data.intent !== "out_of_scope" && (
              <span className="inline-flex items-center gap-1 rounded border border-emerald-700/50 bg-emerald-950/40 px-2 py-0.5 text-xs font-medium text-emerald-400">
                <Sparkles size={10} />
                Gemini
              </span>
            )}
          </div>
        )}

        {/* Message bubble */}
        <div className="rounded-2xl rounded-tl-sm bg-zinc-900 border border-zinc-800 px-4 py-3.5 max-w-2xl">
          <AgentText text={msg.text} />

          {data?.sources && data.sources.length > 0 && (
            <div className="mt-3.5 pt-3 border-t border-zinc-800">
              <p className="text-xs text-zinc-600 mb-1.5 uppercase tracking-wide font-medium">
                Sources
              </p>
              <div className="flex flex-wrap gap-1.5">
                {data.sources.map((s) => (
                  <span
                    key={s}
                    className="rounded-md bg-zinc-800/80 border border-zinc-700/50 px-2 py-0.5 text-xs text-zinc-400"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Related CVEs */}
        {data?.related_cves && data.related_cves.length > 0 && (
          <div className="mt-3">
            <p className="text-xs text-zinc-600 mb-2 uppercase tracking-wide font-medium">
              Related CVEs
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {data.related_cves.map((cve) => (
                <MiniCVECard key={cve.cve_id} cve={cve} />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AgentPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [envVendors, setEnvVendors] = useState<string[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const msgCounter = useRef(0);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("user_environment_vendors");
      if (stored) setEnvVendors(JSON.parse(stored));
    } catch {
      /* ignore */
    }
  }, []);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const addMessage = (msg: Omit<Message, "id">): number => {
    const id = ++msgCounter.current;
    setMessages((prev) => [...prev, { ...msg, id }]);
    return id;
  };

  const updateMessage = (id: number, update: Partial<Message>) => {
    setMessages((prev) =>
      prev.map((m) => (m.id === id ? { ...m, ...update } : m))
    );
  };

  const sendMessage = async (text: string) => {
    if (!text.trim() || isLoading) return;
    const userText = text.trim();
    setInput("");
    setIsLoading(true);

    addMessage({ role: "user", text: userText });
    const agentId = addMessage({ role: "agent", text: "", loading: true });

    try {
      const result = await chatWithAgent(userText, envVendors);
      updateMessage(agentId, { text: result.answer, data: result, loading: false });
    } catch (e: unknown) {
      const err =
        e instanceof Error
          ? e.message
          : "Connection error — is the backend running?";
      updateMessage(agentId, { text: `Error: ${err}`, loading: false });
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) sendMessage(input);
  };

  const isEmpty = messages.length === 0;

  return (
    <div className="flex flex-col h-[calc(100vh-9rem)]">

      {/* ── Page header ──────────────────────────────────────────────── */}
      <div className="flex items-start justify-between mb-5 flex-shrink-0 gap-4">
        <div className="flex items-start gap-4">
          {/* Agent identity icon */}
          <div className="w-12 h-12 rounded-xl bg-zinc-900 border border-zinc-700/60 flex items-center justify-center flex-shrink-0 shadow-inner">
            <AgentReticle size={28} />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white leading-tight">
              AI Threat Prioritization Agent
            </h1>
            <p className="text-sm text-zinc-500 mt-0.5">
              Analyze vulnerabilities, threat actors, anomalies and risk patterns
            </p>
            {envVendors.length > 0 ? (
              <p className="text-xs text-blue-400/80 mt-1.5">
                Environment:{" "}
                <span className="font-medium text-blue-400">
                  {envVendors.join(", ")}
                </span>
              </p>
            ) : (
              <Link
                href="/environment"
                className="text-xs text-zinc-600 hover:text-zinc-400 mt-1.5 block transition-colors"
              >
                Configure My Environment →
              </Link>
            )}
          </div>
        </div>
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 border border-zinc-800 hover:border-zinc-600 px-3 py-1.5 rounded-lg transition-all flex-shrink-0"
        >
          <ArrowLeft size={12} />
          Dashboard
        </Link>
      </div>

      {/* ── Chat area ────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto rounded-xl border border-zinc-800/80 bg-zinc-950/60 p-5 flex flex-col gap-6">
        {isEmpty ? (
          /* Empty state — suggestion grid */
          <div className="flex flex-col items-center justify-center h-full gap-7 text-center py-4">
            <div>
              <div className="flex justify-center mb-4">
                <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-700/60 flex items-center justify-center shadow-inner">
                  <AgentReticle size={40} />
                </div>
              </div>
              <h2 className="text-lg font-semibold text-white mb-2">
                Ready to analyze threats
              </h2>
              <p className="text-zinc-500 text-sm max-w-md leading-relaxed">
                Ask about CVEs, threat actors, EPSS scores, CISA KEV, exploit
                details, anomalies, or this project&apos;s methods.
              </p>
            </div>

            {/* Suggestion cards */}
            <div className="w-full max-w-2xl">
              <p className="text-xs text-zinc-600 mb-3 uppercase tracking-wide font-medium">
                Suggested queries
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {SUGGESTED_PROMPTS.map((p) => (
                  <button
                    key={p.text}
                    onClick={() => sendMessage(p.text)}
                    className="group text-left rounded-xl border border-zinc-800 bg-zinc-900/60 hover:border-blue-500/40 hover:bg-zinc-900 px-4 py-3 transition-all"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-zinc-600 group-hover:text-blue-400 transition-colors">
                        {p.icon}
                      </span>
                      <span className="text-xs text-zinc-600 group-hover:text-zinc-500 font-medium uppercase tracking-wide">
                        {p.category}
                      </span>
                    </div>
                    <p className="text-sm text-zinc-300 group-hover:text-zinc-100 leading-snug transition-colors">
                      {p.text}
                    </p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          messages.map((msg) =>
            msg.role === "user" ? (
              /* User bubble */
              <div key={msg.id} className="flex gap-3 justify-end items-end">
                <div className="max-w-xl rounded-2xl rounded-br-sm bg-blue-600/20 border border-blue-600/30 px-4 py-3 text-sm text-zinc-100">
                  {msg.text}
                </div>
                <div className="w-7 h-7 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center text-sm flex-shrink-0">
                  <span className="text-xs">You</span>
                </div>
              </div>
            ) : (
              <AgentBubble key={msg.id} msg={msg} />
            )
          )
        )}
        <div ref={bottomRef} />
      </div>

      {/* ── Input bar ────────────────────────────────────────────────── */}
      <div className="mt-3 flex gap-2.5 flex-shrink-0">
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          disabled={isLoading}
          placeholder="Ask about threats, CVEs, exploits, anomalies…"
          className="flex-1 rounded-xl border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm placeholder-zinc-600 focus:border-blue-500/60 focus:outline-none disabled:opacity-50 transition-colors"
        />
        <button
          onClick={() => sendMessage(input)}
          disabled={isLoading || !input.trim()}
          className="rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-3 transition-all flex items-center gap-2 text-sm font-semibold text-white flex-shrink-0"
          title="Send (Enter)"
        >
          <Send size={15} />
          <span className="hidden sm:inline">Send</span>
        </button>
      </div>
      <p className="mt-1.5 text-center text-xs text-zinc-700">
        Press Enter to send · Shift+Enter for new line
      </p>
    </div>
  );
}
