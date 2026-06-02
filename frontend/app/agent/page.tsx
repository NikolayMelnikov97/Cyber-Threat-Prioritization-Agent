"use client";

import { useState, useRef, useEffect } from "react";
import Link from "next/link";
import { chatWithAgent, type CVE, type ChatResponse } from "@/lib/api";
import RiskBadge from "@/components/RiskBadge";

const EXAMPLE_PROMPTS = [
  "What are the current threats on my environment?",
  "What are the top threats I should focus on today?",
  "Show me the latest CVEs published recently",
  "What CVEs affect Apache?",
  "Which CVEs have been used in ransomware attacks?",
  "Tell me about APT28 and what systems they target",
  "What do we know about Lazarus Group?",
  "Which CVEs are in the CISA KEV catalog?",
  "What anomalies did the model detect?",
  "What should a SOC analyst patch first today?",
];

interface Message {
  id: number;
  role: "user" | "agent";
  text: string;
  data?: ChatResponse;
  loading?: boolean;
}

function AgentText({ text }: { text: string }) {
  const paragraphs = text.split(/\n\n+/);
  return (
    <div className="text-sm text-zinc-200 leading-relaxed space-y-3">
      {paragraphs.map((para, i) => {
        const lines = para.split("\n").filter((l) => l.trim());
        const isList = lines.length > 1 && lines.every((l) =>
          /^\s*[•\-\*]/.test(l) || /^\s*\d+[.)]\s/.test(l)
        );
        if (isList) {
          return (
            <ul key={i} className="space-y-1.5 pl-1">
              {lines.map((l, j) => (
                <li key={j} className="flex gap-2">
                  <span className="text-blue-400 flex-shrink-0 mt-0.5">•</span>
                  <span>{l.replace(/^\s*[•\-\*]\s*/, "").replace(/^\s*\d+[.)]\s*/, "")}</span>
                </li>
              ))}
            </ul>
          );
        }
        return <p key={i} className="whitespace-pre-wrap">{para}</p>;
      })}
    </div>
  );
}

function IntentBadge({ intent }: { intent: string }) {
  const labels: Record<string, string> = {
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
    threat_actor_query: "Threat Actor Intel",
    environment_query: "My Environment",
    epss_query: "EPSS Intel",
    exploit_detail_query: "Exploit Detail",
    cvss_filter_query: "CVSS Filter",
    general_help: "Help",
  };
  return (
    <span className="inline-block rounded bg-blue-900/50 border border-blue-700 px-2 py-0.5 text-xs text-blue-300 font-mono">
      {labels[intent] ?? intent}
    </span>
  );
}

function MiniCVECard({ cve }: { cve: CVE }) {
  return (
    <Link
      href={`/cve/${cve.cve_id}`}
      className="flex items-start gap-2 rounded-lg border border-zinc-700 bg-zinc-800/50 p-3 hover:border-blue-500 transition-colors group"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <span className="font-mono text-xs font-bold text-blue-400 group-hover:text-blue-300">
            {cve.cve_id}
          </span>
          {cve.is_kev && (
            <span className="rounded bg-red-900 px-1 py-0.5 text-xs text-red-300 font-semibold">KEV</span>
          )}
          {cve.has_exploit && (
            <span className="rounded bg-orange-900 px-1 py-0.5 text-xs text-orange-300 font-semibold">EXPLOIT</span>
          )}
          {cve.is_anomaly && (
            <span className="rounded bg-purple-900 px-1 py-0.5 text-xs text-purple-300 font-semibold">ANOMALY</span>
          )}
          <RiskBadge label={cve.risk_label} score={cve.risk_score} />
        </div>
        <p className="text-xs text-zinc-400 line-clamp-2">
          {cve.description ?? "No description"}
        </p>
        {cve.similarity_score != null && (
          <p className="text-xs text-blue-400 mt-1">
            Similarity: {(cve.similarity_score * 100).toFixed(0)}%
          </p>
        )}
      </div>
    </Link>
  );
}

function AgentBubble({ msg }: { msg: Message }) {
  if (msg.loading) {
    return (
      <div className="flex gap-3">
        <div className="w-8 h-8 rounded-full bg-blue-700 flex items-center justify-center text-sm flex-shrink-0 mt-1">🛡️</div>
        <div className="flex-1 rounded-2xl rounded-tl-sm bg-zinc-800 border border-zinc-700 px-4 py-3">
          <div className="flex gap-1 items-center h-5">
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: "0ms" }} />
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: "150ms" }} />
            <span className="w-2 h-2 rounded-full bg-blue-400 animate-bounce" style={{ animationDelay: "300ms" }} />
          </div>
        </div>
      </div>
    );
  }

  const { data } = msg;

  return (
    <div className="flex gap-3">
      <div className="w-8 h-8 rounded-full bg-blue-700 flex items-center justify-center text-sm flex-shrink-0 mt-1">🛡️</div>
      <div className="flex-1 min-w-0">
        <div className="rounded-2xl rounded-tl-sm bg-zinc-800 border border-zinc-700 px-4 py-3">
          {data && (
            <div className="flex items-center gap-2 mb-3 flex-wrap">
              <IntentBadge intent={data.intent} />
              {data.gemini_enabled && (
                <span className="rounded bg-emerald-900/50 border border-emerald-700 px-2 py-0.5 text-xs text-emerald-300 font-mono">
                  ✨ Gemini Enhanced
                </span>
              )}
            </div>
          )}
          <AgentText text={msg.text} />

          {data?.sources && data.sources.length > 0 && (
            <div className="mt-3 pt-3 border-t border-zinc-700">
              <p className="text-xs text-zinc-500 mb-1">Data sources used:</p>
              <div className="flex flex-wrap gap-1">
                {data.sources.map((s) => (
                  <span key={s} className="rounded bg-zinc-700 px-2 py-0.5 text-xs text-zinc-300">{s}</span>
                ))}
              </div>
            </div>
          )}
        </div>

        {data?.related_cves && data.related_cves.length > 0 && (
          <div className="mt-3">
            <p className="text-xs text-zinc-500 mb-2">Related CVEs:</p>
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

export default function AgentPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [envVendors, setEnvVendors] = useState<string[]>([]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  let msgCounter = useRef(0);

  useEffect(() => {
    try {
      const stored = localStorage.getItem("user_environment_vendors");
      if (stored) setEnvVendors(JSON.parse(stored));
    } catch { /* ignore */ }
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
    setMessages((prev) => prev.map((m) => (m.id === id ? { ...m, ...update } : m)));
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
      const err = e instanceof Error ? e.message : "Connection error — is the backend running?";
      updateMessage(agentId, { text: `⚠️ ${err}`, loading: false });
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
      {/* Header */}
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-xl font-bold">AI Threat Agent</h1>
          <p className="text-xs text-zinc-500">Conversational cyber threat intelligence — powered by ML + Gemini</p>
          {envVendors.length > 0 && (
            <p className="text-xs text-blue-400 mt-1">
              Environment: {envVendors.join(", ")}
            </p>
          )}
          {envVendors.length === 0 && (
            <Link href="/environment" className="text-xs text-zinc-600 hover:text-zinc-400 mt-1 block">
              Set up My Environment →
            </Link>
          )}
        </div>
        <Link href="/" className="text-xs text-zinc-500 hover:text-zinc-300 border border-zinc-700 px-3 py-1.5 rounded-lg">
          ← Dashboard
        </Link>
      </div>

      {/* Chat area */}
      <div className="flex-1 overflow-y-auto rounded-xl border border-zinc-800 bg-zinc-950 p-4 flex flex-col gap-5">
        {isEmpty ? (
          <div className="flex flex-col items-center justify-center h-full gap-6 text-center">
            <div>
              <div className="text-5xl mb-3">🛡️</div>
              <h2 className="text-lg font-semibold mb-1">Cyber Threat Prioritization Agent</h2>
              <p className="text-zinc-500 text-sm max-w-md">
                Ask me anything about the current CVE landscape. I combine ML models, CISA KEV, Exploit-DB,
                and threat intelligence to give you analyst-quality answers.
              </p>
            </div>
            <div className="w-full max-w-2xl">
              <p className="text-xs text-zinc-600 mb-3 uppercase tracking-wide">Try asking:</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {EXAMPLE_PROMPTS.map((p) => (
                  <button
                    key={p}
                    onClick={() => sendMessage(p)}
                    className="text-left text-sm rounded-xl border border-zinc-700 bg-zinc-900 px-4 py-3 hover:border-blue-500 hover:bg-zinc-800 transition-colors text-zinc-300"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          messages.map((msg) =>
            msg.role === "user" ? (
              <div key={msg.id} className="flex gap-3 justify-end">
                <div className="max-w-xl rounded-2xl rounded-tr-sm bg-blue-700 px-4 py-3 text-sm text-white">
                  {msg.text}
                </div>
                <div className="w-8 h-8 rounded-full bg-zinc-700 flex items-center justify-center text-sm flex-shrink-0 mt-1">
                  👤
                </div>
              </div>
            ) : (
              <AgentBubble key={msg.id} msg={msg} />
            )
          )
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="mt-3 flex gap-3 flex-shrink-0">
        <input
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKey}
          disabled={isLoading}
          placeholder="Ask about threats, CVEs, exploits, anomalies…"
          className="flex-1 rounded-xl border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm placeholder-zinc-500 focus:border-blue-500 focus:outline-none disabled:opacity-50"
        />
        <button
          onClick={() => sendMessage(input)}
          disabled={isLoading || !input.trim()}
          className="rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold hover:bg-blue-500 disabled:opacity-40 transition-colors"
        >
          {isLoading ? "…" : "Send"}
        </button>
      </div>
    </div>
  );
}
