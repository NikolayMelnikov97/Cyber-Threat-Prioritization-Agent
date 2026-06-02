import re
from Agent import recommender, llm_client
from Agent.nlp_explainer import explain

# ── Intent detection ────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_INTENT_PATTERNS = [
    ("cve_explanation",    re.compile(r"\b(explain|what is|tell me about|describe|details? (of|about|on)|look up)\b.+CVE-\d{4}-\d+", re.I)),
    ("similar_cves",       re.compile(r"\b(similar|like|related to|same (type|family|cluster) as)\b", re.I)),
    ("kev_query",          re.compile(r"\b(kev|known exploited|cisa|actively exploit)", re.I)),
    ("exploit_query",      re.compile(r"\bexploit|\bpoc\b|\bproof.of.concept", re.I)),
    ("anomaly_query",      re.compile(r"\banomal|\bunusual|\boutlier|\bstrange|\bflagged", re.I)),
    ("summary_query",      re.compile(r"\b(summar|overview|landscape|dataset|overall|big picture|report)\b", re.I)),
    ("top_risks",          re.compile(r"\b(top|highest|most critical|biggest|worst|focus|priority|today)\b", re.I)),
    ("recommendation_query", re.compile(r"\b(recommend|what should|next step|action|patch|mitigat|response|fix|remediat)\b", re.I)),
    ("search_query",       re.compile(r"\b(search|find|look for|vulnerabilit(y|ies) (with|about|related))\b", re.I)),
]


_CVE_AGNOSTIC_INTENTS = {"top_risks", "recommendation_query", "summary_query", "search_query"}


def detect_intent(message: str) -> str:
    cve_ids = _CVE_RE.findall(message)
    matched = None
    for intent, pat in _INTENT_PATTERNS:
        if pat.search(message):
            if intent == "similar_cves" and not cve_ids:
                continue
            matched = intent
            break
    # If message contains a CVE ID and the matched intent is CVE-agnostic,
    # the user is almost certainly asking about that specific CVE.
    if cve_ids and (matched is None or matched in _CVE_AGNOSTIC_INTENTS):
        return "cve_explanation"
    if matched:
        return matched
    return "general_help"


# ── CWE-based recommendation rules ──────────────────────────────────────────

_CWE_ADVICE = {
    "CWE-89":  "Review all SQL input validation paths. Use parameterised queries and prepared statements.",
    "CWE-79":  "Audit output encoding across the application. Strengthen Content Security Policy and WAF rules.",
    "CWE-78":  "Remove or restrict OS command execution. Use allow-lists for any shell interaction.",
    "CWE-22":  "Validate and normalise all file paths server-side. Reject traversal sequences.",
    "CWE-434": "Restrict upload file types strictly. Store uploads outside the web root.",
    "CWE-502": "Disable deserialisation of untrusted data. Pin serialisation libraries.",
    "CWE-306": "Enforce authentication on all sensitive endpoints. Apply zero-trust principles.",
    "CWE-287": "Audit authentication flows. Enforce MFA for privileged access.",
    "CWE-798": "Rotate any hardcoded credentials immediately. Migrate to secrets management.",
    "CWE-20":  "Enforce strict input validation at all trust boundaries.",
    "CWE-119": "Prioritise buffer-overflow-safe language alternatives or enable modern compiler mitigations.",
    "CWE-125": "Enable AddressSanitizer in CI/CD and review bounds checks.",
    "CWE-416": "Audit memory management in the affected component. Prefer memory-safe alternatives.",
    "CWE-476": "Add null-pointer dereference guards. Review all pointer dereference paths.",
}

_RCE_KEYWORDS = {"remote code execution", "rce", "arbitrary code", "execute arbitrary", "code execution"}


def _cwe_advice(cwe: str | None) -> str:
    if not cwe:
        return ""
    for code, advice in _CWE_ADVICE.items():
        if code in (cwe or ""):
            return advice
    return ""


def _rce_advice(description: str) -> str:
    desc_low = (description or "").lower()
    if any(k in desc_low for k in _RCE_KEYWORDS):
        return "This vulnerability may enable Remote Code Execution. Immediately review internet-facing systems and apply network-level mitigations while the patch is prepared."
    return ""


# ── Context builders (compact — never send the full dataset) ─────────────────

def _cve_context(cve: dict) -> str:
    lines = [
        f"CVE ID: {cve.get('cve_id')}",
        f"Risk Score: {cve.get('risk_score', 0):.1f}/10  |  Risk Label: {cve.get('risk_label', 'Unknown')}",
        f"CVSS Base Score: {cve.get('severity_score', 0):.1f}  |  Severity: {cve.get('severity_label', 'N/A')}",
        f"CISA KEV: {'YES — actively exploited in the wild' if cve.get('is_kev') else 'No'}",
        f"Public Exploit: {'YES — exploit publicly available' if cve.get('has_exploit') else 'No'}",
        f"Anomaly: {'YES — unusual risk profile detected by ML model' if cve.get('is_anomaly') else 'No'}",
        f"CWE: {cve.get('cwe', 'Unknown')}",
        f"Cluster: {cve.get('cluster_label', 'Unknown')}",
        f"Published: {cve.get('published', 'Unknown')}",
        f"References: {cve.get('references_count', 0)}",
        f"Description: {(cve.get('description') or '')[:400]}",
    ]
    if cve.get("requiredAction"):
        lines.append(f"CISA Required Action: {cve['requiredAction']}")
    rce = _rce_advice(cve.get("description", ""))
    if rce:
        lines.append(f"RCE Note: {rce}")
    cwe_tip = _cwe_advice(cve.get("cwe"))
    if cwe_tip:
        lines.append(f"CWE-specific guidance: {cwe_tip}")
    return "\n".join(lines)


def _brief_cve(c: dict) -> str:
    kev = " [KEV]" if c.get("is_kev") else ""
    exp = " [EXPLOIT]" if c.get("has_exploit") else ""
    ano = " [ANOMALY]" if c.get("is_anomaly") else ""
    return f"  {c['cve_id']}: risk {c.get('risk_score',0):.1f}/10 ({c.get('risk_label','?')}){kev}{exp}{ano} — {(c.get('description') or '')[:120]}"


# ── Offline (template) response builders ─────────────────────────────────────

def _offline_top_risks(cves: list[dict]) -> str:
    lines = [f"Based on current threat intelligence data, here are the highest-priority vulnerabilities requiring immediate analyst attention:\n"]
    for i, c in enumerate(cves[:5], 1):
        flags = []
        if c.get("is_kev"):
            flags.append("actively exploited (CISA KEV)")
        if c.get("has_exploit"):
            flags.append("public exploit available")
        if c.get("is_anomaly"):
            flags.append("anomalous risk profile")
        flag_str = f" — {', '.join(flags)}" if flags else ""
        lines.append(f"{i}. {c['cve_id']} — Risk {c.get('risk_score',0):.1f}/10 ({c.get('risk_label','?')}){flag_str}")
        lines.append(f"   {(c.get('description') or '')[:150]}")
    lines.append("\nRecommendation: Prioritise CVEs flagged as KEV for immediate patching. Validate exploit availability for High and Critical items. Escalate anomalous entries for manual review.")
    return "\n".join(lines)


def _offline_cve_explanation(cve: dict, similar: list[dict]) -> str:
    text = explain(cve)
    if similar:
        text += "\n\nRelated vulnerabilities in the same cluster:\n"
        for s in similar[:3]:
            text += f"  • {s['cve_id']} (similarity: {s.get('similarity_score',0)*100:.0f}%, risk: {s.get('risk_score',0):.1f}/10)\n"
    return text


def _offline_kev(cves: list[dict]) -> str:
    if not cves:
        return "No KEV-listed vulnerabilities were found in the current dataset."
    lines = ["The following vulnerabilities are confirmed in the CISA Known Exploited Vulnerabilities catalog, meaning active exploitation has been observed in the wild:\n"]
    for c in cves[:8]:
        lines.append(f"  • {c['cve_id']} — Risk {c.get('risk_score',0):.1f}/10 | {(c.get('description') or '')[:120]}")
        if c.get("requiredAction"):
            lines.append(f"    CISA Action: {c['requiredAction'][:120]}")
    lines.append("\nImmediate action required for all KEV entries. Validate affected asset inventory and apply vendor patches without delay.")
    return "\n".join(lines)


def _offline_exploit(cves: list[dict]) -> str:
    if not cves:
        return "No CVEs with public exploits were found in the current dataset."
    lines = ["The following vulnerabilities have confirmed public exploits, raising the probability of exploitation significantly:\n"]
    for c in cves[:8]:
        lines.append(f"  • {c['cve_id']} — Risk {c.get('risk_score',0):.1f}/10 | {(c.get('description') or '')[:120]}")
    lines.append("\nFor all exploit-confirmed vulnerabilities: assume exploitation is technically feasible. Prioritise patching, apply compensating controls, and increase monitoring on affected systems.")
    return "\n".join(lines)


def _offline_anomaly(cves: list[dict]) -> str:
    if not cves:
        return "The anomaly detection model found no significant outliers in the current dataset."
    lines = [f"The Isolation Forest model flagged {len(cves)} CVEs with unusual risk profiles — these have atypical combinations of severity, KEV status, exploit availability, and references:\n"]
    for c in cves[:8]:
        lines.append(f"  • {c['cve_id']} — CVSS {c.get('severity_score',0):.1f}, Risk {c.get('risk_score',0):.1f}/10, KEV: {c.get('is_kev')}, Exploit: {c.get('has_exploit')}")
    lines.append("\nAnomaly-flagged CVEs warrant manual analyst review, as their true risk may not be fully captured by standard scoring metrics.")
    return "\n".join(lines)


def _offline_summary(stats: dict, top: list[dict]) -> str:
    return (
        f"Current threat landscape summary:\n\n"
        f"Total CVEs analysed: {stats['total']:,}\n"
        f"Critical risk: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}\n"
        f"Confirmed in CISA KEV: {stats['kev']}\n"
        f"Public exploits available: {stats['exploit']}\n"
        f"Anomalies detected: {stats['anomalies']}\n\n"
        f"Top priority CVEs right now:\n" +
        "\n".join(f"  • {c['cve_id']} — {c.get('risk_label','?')} ({c.get('risk_score',0):.1f}/10)" for c in top[:5]) +
        "\n\nFocus immediately on KEV-listed and exploit-confirmed vulnerabilities. Review anomalies for hidden risks."
    )


# ── Main agent function ───────────────────────────────────────────────────────

def handle(message: str) -> dict:
    intent = detect_intent(message)
    cve_ids = [m.upper() for m in _CVE_RE.findall(message)]
    related_cves: list[dict] = []
    sources: list[str] = []
    context_text = ""

    # ── top_risks ──
    if intent == "top_risks":
        top = recommender.get_top_risks(10)
        related_cves = top
        sources = ["NVD CVE", "CISA KEV", "Exploit-DB", "Risk Scorer"]
        context_text = "TOP RISK CVEs:\n" + "\n".join(_brief_cve(c) for c in top)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_top_risks(top)

    # ── cve_explanation ──
    elif intent == "cve_explanation" and cve_ids:
        cve_id = cve_ids[0]
        cve = recommender.get_profile(cve_id)
        if not cve:
            return {"answer": f"I couldn't find {cve_id} in the dataset. It may be outside the current 20k CVE window.", "intent": intent, "sources": [], "related_cves": []}
        similar = recommender.get_similar(cve_id, top_n=5)
        related_cves = [cve] + similar[:3]
        sources = ["NVD CVE", "CISA KEV", "Exploit-DB", "TF-IDF Similarity", "Risk Scorer", "Anomaly Detector"]
        context_text = _cve_context(cve) + "\n\nTOP SIMILAR CVEs:\n" + "\n".join(_brief_cve(s) for s in similar[:3])
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_cve_explanation(cve, similar)

    # ── similar_cves ──
    elif intent == "similar_cves" and cve_ids:
        cve_id = cve_ids[0]
        cve = recommender.get_profile(cve_id)
        if not cve:
            return {"answer": f"I couldn't find {cve_id} in the dataset.", "intent": intent, "sources": [], "related_cves": []}
        similar = recommender.get_similar(cve_id, top_n=8)
        related_cves = similar
        sources = ["TF-IDF Cosine Similarity", "NVD CVE", "Risk Scorer"]
        context_text = f"Finding similar CVEs to {cve_id}:\nTarget: {_cve_context(cve)}\n\nSIMILAR CVEs:\n" + "\n".join(_brief_cve(s) for s in similar)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = (
                f"Using TF-IDF cosine similarity, here are the most related vulnerabilities to {cve_id}:\n\n" +
                "\n".join(f"  {i+1}. {s['cve_id']} ({s.get('similarity_score',0)*100:.0f}% similar) — Risk {s.get('risk_score',0):.1f}/10\n     {(s.get('description') or '')[:150]}" for i, s in enumerate(similar[:5]))
            )

    # ── kev_query ──
    elif intent == "kev_query":
        df = recommender._df
        kev_cves = []
        if df is not None:
            kev_rows = df[df["is_kev"] == True].nlargest(10, "risk_score")
            kev_cves = [recommender._row_to_dict(row) for _, row in kev_rows.iterrows()]
        related_cves = kev_cves
        sources = ["CISA KEV", "NVD CVE", "Risk Scorer"]
        context_text = "CISA KEV CVEs in dataset:\n" + "\n".join(_brief_cve(c) for c in kev_cves)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_kev(kev_cves)

    # ── exploit_query ──
    elif intent == "exploit_query":
        df = recommender._df
        exp_cves = []
        if df is not None:
            exp_rows = df[df["has_exploit"] == True].nlargest(10, "risk_score")
            exp_cves = [recommender._row_to_dict(row) for _, row in exp_rows.iterrows()]
        related_cves = exp_cves
        sources = ["Exploit-DB", "NVD CVE", "Risk Scorer"]
        context_text = "CVEs with public exploits:\n" + "\n".join(_brief_cve(c) for c in exp_cves)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_exploit(exp_cves)

    # ── anomaly_query ──
    elif intent == "anomaly_query":
        df = recommender._df
        ano_cves = []
        if df is not None:
            ano_rows = df[df["is_anomaly"] == True].nlargest(10, "risk_score")
            ano_cves = [recommender._row_to_dict(row) for _, row in ano_rows.iterrows()]
        related_cves = ano_cves
        sources = ["Isolation Forest", "NVD CVE", "Risk Scorer"]
        context_text = f"Anomalous CVEs detected by Isolation Forest ({len(ano_cves)} shown):\n" + "\n".join(_brief_cve(c) for c in ano_cves)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_anomaly(ano_cves)

    # ── recommendation_query with specific CVE ──
    elif intent == "recommendation_query" and cve_ids:
        cve_id = cve_ids[0]
        cve = recommender.get_profile(cve_id)
        if not cve:
            return {"answer": f"I couldn't find {cve_id} in the dataset.", "intent": intent, "sources": [], "related_cves": []}
        related_cves = [cve]
        sources = ["NVD CVE", "CISA KEV", "Exploit-DB", "Anomaly Detector"]
        context_text = _cve_context(cve) + "\n\nTask: Generate specific, prioritised remediation recommendations for this CVE."
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = explain(cve)

    # ── recommendation_query (general) ──
    elif intent == "recommendation_query":
        top = recommender.get_top_risks(5)
        related_cves = top
        sources = ["Risk Scorer", "CISA KEV", "Exploit-DB", "Anomaly Detector"]
        context_text = "TOP PRIORITY CVEs FOR REMEDIATION:\n" + "\n".join(_brief_cve(c) for c in top)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_top_risks(top)

    # ── summary_query ──
    elif intent == "summary_query":
        df = recommender._df
        stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0, "exploit": 0, "anomalies": 0}
        if df is not None:
            stats["total"] = len(df)
            counts = df["risk_label"].value_counts()
            stats["critical"] = int(counts.get("Critical", 0))
            stats["high"] = int(counts.get("High", 0))
            stats["medium"] = int(counts.get("Medium", 0))
            stats["low"] = int(counts.get("Low", 0))
            stats["kev"] = int(df["is_kev"].sum())
            stats["exploit"] = int(df["has_exploit"].sum())
            stats["anomalies"] = int(df["is_anomaly"].sum())
        top = recommender.get_top_risks(5)
        related_cves = top
        sources = ["NVD CVE", "CISA KEV", "Exploit-DB", "Risk Scorer", "Isolation Forest", "K-Means Clustering"]
        context_text = f"DATASET SUMMARY:\n{stats}\n\nTOP RISKS:\n" + "\n".join(_brief_cve(c) for c in top)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_summary(stats, top)

    # ── search_query ──
    elif intent == "search_query":
        keywords = re.sub(r"(search|find|look for|vulnerabilities?)\s*", "", message, flags=re.I).strip()
        results = recommender.search_cves(keywords, limit=8)
        related_cves = results
        sources = ["NVD CVE", "TF-IDF Search"]
        context_text = f"Search results for '{keywords}':\n" + "\n".join(_brief_cve(c) for c in results)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = (
                f"Found {len(results)} CVEs matching '{keywords}':\n\n" +
                "\n".join(f"  • {c['cve_id']} — Risk {c.get('risk_score',0):.1f}/10 ({c.get('risk_label','?')}) — {(c.get('description') or '')[:150]}" for c in results)
            )

    # ── general_help ──
    else:
        df = recommender._df
        total = len(df) if df is not None else 0
        answer = (
            f"I'm your Cyber Threat Prioritization AI Agent. I have analysed {total:,} CVEs from NVD, enriched with CISA KEV and Exploit-DB data.\n\n"
            "You can ask me:\n"
            "  • What are the top threats I should focus on today?\n"
            "  • Explain CVE-2026-24061\n"
            "  • Which CVEs are in the CISA KEV catalog?\n"
            "  • Which vulnerabilities have public exploits?\n"
            "  • What anomalies did the model detect?\n"
            "  • Show me CVEs similar to CVE-2026-24061\n"
            "  • Summarise the threat landscape\n"
            "  • What should a SOC analyst do next?"
        )
        intent = "general_help"
        sources = []

    return {
        "answer": answer,
        "intent": intent,
        "sources": sources,
        "related_cves": related_cves[:6],
    }
