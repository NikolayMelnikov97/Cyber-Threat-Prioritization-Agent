import re
from Agent import recommender, llm_client
from Agent.nlp_explainer import explain
from Agent import threat_actors as ta_module

# ── Intent detection ────────────────────────────────────────────────────────

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

_INTENT_PATTERNS = [
    ("cve_explanation",    re.compile(r"\b(explain|what is|tell me about|describe|details? (of|about|on)|look up)\b.+CVE-\d{4}-\d+", re.I)),
    ("similar_cves",       re.compile(r"\b(similar|like|related to|same (type|family|cluster) as)\b", re.I)),
    ("kev_query",          re.compile(r"\b(kev|known exploited|cisa|actively exploit)", re.I)),
    ("exploit_query",      re.compile(r"\bexploit|\bpoc\b|\bproof.of.concept", re.I)),
    ("anomaly_query",      re.compile(r"\banomal|\bunusual|\boutlier|\bstrange|\bflagged", re.I)),
    ("open_project_question", re.compile(r"\b(presentation|assignment|project|limitation|how (does|do|is|are) (this|the|it|your)|what (is|are) (this|the project)|teach|course|workshop|explain (the |this )?(system|architecture|algorithm|model|approach|method|technique))\b", re.I)),
    ("system_query",       re.compile(r"\b(affect(s|ing)?|vulnerabilit(y|ies) (for|in|on|affecting))\b|\b(apache|nginx|tomcat|spring|log4j|windows|linux|android|macos|ubuntu|debian|iis|active directory|exchange server|cisco|fortinet|ivanti|citrix|vmware|juniper|palo alto|solarwinds|atlassian|zoho|okta|sharepoint|office 365|exchange|kubernetes|docker)\b", re.I)),
    ("ransomware_query",   re.compile(r"\b(ransomware|ransom(ware)?|lockbit|blackcat|clop|alphv|ryuk|encrypt(ed|ion) attack)\b", re.I)),
    ("threat_actor_query", re.compile(r"\b(apt|threat actor|hacker(s)?|cyber group|gang|group(s)?|nation.?state|lazarus|fancy bear|cozy bear|sandworm|volt typhoon|salt typhoon|fin7|clop|lockbit|blackcat|scattered spider|alphv|apt28|apt29|apt40|apt41|apt1|muddywater|who (is|are) (behind|targeting|attacking)|which group|targeting \w+)\b", re.I)),
    ("latest_query",       re.compile(r"\b(latest|newest|recent|new(est)?|just (published|added|disclosed)|today'?s? (cve|vuln)|new attack|any new)\b", re.I)),
    ("summary_query",      re.compile(r"\b(summar|overview|landscape|dataset|overall|big picture|report|happening|cybersecurity|cyber security)\b", re.I)),
    ("top_risks",          re.compile(r"\b(top|highest|most critical|biggest|worst|focus|priority|today|critical vulnerabilit|dangerous|severe|urgent|which.*critical|which.*vulnerabilit)\b", re.I)),
    ("recommendation_query", re.compile(r"\b(recommend|what should|next step|action|patch|mitigat|response|fix|remediat|worried about|should i)\b", re.I)),
    ("environment_query",  re.compile(r"\b(my environment|my stack|my system|my infrastructure|threats? (on|to|for|in) my|current threats?|what.*(affect|target|attack).*my|relevant.*my|my.*exposure)\b", re.I)),
    ("search_query",       re.compile(r"\b(search|find|look for|show me|list.*cve|vulnerabilit(y|ies) (with|about|related))\b", re.I)),
]

_CVE_AGNOSTIC_INTENTS = {
    "top_risks", "recommendation_query", "summary_query", "search_query",
    "latest_query", "system_query", "ransomware_query", "threat_actor_query",
    "environment_query",
}


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
    # the user is asking about that specific CVE.
    if cve_ids and (matched is None or matched in _CVE_AGNOSTIC_INTENTS):
        return "cve_explanation"
    if matched:
        return matched
    # Any other question → open-ended project-aware handling
    return "open_project_question"


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


# ── Project context builder ──────────────────────────────────────────────────

def _build_project_context() -> str:
    df = recommender._df
    stats_lines = ""
    if df is not None:
        counts = df["risk_label"].value_counts()
        stats_lines = (
            f"\nLIVE DATASET STATS (as of current run):\n"
            f"  Total CVEs analysed: {len(df):,}\n"
            f"  Critical: {int(counts.get('Critical', 0))} | High: {int(counts.get('High', 0))} | "
            f"Medium: {int(counts.get('Medium', 0))} | Low: {int(counts.get('Low', 0))}\n"
            f"  In CISA KEV (actively exploited): {int(df['is_kev'].sum())}\n"
            f"  With public exploits (Exploit-DB): {int(df['has_exploit'].sum())}\n"
            f"  Anomalies detected by Isolation Forest: {int(df['is_anomaly'].sum())}\n"
        )

    return f"""PROJECT: Cyber Threat Prioritization Agent
COURSE: AI & ML Innovation Workshop — Final Project

GOAL:
An AI-powered full-stack system that helps SOC analysts prioritize CVE vulnerabilities
based on real-world risk — not just CVSS scores alone. The system combines multiple
data sources and ML techniques to surface the vulnerabilities that matter most.

DATASETS USED:
  1. NVD CVE (National Vulnerability Database): 20,000 most recent CVEs from 2026 and prior years.
     Fields: CVE ID, CVSS base score, description, CWE weakness type, published date, references count.
  2. CISA KEV (Known Exploited Vulnerabilities catalog): ~1,200 CVEs confirmed as actively exploited in the wild.
     Adding KEV status adds +2.0 points to the composite risk score.
  3. Exploit-DB: ~50,000 public exploits. Used to flag CVEs with publicly available proof-of-concept code.
     Having a public exploit adds +1.5 points to the composite risk score.
  4. MITRE ATT&CK Enterprise: attack technique framework (downloaded for context and future use).

ML / NLP METHODS:
  - TF-IDF (Term Frequency-Inverse Document Frequency): converts CVE text descriptions into numerical
    vectors. Captures which terms are rare and informative across the corpus.
  - Cosine Similarity: measures the angle between two TF-IDF vectors (range 0–1).
    Higher = more semantically similar descriptions. Used to find related CVEs.
  - Jaccard Similarity: measures the ratio of shared words to total words between two CVE descriptions.
    Better for exact keyword overlap; was compared against cosine in Assignment 2.
    Cosine generally outperforms Jaccard for semantic similarity; Jaccard better for categorical matching.
  - K-Means Clustering (k=15): groups CVEs into 15 vulnerability families based on description similarity.
    Uses TruncatedSVD (LSA) to reduce TF-IDF dimensions to 50 before clustering for efficiency.
    Each cluster is labelled with its top-5 keywords (e.g., "sql, injection, authentication, bypass").
  - Isolation Forest (contamination=5%): detects CVEs with anomalous risk profiles —
    unusual combinations of CVSS score, KEV status, exploit availability, and references count.
    An anomaly means the CVE stands out statistically from peers with similar scores.

RISK SCORING FORMULA (composite, 0–10 scale):
  risk_score = min(
    0.5 × CVSS_base_score
    + 2.0 × is_kev        (boolean: is it in CISA KEV?)
    + 1.5 × has_exploit   (boolean: is there a public exploit?)
    + 0.5 × min(references_count / 20, 1) × 10  (community attention, capped)
  , 10)
  Labels: Critical (≥9.0), High (≥7.0), Medium (≥4.0), Low (<4.0)
  Why this matters: a CVSS 7.0 CVE with no KEV/exploit may be lower priority than
  a CVSS 5.0 CVE that is actively exploited in the wild.

AGENT CAPABILITIES (what users can ask):
  - Top-priority CVEs right now
  - Full profile and explanation for any specific CVE
  - Similar CVEs using TF-IDF cosine similarity
  - CVEs in the CISA KEV catalog
  - CVEs with public exploits from Exploit-DB
  - Anomalies flagged by Isolation Forest
  - Keyword or CVE ID search
  - Threat landscape summary
  - Analyst remediation recommendations
  - Latest CVEs sorted by publication date
  - System-specific vulnerabilities (e.g. "what CVEs affect Apache?")
  - CVEs associated with ransomware campaigns
  - Threat actor profiles (APT groups, ransomware gangs, nation-state actors)

ARCHITECTURE:
  User question → Intent detection (regex) → Tool selection (ML modules) →
  Compact context assembly → Gemini 1.5 Flash → Analyst answer + related CVEs

TECH STACK:
  Backend: FastAPI (Python) | Frontend: Next.js 15 + TypeScript + Tailwind CSS
  ML: scikit-learn (TF-IDF, K-Means, TruncatedSVD, Isolation Forest, cosine similarity)
  LLM: Google Gemini (gemini-2.5-flash-lite) for natural language generation
  Data: CSV files (NVD, KEV, ExploitDB) — no live internet queries during runtime
{stats_lines}
LIMITATIONS:
  - Based on pre-downloaded static datasets, not a live threat feed
  - NVD dataset covers 20,000 CVEs — very old or very new CVEs may not be present
  - Risk score is a heuristic model, not a certified security standard
  - Gemini responses are AI-generated — always verify critical decisions with official sources
  - The system does not perform asset discovery or network scanning
"""


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
    if cve.get("vendorProject"):
        vendor_str = cve["vendorProject"]
        if cve.get("product"):
            vendor_str += f" / {cve['product']}"
        lines.append(f"Vendor/Product: {vendor_str}")
    if cve.get("dateAdded"):
        lines.append(f"KEV Date Added: {str(cve['dateAdded'])[:10]}")
    if cve.get("dueDate"):
        lines.append(f"CISA Patch Due: {str(cve['dueDate'])[:10]}")
    if (cve.get("ransomware_campaign") or "").strip() == "Known":
        lines.append("RANSOMWARE: Confirmed use in ransomware campaigns (CISA)")
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


def _brief_cve_vendor(c: dict) -> str:
    kev = " [KEV]" if c.get("is_kev") else ""
    exp = " [EXPLOIT]" if c.get("has_exploit") else ""
    vendor = f" [{c.get('vendorProject','')}]" if c.get("vendorProject") else ""
    return f"  {c['cve_id']}{vendor}: risk {c.get('risk_score',0):.1f}/10{kev}{exp} — {(c.get('description') or '')[:100]}"


# ── Offline (template) response builders ─────────────────────────────────────

def _offline_top_risks(cves: list[dict]) -> str:
    lines = ["Based on current threat intelligence data, here are the highest-priority vulnerabilities requiring immediate analyst attention:\n"]
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


def _offline_latest(cves: list[dict]) -> str:
    lines = ["Here are the most recently published vulnerabilities in the dataset:\n"]
    for i, c in enumerate(cves[:10], 1):
        pub = (c.get("published") or "")[:10]
        kev = " [KEV]" if c.get("is_kev") else ""
        exp = " [EXPLOIT]" if c.get("has_exploit") else ""
        lines.append(f"{i}. {c['cve_id']} — Published: {pub} | Risk: {c.get('risk_score',0):.1f}/10 ({c.get('risk_label','?')}){kev}{exp}")
        lines.append(f"   {(c.get('description') or '')[:150]}")
    lines.append("\nNote: newer CVEs are not necessarily higher risk — cross-check with KEV status and exploit availability before prioritising.")
    return "\n".join(lines)


def _offline_system_query(vendor: str, cves: list[dict]) -> str:
    if not cves:
        return f"No CVEs found matching '{vendor}' in the current dataset. This vendor may not appear in the CISA KEV catalog or the NVD window."
    lines = [f"Vulnerabilities affecting {vendor} (sorted by risk score):\n"]
    for c in cves[:8]:
        kev = " [KEV]" if c.get("is_kev") else ""
        exp = " [EXPLOIT]" if c.get("has_exploit") else ""
        lines.append(f"  • {c['cve_id']}: Risk {c.get('risk_score',0):.1f}/10{kev}{exp} — {(c.get('description') or '')[:150]}")
    lines.append("\nFocus on KEV-listed and exploit-confirmed CVEs for this vendor first.")
    return "\n".join(lines)


def _offline_ransomware(cves: list[dict]) -> str:
    if not cves:
        return "No CVEs with confirmed ransomware campaign association were found in the current dataset."
    lines = [f"The following {len(cves)} CVEs are associated with known ransomware campaigns (per CISA KEV):\n"]
    for c in cves[:10]:
        vendor = c.get("vendorProject") or ""
        vendor_str = f" [{vendor}]" if vendor else ""
        lines.append(f"  • {c['cve_id']}{vendor_str} — Risk {c.get('risk_score',0):.1f}/10 — {(c.get('description') or '')[:120]}")
        if c.get("dueDate"):
            lines.append(f"    CISA Patch Due: {str(c['dueDate'])[:10]}")
    lines.append("\nCVEs associated with ransomware campaigns are the highest-priority patching targets — these are actively used for financially motivated attacks.")
    return "\n".join(lines)


def _offline_environment(vendors: list[str], actors: list[dict], cves: list[dict]) -> str:
    if not vendors:
        return (
            "Your environment is not configured yet. "
            "Go to the 'My Environment' page and select the vendors/products you use. "
            "The agent will then show you which threat actors target your stack and which CVEs are relevant."
        )
    lines = [f"Threat assessment for your environment ({', '.join(vendors)}):\n"]
    if actors:
        lines.append(f"THREAT ACTORS TARGETING YOUR STACK ({len(actors)} groups):")
        for ta in actors[:5]:
            matched = ta.get("matched_vendors", [])
            lines.append(f"  • {ta['name']} ({ta['country']}) — targets {', '.join(matched)}")
            lines.append(f"    {ta['description'][:120]}")
        lines.append("")
    else:
        lines.append("No known threat actors specifically target your selected vendors.\n")
    if cves:
        lines.append(f"TOP RELEVANT CVEs FOR YOUR ENVIRONMENT ({len(cves)} found):")
        for c in cves[:6]:
            kev = " [KEV]" if c.get("is_kev") else ""
            exp = " [EXPLOIT]" if c.get("has_exploit") else ""
            lines.append(f"  • {c['cve_id']}: Risk {c.get('risk_score',0):.1f}/10{kev}{exp} — {(c.get('description') or '')[:120]}")
    else:
        lines.append("No specific CVEs found for your vendors in the current dataset.")
    lines.append("\nFor full details, visit the 'My Environment' page.")
    return "\n".join(lines)


def _offline_threat_actor(actors: list[dict]) -> str:
    if not actors:
        return "No matching threat actor found. Try asking about APT28, APT29, Lazarus Group, LockBit, Volt Typhoon, Scattered Spider, or similar groups."
    lines = []
    for ta in actors[:2]:
        aliases_str = ", ".join(ta["aliases"][:3])
        lines.append(f"THREAT ACTOR: {ta['name']} (also known as: {aliases_str})")
        lines.append(f"Origin: {ta['country']} | MITRE ATT&CK ID: {ta.get('mitre_id','N/A')}")
        lines.append(f"Profile: {ta['description']}")
        lines.append(f"Primary targets: {', '.join(ta['target_sectors'][:5])}")
        lines.append(f"Known to target: {', '.join(ta['target_vendors'][:6])}")
        lines.append(f"Notable campaigns: {', '.join(ta['notable_campaigns'][:3])}")
        if ta.get("matched_vendors"):
            lines.append(f"RELEVANCE: This group targets {', '.join(ta['matched_vendors'])} which are in your environment.")
        lines.append("")
    return "\n".join(lines)


def _offline_open_question() -> str:
    df = recommender._df
    total = len(df) if df is not None else 0
    return (
        f"This is the Cyber Threat Prioritization Agent — an AI-powered system that helps SOC analysts "
        f"prioritize {total:,} CVEs from the NVD, enriched with CISA KEV and Exploit-DB data.\n\n"
        "The project combines several ML/NLP techniques:\n"
        "  • TF-IDF + Cosine Similarity — to find semantically similar vulnerabilities\n"
        "  • K-Means Clustering (k=15) — to group CVEs into vulnerability families\n"
        "  • Isolation Forest — to detect anomalous risk profiles\n"
        "  • Composite Risk Scoring — combining CVSS, KEV status, exploit availability, and references\n\n"
        "Unlike a simple CVE database, this system ranks vulnerabilities by real-world risk, not just CVSS score alone. "
        "A CVE with CVSS 5.0 that is actively exploited in the wild may rank higher than a CVSS 9.0 with no known exploitation.\n\n"
        "For richer, Gemini-powered answers to project and architecture questions, "
        "configure GEMINI_API_KEY in backend/.env and restart the server.\n\n"
        "You can also ask me:\n"
        "  • What are the top threats today?\n"
        "  • Which CVEs are in the CISA KEV catalog?\n"
        "  • What anomalies did the model detect?\n"
        "  • Explain any specific CVE (e.g. CVE-2026-24061)"
    )


# ── Open-question context for Gemini ─────────────────────────────────────────

_OPEN_QUESTION_INSTRUCTION = """
The user is asking a general question about this project, its methods, architecture, datasets, or cybersecurity concepts.

Answer based strictly on the project information provided above.
- If the question is about this project, its datasets, ML methods, or cybersecurity concepts → answer clearly and helpfully.
- If the question is completely unrelated to cybersecurity or this project (e.g. cooking, sports, politics) → politely decline and redirect to the project.
- Do not invent CVE IDs, vulnerability data, or facts not present in the context.
- Do not claim the system has live internet access or real-time data.
- You may explain ML concepts (TF-IDF, cosine similarity, K-Means, Isolation Forest) in plain language.
- You may help the user prepare a presentation or explain the project's value.
"""


# ── Main agent function ───────────────────────────────────────────────────────

def handle(message: str, environment_vendors: list[str] | None = None) -> dict:
    intent = detect_intent(message)
    cve_ids = [m.upper() for m in _CVE_RE.findall(message)]
    env_vendors: list[str] = environment_vendors or []
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

    # ── environment_query ──
    elif intent == "environment_query":
        relevant_actors = ta_module.get_relevant_for_vendors(env_vendors) if env_vendors else []
        seen_ids: set[str] = set()
        env_cves: list[dict] = []
        for vendor in env_vendors:
            for c in recommender.search_by_vendor(vendor, limit=5):
                if c["cve_id"] not in seen_ids:
                    seen_ids.add(c["cve_id"])
                    env_cves.append(c)
        env_cves.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        related_cves = env_cves[:6]
        sources = ["Threat Actor Database", "CISA KEV", "NVD CVE", "Risk Scorer"]
        vendor_str = ", ".join(env_vendors) if env_vendors else "none configured"
        actor_ctx = "\n".join(
            f"  - {ta['name']} ({ta['country']}): targets {', '.join(ta.get('matched_vendors', []))}"
            for ta in relevant_actors[:5]
        ) or "  None identified for your stack."
        cve_ctx = "\n".join(_brief_cve_vendor(c) for c in env_cves[:8]) or "  No CVEs found."
        context_text = (
            f"USER ENVIRONMENT: {vendor_str}\n\n"
            f"THREAT ACTORS TARGETING THIS ENVIRONMENT:\n{actor_ctx}\n\n"
            f"TOP CVEs RELEVANT TO THIS ENVIRONMENT:\n{cve_ctx}"
        )
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_environment(env_vendors, relevant_actors, env_cves)

    # ── latest_query ──
    elif intent == "latest_query":
        latest = recommender.get_latest(15)
        related_cves = latest[:6]
        sources = ["NVD CVE", "Risk Scorer"]
        context_text = "LATEST PUBLISHED CVEs (by date):\n" + "\n".join(_brief_cve(c) for c in latest)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_latest(latest)

    # ── system_query ──
    elif intent == "system_query":
        vendor_extract = re.sub(
            r"\b(what|which|show|list|find|are|there|any|cves?|vulnerabilit(y|ies)|affecting|affect|for|in|on|targeting|target|about)\b",
            "", message, flags=re.I,
        ).strip(" ?.,")
        vendor_extract = vendor_extract.strip() or message.strip()
        results = recommender.search_by_vendor(vendor_extract, limit=15)
        if not results:
            results = recommender.search_cves(vendor_extract, limit=15)
        related_cves = results[:6]
        sources = ["CISA KEV", "NVD CVE", "Risk Scorer"]
        context_text = f"CVEs affecting '{vendor_extract}':\n" + "\n".join(_brief_cve_vendor(c) for c in results)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_system_query(vendor_extract, results)

    # ── ransomware_query ──
    elif intent == "ransomware_query":
        df = recommender._df
        ransomware_cves: list[dict] = []
        if df is not None:
            ransomware_rows = df[df["ransomware_campaign"] == "Known"].nlargest(15, "risk_score")
            ransomware_cves = [recommender._row_to_dict(row) for _, row in ransomware_rows.iterrows()]
        related_cves = ransomware_cves[:6]
        sources = ["CISA KEV", "NVD CVE", "Risk Scorer"]
        context_text = f"CVEs with known ransomware campaign use ({len(ransomware_cves)} found):\n" + "\n".join(_brief_cve_vendor(c) for c in ransomware_cves)
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_ransomware(ransomware_cves)

    # ── threat_actor_query ──
    elif intent == "threat_actor_query":
        msg_lower = message.lower()
        actors = [
            ta for ta in ta_module.get_all()
            if any(alias.lower() in msg_lower for alias in [ta["name"]] + ta.get("aliases", []))
        ]
        if not actors:
            actors = ta_module.get_all()[:5]
        actor_vendors: list[str] = []
        for ta in actors[:2]:
            actor_vendors.extend(ta.get("target_vendors", []))
        seen_ids: set[str] = set()
        unique_cves: list[dict] = []
        for vendor in set(actor_vendors):
            for c in recommender.search_by_vendor(vendor, limit=3):
                if c["cve_id"] not in seen_ids:
                    seen_ids.add(c["cve_id"])
                    unique_cves.append(c)
        unique_cves.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        related_cves = unique_cves[:6]
        sources = ["Threat Actor Database", "CISA KEV", "NVD CVE", "Risk Scorer"]
        actor_ctx = "\n\n".join(
            f"ACTOR: {ta['name']} ({ta['country']})\nTargets: {', '.join(ta['target_vendors'])}\nCampaigns: {', '.join(ta['notable_campaigns'][:2])}"
            for ta in actors[:2]
        )
        context_text = (
            f"THREAT ACTOR INTELLIGENCE:\n{actor_ctx}\n\n"
            f"RELEVANT CVEs IN DATASET:\n" + "\n".join(_brief_cve_vendor(c) for c in unique_cves[:8])
        )
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_threat_actor(actors)

    # ── open_project_question — flexible fallback for any other question ──
    else:
        intent = "open_project_question"
        sources = ["Project Knowledge Base", "Live Dataset Stats"]
        project_ctx = _build_project_context()
        context_text = project_ctx + _OPEN_QUESTION_INSTRUCTION
        if llm_client.is_enabled():
            answer = llm_client.generate(context_text, message)
        else:
            answer = _offline_open_question()

    return {
        "answer": answer,
        "intent": intent,
        "sources": sources,
        "related_cves": related_cves[:6],
    }
