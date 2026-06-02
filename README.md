# Cyber Threat Prioritization Agent

An AI-powered conversational cyber threat intelligence system for SOC analysts. Built as a final project for the "AI & ML Innovation Workshop".

## What it does

The system combines classical ML, NLP, and generative AI into a full-stack application that helps security analysts prioritize CVE vulnerabilities, track threat actors, and understand their exposure based on the software they run.

### AI Agent (Conversational Interface)

Ask natural-language questions and get analyst-quality answers:

- *"What are the top threats I should focus on today?"*
- *"What are the current threats on my environment?"*
- *"What CVEs affect Apache / Cisco / Windows?"*
- *"Which CVEs have been used in ransomware attacks?"*
- *"Which CVEs are most likely to be exploited?"* (EPSS)
- *"Show me CVEs with verified remote exploits"*
- *"Which CVEs are remotely exploitable with no authentication?"*
- *"Tell me about APT28 and what systems they target"*
- *"What do we know about Lazarus Group?"*
- *"Show me the latest CVEs published recently"*
- *"Which CVEs are in the CISA KEV catalog?"*
- *"What anomalies did the model detect?"*
- *"Explain CVE-2026-24061"*
- *"What should a SOC analyst patch first?"*

The agent routes each question to the right ML tools, builds structured context, and generates a professional analyst response — powered by Gemini 2.5 Flash Lite when a key is configured, or template-based responses without one.

### My Environment

A dedicated profile page where you select the vendors and products you use (Apple, Cisco, Ivanti, etc.). The agent automatically identifies which threat actor groups target your stack and surfaces the most relevant CVEs.

### Dashboard

- Search CVEs by ID or keyword
- Browse top highest-risk CVEs or latest by publication date
- Filter by: KEV only / Has Exploit / Ransomware / Anomaly
- Sort by: Risk Score or Date Published
- Full CVE detail: risk score, EPSS score, exploit type/verification, CVSS attack profile, KEV status, ransomware flag, vendor/product, CISA patch deadline, anomaly flag, cluster, agent explanation, similar CVEs

---

## AI/ML Techniques Used

| Technique | Purpose |
|-----------|---------|
| TF-IDF Vectorisation | Convert CVE descriptions into numeric vectors |
| Cosine Similarity | Find semantically similar CVEs |
| K-Means Clustering (k=15, LSA reduced) | Group CVEs into vulnerability families |
| Isolation Forest | Detect anomalous CVE risk profiles |
| Composite Risk Scoring | Combine CVSS + KEV + EPSS + Exploit metadata + References |
| CVSS Vector Parsing | Extract attack vector, privileges, user interaction per CVE |
| Intent Detection (regex routing) | Route natural-language queries to the right ML tools |
| CWE-based Rule Engine | Generate weakness-specific remediation advice |
| Gemini 2.5 Flash Lite (optional) | Generate analyst-quality natural-language explanations |

---

## Agent Architecture

```
User Question + Environment Context (vendors)
     ↓
Intent Detection (regex patterns → 16 intents)
     ↓
Tool Selection (one or more of):
  ├── Risk Scorer        → composite 0–10 score (CVSS + KEV + EPSS + exploits)
  ├── Recommender        → TF-IDF similarity + CVSS/vendor search
  ├── KEV data           → CISA Known Exploited Vulnerabilities
  ├── EPSS data          → exploit probability scores (FIRST.org)
  ├── Exploit-DB         → verified/remote/platform exploit detail
  ├── Clustering         → K-Means cluster + keywords
  ├── Anomaly Detector   → Isolation Forest flag
  ├── Threat Actor DB    → 15 curated APT/ransomware groups
  ├── OSV packages       → open-source package vulnerability mapping
  └── MITRE ATT&CK       → technique-to-CVE links
     ↓
Context Assembly (compact — never the full dataset)
     ↓
Gemini 2.5 Flash Lite (if key configured)  OR  Template-based offline response
     ↓
Analyst Answer + Related CVEs + Sources
```

**Supported intents:** `top_risks`, `cve_explanation`, `similar_cves`, `kev_query`, `epss_query`, `exploit_query`, `exploit_detail_query`, `cvss_filter_query`, `anomaly_query`, `recommendation_query`, `search_query`, `summary_query`, `latest_query`, `system_query`, `ransomware_query`, `threat_actor_query`, `environment_query`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Next.js 15 + TypeScript + Tailwind CSS |
| ML / NLP | scikit-learn (TF-IDF, K-Means, TruncatedSVD, Isolation Forest, cosine similarity) |
| Generative AI | Google Gemini 2.5 Flash Lite (optional) |
| Data | NVD, CISA KEV, Exploit-DB, EPSS, OSV, MITRE ATT&CK, curated threat actor database |

---

## Data Sources

| Dataset | Source | Records | Refresh |
|---------|--------|---------|---------|
| NVD CVE | NIST National Vulnerability Database | 20,000 | `Scripts/fetch_CVE.py` |
| CISA KEV | Known Exploited Vulnerabilities catalog | ~1,500 | `Scripts/fetch_kev.py` |
| Exploit-DB | Public exploit database | ~47,000 | `Scripts/fetch_exploitdb_csv.py` |
| EPSS | Exploit Prediction Scoring System (FIRST.org) | 337,000+ CVEs | `Scripts/fetch_epss.py` |
| OSV | Open Source Vulnerabilities (Google) | ~279,000 package entries | `Scripts/fetch_osv.py` |
| MITRE ATT&CK | Enterprise attack framework + CVE links | ~600 techniques | `Scripts/fetch_mitre_attack.py` + `parse_mitre_attack.py` |
| Threat Actor DB | Curated APT/ransomware intelligence | 15 groups | `backend/Agent/threat_actors.py` |

---

## Risk Score Formula

```
risk_score = min(
  0.5 × CVSS_base_score
  + 2.0 × is_kev                           (actively exploited by CISA)
  + epss_score × 2.0                        (exploit probability, 0–1)
  + exploit_verified × 1.2                  (verified exploit in Exploit-DB)
  + (exploit_type == "remote") × 0.5        (remote exploit bonus)
  + has_exploit × 0.3                       (any exploit)  [all capped at 1.5]
  + min(references_count / 20, 1) × 5.0    (community attention)
, 10)
```

Labels: Critical ≥ 9.0 / High ≥ 7.0 / Medium ≥ 4.0 / Low < 4.0

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/cve/{id}` | Full CVE profile with 36 enriched fields |
| GET | `/cve/{id}/similar?n=5` | Top N similar CVEs (TF-IDF cosine similarity) |
| GET | `/top-risks?n=20` | Top N highest-risk CVEs |
| GET | `/latest-cves?n=20` | Latest N CVEs sorted by publication date |
| GET | `/search?q=...` | Search by CVE ID or keyword |
| GET | `/vendors` | Unique vendor/product pairs from CISA KEV |
| GET | `/threat-actors?vendor=X` | All threat actors (optionally filtered by vendor) |
| **POST** | **`/agent/chat`** | **Conversational AI agent** |

### `/agent/chat` request / response

```json
// Request
{
  "message": "Which CVEs are most likely to be exploited?",
  "environment_vendors": ["Cisco", "Microsoft", "Ivanti"]
}

// Response
{
  "answer": "Based on EPSS scores...",
  "intent": "epss_query",
  "sources": ["EPSS (FIRST.org)", "NVD CVE", "Risk Scorer"],
  "related_cves": [...],
  "gemini_enabled": true
}
```

`environment_vendors` is optional — pass your tech stack for environment-aware answers.

---

## Local Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- (Optional) Google Gemini API key from [aistudio.google.com](https://aistudio.google.com)

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

The backend starts at `http://localhost:8000`. On first run it merges all data sources, builds ML models, and creates a TF-IDF similarity index (~30 seconds).

API docs at `http://localhost:8000/docs`.

### 2. Download additional datasets (recommended)

```bash
cd Scripts
python fetch_epss.py          # EPSS exploit probability scores (~2 MB)
python fetch_mitre_attack.py  # MITRE ATT&CK STIX JSON (~25 MB)
python parse_mitre_attack.py  # Parse ATT&CK → CVE links
python fetch_osv.py           # OSV open source vulns (~300 MB, takes ~5 min)
```

After running, delete `backend/Data/enriched_cves.csv` and restart the backend to rebuild with the new data.

### 3. Gemini (Optional but recommended)

```bash
cp backend/.env.example backend/.env
# edit backend/.env and set GEMINI_API_KEY
```

`backend/.env` is gitignored — never commit it.

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | *(none)* | API key from [aistudio.google.com](https://aistudio.google.com) |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model to use |

### 4. Frontend

```bash
cd frontend
npm install
npm run dev
```

| Page | URL |
|------|-----|
| Dashboard | `http://localhost:3000` |
| AI Agent | `http://localhost:3000/agent` |
| My Environment | `http://localhost:3000/environment` |

---

## Deployment

### Backend → Render

1. Create a **Web Service** on [render.com](https://render.com)
2. Connect the GitHub repo, set **Root directory**: `backend`
3. **Build command**: `pip install -r requirements.txt`
4. **Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add environment variable: `GEMINI_API_KEY=your-key`

### Frontend → Vercel

1. Import the repo on [vercel.com](https://vercel.com), set **Root directory**: `frontend`
2. Add environment variable: `NEXT_PUBLIC_API_URL=https://your-app.onrender.com`

---

## Project Structure

```
Cyber-Threat-Prioritization-Agent/
├── backend/
│   ├── main.py                    # FastAPI app (9 endpoints)
│   ├── requirements.txt
│   ├── .env.example               # Copy to .env and add GEMINI_API_KEY
│   ├── Agent/
│   │   ├── data_loader.py         # Merge all data sources → 36-column enriched CSV
│   │   ├── risk_scorer.py         # Composite 0–10 risk formula (CVSS+KEV+EPSS+exploits)
│   │   ├── clustering.py          # K-Means + TruncatedSVD (LSA)
│   │   ├── anomaly_detector.py    # Isolation Forest
│   │   ├── recommender.py         # TF-IDF index + vendor/CVSS/package search
│   │   ├── nlp_explainer.py       # Template NLP summaries with EPSS + CVSS context
│   │   ├── chat_agent.py          # Intent routing + 16 intent handlers
│   │   ├── llm_client.py          # Gemini 2.5 Flash Lite + offline fallback
│   │   └── threat_actors.py       # Curated APT/ransomware group database (15 groups)
│   └── Data/                      # CSV datasets (NVD, KEV, Exploit-DB, EPSS, OSV, MITRE)
├── frontend/
│   ├── app/
│   │   ├── page.tsx               # Dashboard: search, filters, sort, top/latest
│   │   ├── agent/page.tsx         # AI Agent chat interface
│   │   ├── environment/page.tsx   # My Environment: vendor selector + threat actors
│   │   └── cve/[id]/page.tsx      # CVE detail with all 36 enriched fields
│   ├── components/
│   │   ├── CVECard.tsx            # CVE card: KEV/EXPLOIT/RANSOM/EPSS badges
│   │   ├── RiskBadge.tsx          # Risk level color badge
│   │   └── SimilarCVEList.tsx     # Similar CVE list
│   └── lib/api.ts                 # API client + TypeScript types (36 CVE fields)
└── Scripts/
    ├── fetch_CVE.py               # NVD CVE API → latest_20k_cves_from_2026.csv
    ├── fetch_kev.py               # CISA KEV → cisa_kev.csv
    ├── fetch_exploitdb_csv.py     # Exploit-DB → exploitdb.csv
    ├── fetch_epss.py              # EPSS scores → epss_scores.csv
    ├── fetch_osv.py               # OSV packages → osv_packages.csv
    ├── fetch_mitre_attack.py      # MITRE ATT&CK STIX → enterprise-attack.json
    └── parse_mitre_attack.py      # Parse ATT&CK JSON → mitre_cve_links.csv
```
