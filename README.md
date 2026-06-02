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
- *"Tell me about APT28 and what systems they target"*
- *"What do we know about Lazarus Group?"*
- *"Show me the latest CVEs published recently"*
- *"Which CVEs are in the CISA KEV catalog?"*
- *"What anomalies did the model detect?"*
- *"Explain CVE-2026-24061"*
- *"Show me similar vulnerabilities to CVE-2026-24061"*
- *"What should a SOC analyst patch first?"*

The agent routes each question to the right ML tools, builds structured context, and generates a professional analyst response — powered by Gemini 2.5 Flash Lite when a key is configured, or template-based responses without one.

### My Environment

A dedicated profile page where you select the vendors and products you use (Apple, Cisco, Ivanti, etc.). The agent automatically identifies which threat actor groups target your stack and surfaces the most relevant CVEs — including a "what are the current threats on my environment?" query in the chat.

### Dashboard

- Search CVEs by ID or keyword
- Browse top highest-risk CVEs or latest by publication date
- Filter by: KEV only / Has Exploit / Ransomware / Anomaly
- Sort by: Risk Score or Date Published
- Full CVE detail: risk score, KEV status, exploit availability, ransomware flag, vendor/product, CISA patch deadline, anomaly flag, cluster, agent explanation, similar CVEs

---

## AI/ML Techniques Used

| Technique | Purpose |
|-----------|---------|
| TF-IDF Vectorisation | Convert CVE descriptions into numeric vectors |
| Cosine Similarity | Find semantically similar CVEs |
| K-Means Clustering (k=15, LSA reduced) | Group CVEs into vulnerability families |
| Isolation Forest | Detect anomalous CVE risk profiles |
| Composite Risk Scoring | Combine CVSS + KEV + Exploit + References into a 0–10 score |
| Intent Detection (regex routing) | Route natural-language queries to the right ML tools |
| CWE-based Rule Engine | Generate weakness-specific remediation advice |
| Gemini 2.5 Flash Lite (optional) | Generate analyst-quality natural-language explanations |

---

## Agent Architecture

```
User Question + Environment Context (vendors)
     ↓
Intent Detection (regex patterns → 13 intents)
     ↓
Tool Selection (one or more of):
  ├── Risk Scorer        → composite 0–10 score
  ├── Recommender        → TF-IDF similarity lookup
  ├── KEV data           → CISA Known Exploited Vulnerabilities
  ├── Exploit data       → Exploit-DB public exploit flag
  ├── Clustering         → K-Means cluster + keywords
  ├── Anomaly Detector   → Isolation Forest flag
  ├── Threat Actor DB    → 15 curated APT/ransomware groups
  └── Vendor Search      → product/vendor CVE matching
     ↓
Context Assembly (compact — never the full dataset)
     ↓
Gemini 2.5 Flash Lite (if key configured)
OR
Template-based offline response
     ↓
Analyst Answer + Related CVEs + Sources
```

**Supported intents:** `top_risks`, `cve_explanation`, `similar_cves`, `kev_query`, `exploit_query`, `anomaly_query`, `recommendation_query`, `search_query`, `summary_query`, `latest_query`, `system_query`, `ransomware_query`, `threat_actor_query`, `environment_query`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Next.js 15 + TypeScript + Tailwind CSS |
| ML / NLP | scikit-learn (TF-IDF, K-Means, TruncatedSVD, Isolation Forest, cosine similarity) |
| Generative AI | Google Gemini 2.5 Flash Lite (optional) |
| Data | NVD CVE API, CISA KEV, Exploit-DB, curated threat actor database |

---

## Data Sources

| Dataset | Source | Records |
|---------|--------|---------|
| NVD CVE | NIST National Vulnerability Database | 20,000 |
| CISA KEV | Known Exploited Vulnerabilities catalog | ~1,500 |
| Exploit-DB | Public exploit database | ~47,000 |
| Threat Actor DB | Curated APT/ransomware intelligence | 15 groups |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/cve/{id}` | Full CVE profile with risk score and explanation |
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
  "message": "What are the current threats on my environment?",
  "environment_vendors": ["Cisco", "Microsoft", "Ivanti"]
}

// Response
{
  "answer": "Threat assessment for your environment...",
  "intent": "environment_query",
  "sources": ["Threat Actor Database", "CISA KEV", "NVD CVE", "Risk Scorer"],
  "related_cves": [...],
  "gemini_enabled": true
}
```

`environment_vendors` is optional — omit it or pass `[]` for general queries.

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

The backend starts at `http://localhost:8000`. On first run it:
1. Merges NVD + KEV + Exploit-DB into an enriched dataset
2. Builds K-Means clusters and anomaly flags
3. Builds the TF-IDF similarity index

API docs available at `http://localhost:8000/docs`.

### 2. Gemini (Optional but recommended)

```bash
cp backend/.env.example backend/.env
# edit backend/.env and set GEMINI_API_KEY
```

`backend/.env` is gitignored — never commit it.

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_API_KEY` | *(none)* | API key from [aistudio.google.com](https://aistudio.google.com) |
| `GEMINI_MODEL` | `gemini-2.5-flash-lite` | Gemini model to use |

Without `GEMINI_API_KEY` the agent uses template-based responses (fully functional). With it, responses are AI-generated.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

| Page | URL |
|------|-----|
| Dashboard | `http://localhost:3000` |
| AI Agent | `http://localhost:3000/agent` |
| My Environment | `http://localhost:3000/environment` |

---

## Deployment

### Backend → Render

1. Create a **Web Service** on [render.com](https://render.com)
2. Connect the GitHub repo
3. Set:
   - **Root directory**: `backend`
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Add environment variable: `GEMINI_API_KEY=your-key`

### Frontend → Vercel

1. Import the repo on [vercel.com](https://vercel.com)
2. Set **Root directory**: `frontend`
3. Add environment variable: `NEXT_PUBLIC_API_URL=https://your-app.onrender.com`

---

## Project Structure

```
Cyber-Threat-Prioritization-Agent/
├── backend/
│   ├── main.py                    # FastAPI app (9 endpoints)
│   ├── requirements.txt
│   ├── .env.example               # Copy to .env and add GEMINI_API_KEY
│   ├── Agent/
│   │   ├── data_loader.py         # Merge NVD + KEV + Exploit-DB
│   │   ├── risk_scorer.py         # Composite 0–10 risk score
│   │   ├── clustering.py          # K-Means + TruncatedSVD (LSA)
│   │   ├── anomaly_detector.py    # Isolation Forest
│   │   ├── recommender.py         # TF-IDF cosine similarity index
│   │   ├── nlp_explainer.py       # Template NLP summaries
│   │   ├── chat_agent.py          # Intent routing + tool calls (13 intents)
│   │   ├── llm_client.py          # Gemini 2.5 Flash Lite + offline fallback
│   │   └── threat_actors.py       # Curated APT/ransomware group database
│   └── Data/                      # Source CSV datasets (NVD, KEV, Exploit-DB)
├── frontend/
│   ├── app/
│   │   ├── page.tsx               # Dashboard: search, filters, top risks, latest
│   │   ├── agent/page.tsx         # AI Agent chat interface
│   │   ├── environment/page.tsx   # My Environment: vendor selector + threat actors
│   │   └── cve/[id]/page.tsx      # CVE detail page
│   ├── components/
│   │   ├── CVECard.tsx            # CVE card with KEV/exploit/ransomware badges
│   │   ├── RiskBadge.tsx          # Risk level color badge
│   │   └── SimilarCVEList.tsx     # Similar CVE list
│   └── lib/api.ts                 # API client + TypeScript types
├── Scripts/                       # Data collection scripts (NVD, KEV, Exploit-DB, MITRE)
├── Similarity Algorithms/         # Cosine + Jaccard similarity implementations
└── docs/                          # Assignment documents and academic papers
```
