# Cyber Threat Prioritization Agent

An AI-powered conversational cyber threat intelligence system for cybersecurity analysts. Built as a final project for the "AI & ML Innovation Workshop".

## What it does

The system combines classical ML, NLP, and generative AI into a full-stack application that helps a SOC analyst prioritize and understand CVE vulnerabilities.

### AI Agent (Conversational Interface)

Ask natural-language questions and get analyst-quality answers:

- *"What are the top threats I should focus on today?"*
- *"Explain CVE-2026-24061"*
- *"Which CVEs are in the CISA KEV catalog?"*
- *"Which vulnerabilities have public exploits?"*
- *"What anomalies did the model detect?"*
- *"Show me similar vulnerabilities to CVE-2026-24061"*
- *"Summarise the threat landscape"*
- *"What should a SOC analyst do next?"*

The agent routes each question to the right ML tools, builds structured context, and generates a professional analyst response — powered by Gemini 1.5 Flash when a key is configured, or template-based responses without one.

### Dashboard

- Search CVEs by ID or keyword
- Browse the top 20 highest-risk CVEs
- View full CVE detail: risk score, KEV status, exploit availability, anomaly flag, cluster, agent explanation, similar CVEs

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
| Gemini 1.5 Flash (optional) | Generate analyst-quality natural-language explanations |

---

## Agent Architecture

```
User Question
     ↓
Intent Detection (regex patterns → 9 intents)
     ↓
Tool Selection (one or more of):
  ├── Risk Scorer      → composite 0–10 score
  ├── Recommender      → TF-IDF similarity lookup
  ├── KEV data         → CISA Known Exploited Vulnerabilities
  ├── Exploit data     → Exploit-DB public exploit flag
  ├── Clustering       → K-Means cluster + keywords
  └── Anomaly Detector → Isolation Forest flag
     ↓
Context Assembly (compact — never the full dataset)
     ↓
Gemini 1.5 Flash (if key is configured)
OR
Template-based offline response
     ↓
Analyst Answer + Related CVEs + Sources
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python 3.11+) |
| Frontend | Next.js 15 + TypeScript + Tailwind CSS |
| ML / NLP | scikit-learn (TF-IDF, K-Means, TruncatedSVD, Isolation Forest, cosine similarity) |
| Generative AI | Google Gemini 1.5 Flash (optional) |
| Data | NVD CVE API, CISA KEV, Exploit-DB, MITRE ATT&CK |

---

## Data Sources

| Dataset | Source | Records |
|---------|--------|---------|
| NVD CVE | NIST National Vulnerability Database | 20,000 |
| CISA KEV | Known Exploited Vulnerabilities catalog | ~1,200 |
| Exploit-DB | Public exploit database | ~50,000 |
| MITRE ATT&CK | Enterprise attack framework (STIX) | — |

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/cve/{id}` | Full CVE profile with risk score and explanation |
| GET | `/cve/{id}/similar?n=5` | Top N similar CVEs (TF-IDF cosine similarity) |
| GET | `/top-risks?n=20` | Top N highest-risk CVEs |
| GET | `/search?q=...` | Search by CVE ID or keyword |
| **POST** | **`/agent/chat`** | **Conversational AI agent** |

### `/agent/chat` request / response

```json
// Request
{ "message": "What are the top threats I should focus on today?" }

// Response
{
  "answer": "Based on current threat intelligence data...",
  "intent": "top_risks",
  "sources": ["NVD CVE", "CISA KEV", "Exploit-DB", "Risk Scorer"],
  "related_cves": [...],
  "gemini_enabled": false
}
```

Supported intents: `top_risks`, `cve_explanation`, `similar_cves`, `kev_query`, `exploit_query`, `anomaly_query`, `recommendation_query`, `search_query`, `summary_query`, `general_help`.

---

## Local Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- (Optional) Google Gemini API key from [aistudio.google.com](https://aistudio.google.com)

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

The backend starts at `http://localhost:8000`. On first run, it:
1. Merges NVD + KEV + Exploit-DB into an enriched dataset (~20 seconds)
2. Builds K-Means clusters and anomaly flags
3. Builds the TF-IDF similarity index

API docs at `http://localhost:8000/docs`.

### 2. Gemini (Optional)

```bash
# In the backend directory:
export GEMINI_API_KEY="your-key-here"
uvicorn main:app --reload
```

Without `GEMINI_API_KEY`, the agent uses high-quality template-based responses (fully functional). With the key, responses are enhanced by Gemini 1.5 Flash.

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The AI Agent is at `http://localhost:3000/agent`.

The frontend uses `NEXT_PUBLIC_API_URL` from `frontend/.env.local` (defaults to `http://localhost:8000`).

---

## Deployment

### Backend → Render

1. Create a **Web Service** on [render.com](https://render.com)
2. Connect the GitHub repo
3. Set:
   - **Root directory**: `backend`
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. (Optional) Add environment variable: `GEMINI_API_KEY=your-key`
5. Deploy

### Frontend → Vercel

1. Import the repo on [vercel.com](https://vercel.com)
2. Set **Root directory**: `frontend`
3. Add environment variable: `NEXT_PUBLIC_API_URL=https://your-app.onrender.com`
4. Deploy

---

## Project Structure

```
Cyber-Threat-Prioritization-Agent/
├── backend/
│   ├── main.py                  # FastAPI app (6 endpoints)
│   ├── requirements.txt
│   ├── Agent/
│   │   ├── data_loader.py       # Merge NVD + KEV + Exploit-DB
│   │   ├── risk_scorer.py       # Composite 0–10 risk score
│   │   ├── clustering.py        # K-Means + TruncatedSVD (LSA)
│   │   ├── anomaly_detector.py  # Isolation Forest
│   │   ├── recommender.py       # TF-IDF cosine similarity index
│   │   ├── nlp_explainer.py     # Template NLP summaries
│   │   ├── chat_agent.py        # Intent routing + tool calls + response assembly
│   │   └── llm_client.py        # Gemini 1.5 Flash + offline fallback
│   └── Data/                    # Source CSV datasets
├── frontend/
│   ├── app/
│   │   ├── page.tsx             # Dashboard: search + top risks
│   │   ├── agent/page.tsx       # AI Agent chat interface
│   │   └── cve/[id]/page.tsx   # CVE detail page
│   ├── components/
│   │   ├── CVECard.tsx
│   │   ├── RiskBadge.tsx
│   │   └── SimilarCVEList.tsx
│   └── lib/api.ts               # API client (fetch wrapper)
├── Scripts/                     # Data collection scripts
├── Similarity Algorithms/       # Assignment 2: Cosine + Jaccard
└── README.md
```
