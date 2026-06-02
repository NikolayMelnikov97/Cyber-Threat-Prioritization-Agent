# Cyber Threat Prioritization Agent

An AI-powered web application that helps cybersecurity analysts prioritize CVEs based on real-world risk, not just CVSS scores alone.

## What it does

- Merges NVD CVE data with CISA KEV (actively exploited) and Exploit-DB (public exploits)
- Computes a composite **risk score** (0–10) combining CVSS, KEV status, and exploit availability
- Clusters CVEs into 15 vulnerability families using K-Means + TF-IDF
- Detects anomalous CVEs using Isolation Forest
- Finds similar CVEs using cosine similarity on TF-IDF vectors
- Generates a natural-language analyst explanation for each CVE

## Tech stack

| Layer | Technology |
|-------|-----------|
| Backend | FastAPI (Python) |
| Frontend | Next.js 15 + TypeScript + Tailwind CSS |
| ML/NLP | scikit-learn (TF-IDF, K-Means, Isolation Forest, cosine similarity) |
| Data | NVD CVE API, CISA KEV, Exploit-DB, MITRE ATT&CK |

## Local setup

### Prerequisites

- Python 3.10+
- Node.js 18+

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

The backend will:
1. Load and merge datasets from `Data/` (~20 seconds on first run)
2. Build the risk scores, clusters, anomaly flags, and TF-IDF index
3. Serve the API at `http://localhost:8000`

API docs are available at `http://localhost:8000/docs`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000` in your browser.

> The frontend reads `NEXT_PUBLIC_API_URL` from `.env.local`. Default is `http://localhost:8000`.

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/cve/{id}` | Full CVE profile with risk score and explanation |
| GET | `/cve/{id}/similar?n=5` | Top N similar CVEs |
| GET | `/top-risks?n=20` | Top N highest-risk CVEs |
| GET | `/search?q=...` | Search by CVE ID or keyword |

## Deployment

### Backend → Render

1. Create a new **Web Service** on [render.com](https://render.com)
2. Connect your GitHub repository
3. Set:
   - **Root directory**: `backend`
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Deploy

> **Note:** The `Data/` folder must be committed to the repo (CSV files). Render does not persist the filesystem between deploys, but the CSVs are read-only and small enough to include in the repo (except `enterprise-attack.json` at 50 MB — add it to `.gitignore` if needed and regenerate with `Scripts/fetch_mitre_attack.py`).

### Frontend → Vercel

1. Import the repository on [vercel.com](https://vercel.com)
2. Set **Root directory** to `frontend`
3. Add environment variable:
   - `NEXT_PUBLIC_API_URL` = your Render backend URL (e.g. `https://your-app.onrender.com`)
4. Deploy

## Project structure

```
Cyber-Threat-Prioritization-Agent/
├── backend/
│   ├── main.py                  # FastAPI application
│   ├── requirements.txt
│   ├── Agent/
│   │   ├── data_loader.py       # Merge NVD + KEV + ExploitDB
│   │   ├── risk_scorer.py       # Composite risk score
│   │   ├── clustering.py        # K-Means CVE clustering
│   │   ├── anomaly_detector.py  # Isolation Forest anomaly detection
│   │   ├── recommender.py       # TF-IDF similarity index
│   │   └── nlp_explainer.py     # Natural language explanation
│   └── Data/                    # CSV datasets
├── frontend/
│   ├── app/
│   │   ├── page.tsx             # Home: search + top risks
│   │   └── cve/[id]/page.tsx   # CVE detail page
│   ├── components/
│   │   ├── CVECard.tsx
│   │   ├── RiskBadge.tsx
│   │   └── SimilarCVEList.tsx
│   └── lib/api.ts               # API client
├── Scripts/                     # Data collection scripts
├── Similarity Algorithms/       # Assignment 2 code
└── README.md
```

## Data sources

| Dataset | Source | Records |
|---------|--------|---------|
| NVD CVE | NIST National Vulnerability Database API | 20,000 |
| CISA KEV | CISA Known Exploited Vulnerabilities catalog | ~1,200 |
| Exploit-DB | Exploit Database | ~50,000 |
| MITRE ATT&CK | MITRE ATT&CK Enterprise STIX data | — |
