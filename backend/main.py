from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from Agent.data_loader import load_data
from Agent.risk_scorer import score_cves
from Agent.clustering import fit_clusters
from Agent.anomaly_detector import detect_anomalies
from Agent import recommender
from Agent.nlp_explainer import explain
from Agent import chat_agent
from Agent import llm_client
from Agent import threat_actors as ta_module


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[startup] Loading and enriching data...")
    df = load_data()
    df = score_cves(df)
    df = fit_clusters(df)
    df = detect_anomalies(df)
    recommender.build_index(df)
    print("[startup] Ready.")
    yield


app = FastAPI(title="Cyber Threat Prioritization Agent", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/cve/{cve_id}")
def get_cve(cve_id: str):
    profile = recommender.get_profile(cve_id.upper())
    if profile is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    profile["explanation"] = explain(profile)
    return profile


@app.get("/cve/{cve_id}/similar")
def get_similar(cve_id: str, n: int = Query(default=5, ge=1, le=20)):
    profile = recommender.get_profile(cve_id.upper())
    if profile is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} not found")
    return recommender.get_similar(cve_id.upper(), top_n=n)


@app.get("/stats")
def get_stats():
    df = recommender._df
    if df is None:
        return {
            "total_cves": 0, "critical_count": 0, "high_count": 0,
            "medium_count": 0, "low_count": 0, "kev_count": 0,
            "exploit_count": 0, "anomaly_count": 0,
            "ransomware_count": 0, "high_epss_count": 0,
        }
    labels = df["risk_label"].value_counts()
    return {
        "total_cves":       int(len(df)),
        "critical_count":   int(labels.get("Critical", 0)),
        "high_count":       int(labels.get("High", 0)),
        "medium_count":     int(labels.get("Medium", 0)),
        "low_count":        int(labels.get("Low", 0)),
        "kev_count":        int(df["is_kev"].sum()),
        "exploit_count":    int(df["has_exploit"].sum()),
        "anomaly_count":    int(df["is_anomaly"].sum()),
        "ransomware_count": int((df["ransomware_campaign"] == "Known").sum()),
        "high_epss_count":  int((df["epss_score"].fillna(0) >= 0.5).sum()),
    }


@app.get("/top-risks")
def top_risks(n: int = Query(default=20, ge=1, le=100)):
    return recommender.get_top_risks(n)


@app.get("/search")
def search(q: str = Query(..., min_length=1)):
    results = recommender.search_cves(q)
    if not results:
        return []
    return results


@app.get("/latest-cves")
def latest_cves(n: int = Query(default=20, ge=1, le=100)):
    return recommender.get_latest(n)


@app.get("/vendors")
def get_vendors():
    return recommender.get_vendors()


@app.get("/threat-actors")
def get_threat_actors(vendor: str | None = Query(default=None)):
    if vendor:
        return ta_module.get_by_vendor(vendor)
    return ta_module.get_all()


class ChatRequest(BaseModel):
    message: str
    environment_vendors: list[str] = []


@app.post("/agent/chat")
def agent_chat(req: ChatRequest):
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be empty")
    result = chat_agent.handle(req.message.strip(), environment_vendors=req.environment_vendors)
    result["gemini_enabled"] = llm_client.is_enabled()
    return result
