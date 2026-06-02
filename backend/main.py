from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from Agent.data_loader import load_data
from Agent.risk_scorer import score_cves
from Agent.clustering import fit_clusters
from Agent.anomaly_detector import detect_anomalies
from Agent import recommender
from Agent.nlp_explainer import explain


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
    allow_methods=["GET"],
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


@app.get("/top-risks")
def top_risks(n: int = Query(default=20, ge=1, le=100)):
    return recommender.get_top_risks(n)


@app.get("/search")
def search(q: str = Query(..., min_length=1)):
    results = recommender.search_cves(q)
    if not results:
        return []
    return results
