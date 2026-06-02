import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

_df: pd.DataFrame | None = None
_tfidf_matrix = None
_vectorizer: TfidfVectorizer | None = None
_id_to_index: dict = {}


def build_index(df: pd.DataFrame) -> None:
    global _df, _tfidf_matrix, _vectorizer, _id_to_index

    _df = df.reset_index(drop=True)
    _id_to_index = {row["cve_id"]: i for i, row in _df.iterrows()}

    _vectorizer = TfidfVectorizer(
        stop_words="english",
        max_features=5000,
        sublinear_tf=True,
    )
    _tfidf_matrix = _vectorizer.fit_transform(_df["description"].fillna(""))
    print(f"[recommender] TF-IDF index built for {len(_df)} CVEs")


def get_profile(cve_id: str) -> dict | None:
    if _df is None:
        return None
    idx = _id_to_index.get(cve_id)
    if idx is None:
        return None
    row = _df.iloc[idx]
    return _row_to_dict(row)


def get_similar(cve_id: str, top_n: int = 5) -> list[dict]:
    if _df is None or _tfidf_matrix is None:
        return []
    idx = _id_to_index.get(cve_id)
    if idx is None:
        return []

    scores = cosine_similarity(_tfidf_matrix[idx], _tfidf_matrix).flatten()
    scores[idx] = -1  # exclude self
    top_indices = np.argsort(scores)[-top_n:][::-1]

    results = []
    for i in top_indices:
        row = _df.iloc[i]
        d = _row_to_dict(row)
        d["similarity_score"] = round(float(scores[i]), 4)
        results.append(d)
    return results


def get_top_risks(n: int = 20) -> list[dict]:
    if _df is None:
        return []
    top = _df.nlargest(n, "risk_score")
    return [_row_to_dict(row) for _, row in top.iterrows()]


def search_cves(query: str, limit: int = 20) -> list[dict]:
    if _df is None:
        return []
    q = query.strip().upper()
    mask = (
        _df["cve_id"].str.upper().str.contains(q, na=False)
        | _df["description"].str.upper().str.contains(q, na=False)
    )
    results = _df[mask].head(limit)
    return [_row_to_dict(row) for _, row in results.iterrows()]


def get_latest(n: int = 20) -> list[dict]:
    if _df is None:
        return []
    sorted_df = _df.sort_values("published", ascending=False)
    return [_row_to_dict(row) for _, row in sorted_df.head(n).iterrows()]


def search_by_vendor(vendor: str, limit: int = 20) -> list[dict]:
    if _df is None:
        return []
    q = vendor.strip().lower()
    mask = (
        _df["vendorProject"].str.lower().str.contains(q, na=False)
        | _df["product"].str.lower().str.contains(q, na=False)
    )
    results = _df[mask].nlargest(limit, "risk_score")
    return [_row_to_dict(row) for _, row in results.iterrows()]


def get_vendors() -> list[dict]:
    if _df is None:
        return []
    kev_rows = _df[_df["is_kev"] == True][["vendorProject", "product"]].drop_duplicates()
    kev_rows = kev_rows[kev_rows["vendorProject"] != ""]
    return sorted(
        [{"vendor": r["vendorProject"], "product": r["product"]} for _, r in kev_rows.iterrows()],
        key=lambda x: x["vendor"].lower(),
    )


def _row_to_dict(row) -> dict:
    def safe(v):
        if isinstance(v, float) and np.isnan(v):
            return None
        if isinstance(v, (np.bool_,)):
            return bool(v)
        if isinstance(v, (np.integer,)):
            return int(v)
        if isinstance(v, (np.floating,)):
            return float(v)
        return v

    return {k: safe(v) for k, v in row.items()}
