import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "Data")
ENRICHED_PATH = os.path.join(DATA_DIR, "enriched_cves.csv")


def _parse_exploitdb_cve_ids(codes_series: pd.Series) -> set:
    cve_ids = set()
    for cell in codes_series.dropna():
        for token in str(cell).split(";"):
            token = token.strip()
            if token.startswith("CVE-"):
                cve_ids.add(token)
    return cve_ids


def load_data(force_rebuild: bool = False) -> pd.DataFrame:
    if not force_rebuild and os.path.exists(ENRICHED_PATH):
        return pd.read_csv(ENRICHED_PATH)

    nvd = pd.read_csv(os.path.join(DATA_DIR, "latest_20k_cves_from_2026.csv"))
    nvd["cve_id"] = nvd["cve_id"].str.strip()

    kev = pd.read_csv(os.path.join(DATA_DIR, "cisa_kev.csv"))
    kev = kev.rename(columns={"cveID": "cve_id"})
    kev["cve_id"] = kev["cve_id"].str.strip()
    kev_ids = set(kev["cve_id"])

    exploitdb = pd.read_csv(os.path.join(DATA_DIR, "exploitdb.csv"), low_memory=False)
    exploit_ids = _parse_exploitdb_cve_ids(exploitdb["codes"])

    nvd["is_kev"] = nvd["cve_id"].isin(kev_ids)
    nvd["has_exploit"] = nvd["cve_id"].isin(exploit_ids)

    kev_meta = kev[["cve_id", "requiredAction", "vulnerabilityName"]].drop_duplicates("cve_id")
    df = nvd.merge(kev_meta, on="cve_id", how="left")

    df["description"] = df["description"].fillna("")
    df["severity_score"] = pd.to_numeric(df["severity_score"], errors="coerce").fillna(0.0)
    df["references_count"] = pd.to_numeric(df["references_count"], errors="coerce").fillna(0.0)
    df["cwe"] = df["cwe"].fillna("UNKNOWN")

    df.to_csv(ENRICHED_PATH, index=False)
    print(f"[data_loader] Enriched dataset saved: {df.shape[0]} rows")
    return df
