import os
import re
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "Data")
ENRICHED_PATH = os.path.join(DATA_DIR, "enriched_cves.csv")

_CVSS_RE = re.compile(
    r"AV:(?P<av>[NALP])[^/]*/AC:(?P<ac>[LH])/PR:(?P<pr>[NLH])/UI:(?P<ui>[NR])/"
    r"S:[UC]/C:(?P<c>[NLH])/I:(?P<i>[NLH])/A:(?P<a>[NLH])",
    re.IGNORECASE,
)
_AV_MAP = {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}
_LEVEL_MAP = {"N": "None", "L": "Low", "H": "High", "R": "Required"}
_AC_MAP = {"L": "Low", "H": "High"}


def _parse_cvss_vector(vector: str) -> dict:
    empty = {
        "attack_vector": "", "attack_complexity": "",
        "privileges_required": "", "user_interaction": "",
        "confidentiality": "", "integrity": "", "availability": "",
    }
    if not vector or not isinstance(vector, str):
        return empty
    m = _CVSS_RE.search(vector)
    if not m:
        return empty
    return {
        "attack_vector":       _AV_MAP.get(m.group("av").upper(), ""),
        "attack_complexity":   _AC_MAP.get(m.group("ac").upper(), ""),
        "privileges_required": _LEVEL_MAP.get(m.group("pr").upper(), ""),
        "user_interaction":    _LEVEL_MAP.get(m.group("ui").upper(), ""),
        "confidentiality":     _LEVEL_MAP.get(m.group("c").upper(), ""),
        "integrity":           _LEVEL_MAP.get(m.group("i").upper(), ""),
        "availability":        _LEVEL_MAP.get(m.group("a").upper(), ""),
    }


def _parse_exploitdb_metadata(exploitdb: pd.DataFrame) -> dict:
    """Return dict: cve_id → {exploit_type, exploit_verified, exploit_platform}"""
    meta: dict[str, dict] = {}
    for _, row in exploitdb.iterrows():
        codes = str(row.get("codes", "") or "")
        cve_ids = [t.strip() for t in codes.split(";") if t.strip().startswith("CVE-")]
        if not cve_ids:
            continue
        exploit_type = str(row.get("type", "") or "").lower().strip()
        verified = bool(row.get("verified", 0))
        platform = str(row.get("platform", "") or "").strip()
        for cid in cve_ids:
            if cid not in meta:
                meta[cid] = {"exploit_type": set(), "exploit_verified": False, "exploit_platform": set()}
            meta[cid]["exploit_type"].add(exploit_type)
            meta[cid]["exploit_verified"] = meta[cid]["exploit_verified"] or verified
            if platform:
                meta[cid]["exploit_platform"].add(platform)
    return {
        cid: {
            "exploit_type": ",".join(sorted(v["exploit_type"])),
            "exploit_verified": v["exploit_verified"],
            "exploit_platform": ",".join(sorted(v["exploit_platform"])),
        }
        for cid, v in meta.items()
    }


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
    exploit_meta = _parse_exploitdb_metadata(exploitdb)
    exploit_ids = set(exploit_meta.keys())

    nvd["is_kev"] = nvd["cve_id"].isin(kev_ids)
    nvd["has_exploit"] = nvd["cve_id"].isin(exploit_ids)

    # Exploit-DB metadata columns
    nvd["exploit_type"] = nvd["cve_id"].map(lambda x: exploit_meta.get(x, {}).get("exploit_type", ""))
    nvd["exploit_verified"] = nvd["cve_id"].map(lambda x: exploit_meta.get(x, {}).get("exploit_verified", False))
    nvd["exploit_platform"] = nvd["cve_id"].map(lambda x: exploit_meta.get(x, {}).get("exploit_platform", ""))

    # KEV metadata
    kev_meta = kev[[
        "cve_id", "vendorProject", "product", "vulnerabilityName",
        "dateAdded", "dueDate", "requiredAction", "knownRansomwareCampaignUse",
    ]].drop_duplicates("cve_id").rename(columns={"knownRansomwareCampaignUse": "ransomware_campaign"})
    df = nvd.merge(kev_meta, on="cve_id", how="left")

    # EPSS scores (optional — only if file exists)
    epss_path = os.path.join(DATA_DIR, "epss_scores.csv")
    if os.path.exists(epss_path):
        epss = pd.read_csv(epss_path, comment="#")
        epss.columns = [c.strip().lower() for c in epss.columns]
        if "cve" in epss.columns:
            epss = epss.rename(columns={"cve": "cve_id"})
        epss = epss[["cve_id", "epss", "percentile"]].rename(
            columns={"epss": "epss_score", "percentile": "epss_percentile"}
        ).drop_duplicates("cve_id")
        df = df.merge(epss, on="cve_id", how="left")
        df["epss_score"] = pd.to_numeric(df["epss_score"], errors="coerce").fillna(0.0)
        df["epss_percentile"] = pd.to_numeric(df["epss_percentile"], errors="coerce").fillna(0.0)
        print(f"[data_loader] EPSS scores joined: {epss.shape[0]} entries")
    else:
        df["epss_score"] = 0.0
        df["epss_percentile"] = 0.0

    # CPE vendor/product data (optional — only if file exists)
    cpe_path = os.path.join(DATA_DIR, "cve_cpe.csv")
    if os.path.exists(cpe_path):
        cpe = pd.read_csv(cpe_path, low_memory=False)
        cpe_agg = (
            cpe.groupby("cve_id")
            .agg(
                cpe_vendors=("cpe_vendor", lambda x: ",".join(sorted(set(x.dropna())))),
                cpe_products=("cpe_product", lambda x: ",".join(sorted(set(x.dropna())))),
            )
            .reset_index()
        )
        df = df.merge(cpe_agg, on="cve_id", how="left")
        df["cpe_vendors"] = df["cpe_vendors"].fillna("")
        df["cpe_products"] = df["cpe_products"].fillna("")
        print(f"[data_loader] CPE data joined: {cpe_agg.shape[0]} CVEs with product info")
    else:
        df["cpe_vendors"] = ""
        df["cpe_products"] = ""

    # MITRE ATT&CK technique links (optional)
    mitre_path = os.path.join(DATA_DIR, "mitre_cve_links.csv")
    if os.path.exists(mitre_path):
        mitre = pd.read_csv(mitre_path)
        mitre_agg = (
            mitre.groupby("cve_id")
            .agg(mitre_techniques=("technique_id", lambda x: ",".join(sorted(set(x.dropna())))))
            .reset_index()
        )
        df = df.merge(mitre_agg, on="cve_id", how="left")
        df["mitre_techniques"] = df["mitre_techniques"].fillna("")
        print(f"[data_loader] MITRE ATT&CK links joined: {mitre_agg.shape[0]} CVEs with technique links")
    else:
        df["mitre_techniques"] = ""

    # CVSS vector parsing
    parsed = df["cvss_vector"].apply(_parse_cvss_vector).apply(pd.Series)
    df = pd.concat([df, parsed], axis=1)

    # Fill defaults
    df["description"] = df["description"].fillna("")
    df["severity_score"] = pd.to_numeric(df["severity_score"], errors="coerce").fillna(0.0)
    df["references_count"] = pd.to_numeric(df["references_count"], errors="coerce").fillna(0.0)
    df["cwe"] = df["cwe"].fillna("UNKNOWN")
    df["vendorProject"] = df["vendorProject"].fillna("")
    df["product"] = df["product"].fillna("")
    df["dateAdded"] = df["dateAdded"].fillna("")
    df["dueDate"] = df["dueDate"].fillna("")
    df["ransomware_campaign"] = df["ransomware_campaign"].fillna("")
    df["exploit_type"] = df["exploit_type"].fillna("")
    df["exploit_verified"] = df["exploit_verified"].fillna(False)
    df["exploit_platform"] = df["exploit_platform"].fillna("")

    df.to_csv(ENRICHED_PATH, index=False)
    print(f"[data_loader] Enriched dataset saved: {df.shape[0]} rows, {df.shape[1]} columns")
    return df
