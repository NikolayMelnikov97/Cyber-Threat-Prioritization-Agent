import pandas as pd


def score_cves(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    kev_bonus = df["is_kev"].astype(float) * 2.0
    ref_bonus = (df["references_count"].clip(upper=20) / 20.0) * 0.5 * 10

    # Exploit-DB metadata: verified remote exploit scores higher than a generic exploit flag
    exploit_verified = df["exploit_verified"].astype(float)
    exploit_remote = df["exploit_type"].str.contains("remote", case=False, na=False).astype(float)
    exploit_bonus = (
        exploit_verified * 1.2          # verified exploit
        + exploit_remote * 0.5          # remote exploit bonus
        + df["has_exploit"].astype(float) * 0.3   # any exploit (unverified)
    ).clip(upper=1.5)

    # EPSS: probability of exploitation in next 30 days (0–1 scale → 0–2 bonus)
    epss_bonus = df["epss_score"].clip(upper=1.0) * 2.0

    df["risk_score"] = (
        0.50 * df["severity_score"]
        + kev_bonus
        + exploit_bonus
        + epss_bonus
        + ref_bonus
    ).clip(upper=10).round(2)

    df["risk_label"] = pd.cut(
        df["risk_score"],
        bins=[-0.01, 4.0, 7.0, 9.0, 10.01],
        labels=["Low", "Medium", "High", "Critical"],
    ).astype(str)

    return df
