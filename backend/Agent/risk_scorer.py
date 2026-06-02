import pandas as pd


def score_cves(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    kev_bonus = df["is_kev"].astype(float) * 2.0
    exploit_bonus = df["has_exploit"].astype(float) * 1.5
    ref_bonus = (df["references_count"].clip(upper=20) / 20.0) * 0.5 * 10

    df["risk_score"] = (
        0.50 * df["severity_score"]
        + kev_bonus
        + exploit_bonus
        + ref_bonus
    ).clip(upper=10).round(2)

    df["risk_label"] = pd.cut(
        df["risk_score"],
        bins=[-0.01, 4.0, 7.0, 9.0, 10.01],
        labels=["Low", "Medium", "High", "Critical"],
    ).astype(str)

    return df
