import pandas as pd
from sklearn.ensemble import IsolationForest

CONTAMINATION = 0.05
RANDOM_STATE = 42


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    features = df[["severity_score", "references_count"]].copy()
    features["is_kev"] = df["is_kev"].astype(float)
    features["has_exploit"] = df["has_exploit"].astype(float)
    features = features.fillna(0.0)

    model = IsolationForest(contamination=CONTAMINATION, random_state=RANDOM_STATE)
    preds = model.fit_predict(features)

    # IsolationForest returns -1 for anomalies, 1 for normal
    df["is_anomaly"] = preds == -1

    flagged = df["is_anomaly"].sum()
    print(f"[anomaly_detector] Flagged {flagged} anomalies ({flagged/len(df)*100:.1f}%)")
    return df
