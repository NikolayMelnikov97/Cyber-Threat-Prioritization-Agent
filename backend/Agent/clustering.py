import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD
from sklearn.cluster import KMeans

N_CLUSTERS = 15
N_COMPONENTS = 50
MAX_FEATURES = 3000
RANDOM_STATE = 42


def fit_clusters(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    vectorizer = TfidfVectorizer(
        stop_words="english",
        max_features=MAX_FEATURES,
        sublinear_tf=True,
    )
    tfidf = vectorizer.fit_transform(df["description"].fillna(""))

    svd = TruncatedSVD(n_components=N_COMPONENTS, random_state=RANDOM_STATE)
    reduced = svd.fit_transform(tfidf)

    kmeans = KMeans(n_clusters=N_CLUSTERS, random_state=RANDOM_STATE, n_init=10)
    df["cluster_id"] = kmeans.fit_predict(reduced)

    terms = vectorizer.get_feature_names_out()
    cluster_labels = {}
    for i, center in enumerate(kmeans.cluster_centers_):
        # Map cluster centers back through SVD to TF-IDF space
        tfidf_center = svd.inverse_transform(center.reshape(1, -1))[0]
        top_indices = tfidf_center.argsort()[-5:][::-1]
        keywords = ", ".join(terms[j] for j in top_indices)
        cluster_labels[i] = keywords

    df["cluster_label"] = df["cluster_id"].map(cluster_labels)

    print(f"[clustering] Assigned {N_CLUSTERS} clusters to {len(df)} CVEs")
    return df
