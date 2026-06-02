import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# Load the CVE dataset
df = pd.read_csv("Data/latest_20k_cves_from_2026.csv")

# Keep relevant columns
df = df[["cve_id", "description", "cwe", "severity_score"]].copy()

# Replace missing values
df["description"] = df["description"].fillna("")
df["cwe"] = df["cwe"].fillna("UNKNOWN_CWE")
df["severity_score"] = df["severity_score"].fillna("UNKNOWN_SCORE")

# Convert severity score to text so it can be included in TF-IDF
df["severity_score_text"] = "severity_" + df["severity_score"].astype(str)

# Combine textual and categorical features into one field
df["combined_features"] = (
    df["description"] + " " +
    df["cwe"] + " " +
    df["severity_score_text"]
)

# Convert combined features into TF-IDF vectors
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

tfidf_matrix = vectorizer.fit_transform(df["combined_features"])

# Calculate cosine similarity between all CVEs
cosine_matrix = cosine_similarity(tfidf_matrix)

# Choose the first CVE as the target item
target_index = 0
target_cve = df.iloc[target_index]["cve_id"]

# Get similarity scores for the target CVE
similarity_scores = list(enumerate(cosine_matrix[target_index]))

# Sort by similarity score from highest to lowest
similarity_scores = sorted(similarity_scores, key=lambda x: x[1], reverse=True)

# Skip the first result because it is the CVE compared with itself
top_similar = similarity_scores[1:6]

print(f"Target CVE: {target_cve}")
print("\nTop 5 similar CVEs based on description + category:\n")

for index, score in top_similar:
    print("CVE ID:", df.iloc[index]["cve_id"])
    print("Similarity Score:", round(score, 4))
    print("CWE:", df.iloc[index]["cwe"])
    print("Severity Score:", df.iloc[index]["severity_score"])
    print("Description:", df.iloc[index]["description"][:300])
    print("-" * 80)