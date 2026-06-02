import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# Load the CVE dataset
df = pd.read_csv("Data/latest_20k_cves_from_2026.csv")

# Keep only the relevant columns
df = df[["cve_id", "description"]].copy()

# Replace missing descriptions with empty strings
df["description"] = df["description"].fillna("")

# Convert CVE descriptions into TF-IDF vectors
vectorizer = TfidfVectorizer(
    stop_words="english",
    max_features=5000
)

tfidf_matrix = vectorizer.fit_transform(df["description"])

# Calculate cosine similarity between all CVE descriptions
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
print("\nTop 5 similar CVEs based on description only:\n")

for index, score in top_similar:
    print("CVE ID:", df.iloc[index]["cve_id"])
    print("Similarity Score:", round(score, 4))
    print("Description:", df.iloc[index]["description"][:300])
    print("-" * 80)