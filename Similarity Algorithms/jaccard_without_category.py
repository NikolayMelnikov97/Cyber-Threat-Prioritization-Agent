import pandas as pd
import re


# Load the CVE dataset
df = pd.read_csv("Data/latest_20k_cves_from_2026.csv")

# Keep only relevant columns
df = df[["cve_id", "description"]].copy()

# Replace missing descriptions with empty strings
df["description"] = df["description"].fillna("")


def text_to_word_set(text):
    """
    Convert a text description into a set of normalized words.
    """
    text = text.lower()
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text)
    return set(words)


def jaccard_similarity(set_a, set_b):
    """
    Calculate Jaccard similarity between two sets.
    """
    union = set_a | set_b

    if not union:
        return 0

    intersection = set_a & set_b
    return len(intersection) / len(union)


# Convert each CVE description into a set of words
df["word_set"] = df["description"].apply(text_to_word_set)

# Choose the first CVE as the target item
target_index = 0
target_cve = df.iloc[target_index]["cve_id"]
target_set = df.iloc[target_index]["word_set"]

# Calculate Jaccard similarity between the target CVE and all other CVEs
similarities = []

for index, row in df.iterrows():
    if index == target_index:
        continue

    score = jaccard_similarity(target_set, row["word_set"])

    similarities.append({
        "cve_id": row["cve_id"],
        "similarity_score": score,
        "description": row["description"]
    })

# Convert results to DataFrame
results_df = pd.DataFrame(similarities)

# Sort by similarity score from highest to lowest
results_df = results_df.sort_values(by="similarity_score", ascending=False)

# Print top 5 most similar CVEs
print(f"Target CVE: {target_cve}")
print("\nTop 5 similar CVEs based on Jaccard description only:\n")

for _, row in results_df.head(5).iterrows():
    print("CVE ID:", row["cve_id"])
    print("Similarity Score:", round(row["similarity_score"], 4))
    print("Description:", row["description"][:300])
    print("-" * 80)