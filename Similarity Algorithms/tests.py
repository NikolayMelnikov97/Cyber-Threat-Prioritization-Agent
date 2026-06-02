import pandas as pd

df = pd.read_csv("Data/latest_20k_cves_from_2026.csv")

# Check distribution of severity values (including missing)
print(df["severity_label"].value_counts(dropna=False))

# Count missing values explicitly
missing_count = df["severity_label"].isna().sum()
total = len(df)

print("\nMissing severity count:", missing_count)
print("Total records:", total)
print("Missing percentage:", round((missing_count / total) * 100, 2), "%")

print(df["severity_score"].value_counts(dropna=False).head())