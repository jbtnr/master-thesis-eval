import pandas as pd

BASE_CSV = "data/results/sast_baseline_results.csv"
OVERRIDE_CSV = "data/results/sast_baseline_results_filtered_mit_bewertung.csv"
OUTPUT_CSV = "data/results/sast_baseline_results_validated.csv"

df_base = pd.read_csv(BASE_CSV)
df_override = pd.read_csv(OVERRIDE_CSV)

override_header = list(df_override.columns)

key_columns = ["CWE-ID", "Model"]

df_base.set_index(key_columns, inplace=True)
df_override.set_index(key_columns, inplace=True)

for col in df_override.columns:
    if col not in df_base.columns:
        df_base[col] = None

df_base.update(df_override)

df_merged = df_base.reset_index()

final_columns = override_header + [
    c for c in df_merged.columns if c not in override_header
]
df_merged = df_merged[final_columns]

df_merged.to_csv(OUTPUT_CSV, index=False)

print(f"CSV merged. Result in '{OUTPUT_CSV}'")