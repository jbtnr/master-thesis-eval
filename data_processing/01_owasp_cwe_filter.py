import pandas as pd

df = pd.read_csv("../data/1450.csv", index_col=False)

platform_mask = (
    df['Applicable Platforms'].isna() |
    df['Applicable Platforms'].astype(str).str.contains(
        'Java|Not Technology-Specific|Not Language-Specific', case=False
    )
)
df_filtered = df[platform_mask]

implementation_mask = df_filtered['Modes Of Introduction'].astype(str).str.contains('PHASE:Implementation', case=False)
df_final = df_filtered[implementation_mask]

df_final.to_csv("owasp_top_ten_java_cwes.csv", index=False)

print(f"Done. From {len(df)} CWEs {len(df_final)} are relevant for java source code.")