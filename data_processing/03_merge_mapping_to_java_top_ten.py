import pandas as pd

CWE_FILE = "../data/owasp_top_ten_java_cwes.csv"
MAPPING_FILE = "../data/owasp_top10_2025_cwe_mapping.csv"

OUTPUT_FILE = "../data/cwe_java_with_owasp.csv"

cwe_df = pd.read_csv(CWE_FILE)
mapping_df = pd.read_csv(MAPPING_FILE)

mapping_df = mapping_df.rename(columns={"CWE_ID": "CWE-ID"})

mapping_df["CWE-ID"] = (
    mapping_df["CWE-ID"]
    .str.replace("CWE-", "", regex=False)
    .astype(int)
)

result = cwe_df.merge(
    mapping_df,
    on="CWE-ID",
    how="left"
)

result.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")

print(f"Done! {len(result)} columns.")
print(f"Found OWASP-Category for {result['OWASP_Category'].notna().sum()} CWEs.")