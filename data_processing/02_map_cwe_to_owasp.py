import re
from pathlib import Path
import pandas as pd

INPUT_DIR = Path("../data/OWASP_2025_MD/")

rows = []

for md_file in INPUT_DIR.glob("*.md"):

    with open(md_file, "r", encoding="utf-8") as f:
        text = f.read()


    header_match = re.search(r"^#\s+(.+?)(?:\s+!\[|$)", text, re.MULTILINE)

    if header_match:
        category = header_match.group(1).strip()
    else:
        category = md_file.stem
        print(f"No heading found in {md_file.name}")


    match = re.search(
        r"##\s+List of Mapped CWEs(.*?)(?:\n##\s|\Z)",
        text,
        flags=re.DOTALL,
    )

    if not match:
        print(f"No CWE list found in {md_file.name}")
        continue

    cwe_section = match.group(1)

    cwe_ids = sorted(set(re.findall(r"CWE-(\d+)", cwe_section)), key=int)

    for cwe in cwe_ids:
        rows.append({
            "CWE_ID": f"CWE-{cwe}",
            "OWASP_Category": category
        })

df = pd.DataFrame(rows)

df = df.sort_values(["OWASP_Category", "CWE_ID"])

df.to_csv("owasp_top10_2025_cwe_mapping.csv", index=False, encoding="utf-8-sig")

print(f"{len(df)} CWE-Mappins saved.")