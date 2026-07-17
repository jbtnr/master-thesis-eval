import os
import re
import pandas as pd

INPUT_TABLE = "cwe_java_with_owasp.csv"
OUTPUT_TABLE = "filtered_cwe_table.csv"
SEMGREP_FILE = "semgrep_cwes_result.txt"


def extract_semgrep_cwes(filepath):
    """Extracts all CWEs from semgrep-results file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File '{filepath}' not found.")

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    cwes = set(re.findall(r"CWE-\d+", content, re.IGNORECASE))
    return {cwe.upper() for cwe in cwes}


def normalize_cwe_string(val):
    """Noramlizing (z.B. '89', 'CWE 89', 'CWE-89' -> 'CWE-89')
    """
    if pd.isna(val):
        return ""
    val_str = str(val).strip()
    match = re.search(r"\d+", val_str)
    if match:
        return f"CWE-{match.group(0)}"
    return val_str.upper()


def main():
    try:
        semgrep_cwes = extract_semgrep_cwes(SEMGREP_FILE)
        print(
            f"[*] {len(semgrep_cwes)} Successfully loaded CWEs from '{SEMGREP_FILE}'."
        )
    except Exception as e:
        print(f"[!] Error when loading semgrep results: {e}")
        return

    if not os.path.exists(INPUT_TABLE):
        print(
            f"[!] Error: Table '{INPUT_TABLE}' doesnt exist in current dir."
        )
        return

    print(f"[*] Loading table '{INPUT_TABLE}'...")
    if INPUT_TABLE.endswith(".csv"):
        df = pd.read_csv(INPUT_TABLE)
    elif INPUT_TABLE.endswith((".xlsx", ".xls")):
        df = pd.read_excel(INPUT_TABLE)
    else:
        print(
            "[!] Error: Unknown file format."
        )
        return

    cwe_col = None
    for col in df.columns:
        if "cwe" in col.lower():
            cwe_col = col
            break

    if not cwe_col:
        print("[!] Warning: No column 'CWE' found.")
        print(f"    Available columns: {list(df.columns)}")
        cwe_col = df.columns[0]
        print(f"    Using first column instead: '{cwe_col}'")
    else:
        print(f"[*] Using column '{cwe_col}' for CWE check.")

    df["_temp_normalized_cwe"] = df[cwe_col].apply(normalize_cwe_string)

    filtered_df = df[df["_temp_normalized_cwe"].isin(semgrep_cwes)].copy()

    filtered_df = filtered_df.drop(columns=["_temp_normalized_cwe"])

    print(f"[*] Zeilen in Originaltabelle: {len(df)}")
    print(f"[*] Zeilen nach Filterung:      {len(filtered_df)}")

    if OUTPUT_TABLE.endswith(".csv"):
        filtered_df.to_csv(OUTPUT_TABLE, index=False, encoding="utf-8")
    else:
        filtered_df.to_excel(OUTPUT_TABLE, index=False)

    print(f"[+] Gefilterte Tabelle erfolgreich gespeichert unter: {OUTPUT_TABLE}")


if __name__ == "__main__":
    main()