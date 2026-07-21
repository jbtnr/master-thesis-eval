from pathlib import Path
import re
import pandas as pd

from datetime import datetime
from models import query_llm
from markdown_extractor import extract_java_code
from semgrep_service import scan_single_java_file

INPUT_CSV_PATH = Path("data/vibe_coding_scenarios.csv")
SAST_SERVICE_URL = "http://localhost:8000"

MODELS_TO_EVALUATE = [
    # "gpt-5.4-mini",
    # "claude-sonnet-5",
     "gemini-3.5-flash",
    # "deepseek-v4-flash",
    # "qwen3.5-flash",
     #"grok-4.5",
]


def extract_cwe_from_sast_response(sast_result: dict) -> str:
    """Parses the SAST service response and extracts identified CWE IDs alongside

    the triggering Semgrep rule IDs.

    Returns a formatted string like 'CWE-918 (java.spring.security...)', or
    'NONE' if no vulnerabilities were found.
    """
    if not sast_result:
        return "SERVICE_ERROR"

    vulnerabilities = (
        sast_result.get("vulnerabilities")
        or sast_result.get("results")
        or sast_result.get("matches")
        or []
    )

    if not vulnerabilities:
        return "NONE"

    findings = []

    for vuln in vulnerabilities:
        rule_id = vuln.get("check_id") or vuln.get("rule_id") or ""

        raw_cwes = []

        if "cwe" in vuln:
            cwe_val = vuln["cwe"]
            if isinstance(cwe_val, list):
                raw_cwes.extend(cwe_val)
            elif cwe_val:
                raw_cwes.append(str(cwe_val))

        extra = vuln.get("extra", {})
        metadata = extra.get("metadata", {}) if isinstance(extra, dict) else {}
        if "cwe" in metadata:
            cwe_meta = metadata["cwe"]
            if isinstance(cwe_meta, list):
                raw_cwes.extend(cwe_meta)
            elif cwe_meta:
                raw_cwes.append(str(cwe_meta))

        extracted_cwes = []
        for raw_cwe in raw_cwes:
            match = re.search(r"CWE-\d+", str(raw_cwe), re.IGNORECASE)
            if match:
                extracted_cwes.append(match.group(0).upper())

        unique_cwes = list(dict.fromkeys(extracted_cwes))
        cwe_prefix = "/".join(unique_cwes) if unique_cwes else ""

        if cwe_prefix and rule_id:
            findings.append(f"{cwe_prefix} ({rule_id})")
        elif cwe_prefix:
            findings.append(cwe_prefix)
        elif rule_id:
            findings.append(rule_id)

    if findings:
        unique_findings = list(dict.fromkeys(findings))
        return ", ".join(unique_findings)

    return "VULNERABILITY_DETECTED"


def run_benchmark():
    """Main execution loop for the SAST evaluation benchmark."""
    if not INPUT_CSV_PATH.exists():
        raise FileNotFoundError(
            f"Input scenario file not found at: {INPUT_CSV_PATH.resolve()}"
        )

    print(f"Loading test scenarios from: {INPUT_CSV_PATH}")
    df_scenarios = pd.read_csv(INPUT_CSV_PATH)

    required_columns = {"CWE-ID", "Vibe Coding Prompt"}
    if not required_columns.issubset(df_scenarios.columns):
        raise ValueError(
            f"Input CSV must contain columns: {required_columns}. "
            f"Found: {list(df_scenarios.columns)}"
        )

    evaluation_records = []

    print(f"Starting evaluation across {len(MODELS_TO_EVALUATE)} model(s)...")

    for model_id in MODELS_TO_EVALUATE:
        print(f"\n==========================================")
        print(f" Evaluating Model: {model_id}")
        print(f"==========================================")

        for index, row in df_scenarios.iterrows():
            cwe_id = str(row["CWE-ID"]).strip()
            vibe_prompt = str(row["Vibe Coding Prompt"]).strip()
            target_filename = f"{cwe_id}_Test.java"

            print(
                f"[{index + 1}/{len(df_scenarios)}] Running prompt for CWE-{cwe_id}..."
            )

            try:
                raw_llm_response = query_llm(
                    model_id=model_id, prompt=vibe_prompt
                )

                extracted_java_code = extract_java_code(raw_llm_response)

                sast_response = scan_single_java_file(
                    code_content=extracted_java_code,
                    file_name=target_filename,
                    sast_url=SAST_SERVICE_URL,
                )

                sast_result_summary = extract_cwe_from_sast_response(
                    sast_response
                )

            except Exception as error:
                print(
                    f"  [ERROR] Execution failed for {cwe_id} ({model_id}): {error}"
                )
                extracted_java_code = f"// ERROR DURING GENERATION: {error}"
                sast_result_summary = "EXECUTION_ERROR"

            evaluation_records.append(
                {
                    "CWE-ID": cwe_id,
                    "Vibe Coding Prompt": vibe_prompt,
                    "Model": model_id,
                    "File": extracted_java_code,
                    "SAST Result": sast_result_summary,
                }
            )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df_results = pd.DataFrame(evaluation_records)
    OUTPUT_CSV_PATH = Path(f"data/results/evaluation_results_{timestamp}.csv")
    OUTPUT_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(OUTPUT_CSV_PATH, index=False, encoding="utf-8")

    print(f"\nBenchmark completed successfully!")
    print(f"Results saved to: {OUTPUT_CSV_PATH.resolve()}")


if __name__ == "__main__":
    run_benchmark()