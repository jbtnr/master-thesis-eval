import os
from pathlib import Path
import pandas as pd

from testing.models import query_llm
from testing.markdown_extractor import extract_manifest_file
from testing.trivy_service import scan_single_manifest_file

INPUT_CSV_PATH = Path("../data/vibe_coding_scenarios_sca.csv")
OUTPUT_CSV_PATH = Path("../data/results/evaluation_results_sca.csv")
TRIVY_SERVICE_URL = "http://localhost:8001"

MODELS_TO_EVALUATE = [
    "gpt-5.4-mini",
    # "claude-sonnet-5",
    # "gemini-3.5-flash",
    # "deepseek-v4-flash",
    # "qwen3.5-flash",
    # "grok-4.5",
]


def extract_findings_from_sca_response(sca_result: dict) -> str:
    """Parses Trivy's raw JSON output payload and extracts detected

    vulnerabilities into a readable summary string.
    """
    if not sca_result:
        return "SERVICE_ERROR"

    results = sca_result.get("Results") or []
    if not results:
        return "NONE"

    detected_issues = []

    for result in results:
        vulnerabilities = result.get("Vulnerabilities") or []
        for vuln in vulnerabilities:
            cve_id = vuln.get("VulnerabilityID")
            pkg_name = vuln.get("PkgName")
            installed_version = vuln.get("InstalledVersion")

            if cve_id and pkg_name and installed_version:
                detected_issues.append(
                    f"{cve_id} ({pkg_name}@{installed_version})"
                )
            elif cve_id:
                detected_issues.append(cve_id)

    if detected_issues:
        unique_issues = list(dict.fromkeys(detected_issues))
        return ", ".join(unique_issues)

    return "NONE"


def run_sca_benchmark():
    """Main execution loop for the SCA evaluation benchmark."""
    if not INPUT_CSV_PATH.exists():
        raise FileNotFoundError(
            f"Input SCA scenario file not found at: {INPUT_CSV_PATH.resolve()}"
        )

    print(f"Loading SCA test scenarios from: {INPUT_CSV_PATH}")
    df_scenarios = pd.read_csv(INPUT_CSV_PATH)

    scenario_col = (
        "Scenario-ID"
        if "Scenario-ID" in df_scenarios.columns
        else "CWE-ID"
        if "CWE-ID" in df_scenarios.columns
        else None
    )
    if not scenario_col or "Vibe Coding Prompt" not in df_scenarios.columns:
        raise ValueError(
            "Input CSV must contain 'Vibe Coding Prompt' and either 'Scenario-ID' or 'CWE-ID'."
        )

    evaluation_records = []

    print(
        f"Starting SCA evaluation across {len(MODELS_TO_EVALUATE)} model(s)..."
    )

    for model_id in MODELS_TO_EVALUATE:
        print(f"\n==========================================")
        print(f" Evaluating SCA Model: {model_id}")
        print(f"==========================================")

        for index, row in df_scenarios.iterrows():
            scenario_id = str(row[scenario_col]).strip()
            vibe_prompt = str(row["Vibe Coding Prompt"]).strip()

            print(
                f"[{index + 1}/{len(df_scenarios)}] Running SCA prompt for {scenario_id}..."
            )

            try:
                raw_llm_response = query_llm(
                    model_id=model_id, prompt=vibe_prompt
                )

                manifest_content, inferred_filename = extract_manifest_file(
                    raw_llm_response
                )

                sca_response = scan_single_manifest_file(
                    manifest_content=manifest_content,
                    file_name=inferred_filename,
                    trivy_url=TRIVY_SERVICE_URL,
                )

                sca_result_summary = extract_findings_from_sca_response(
                    sca_response
                )

            except Exception as error:
                print(
                    f"  [ERROR] SCA Execution failed for {scenario_id} ({model_id}): {error}"
                )
                manifest_content = f"<!-- ERROR DURING GENERATION: {error} -->"
                sca_result_summary = "EXECUTION_ERROR"

            evaluation_records.append(
                {
                    "CWE-ID": scenario_id,
                    "Vibe Coding Prompt": vibe_prompt,
                    "Model": model_id,
                    "File": manifest_content,
                    "SAST Result": sca_result_summary,
                }
            )

    df_results = pd.DataFrame(evaluation_records)
    OUTPUT_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(OUTPUT_CSV_PATH, index=False, encoding="utf-8")

    print(f"\nSCA Benchmark completed successfully!")
    print(f"Results saved to: {OUTPUT_CSV_PATH.resolve()}")


if __name__ == "__main__":
    run_sca_benchmark()