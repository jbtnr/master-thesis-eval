import json
import uuid
from datetime import datetime
from pathlib import Path
import pandas as pd
import requests

from markdown_extractor import extract_manifest_file

INPUT_CSV_PATH = Path("data/sca_vibe_coding_scenarios.csv")
SECVIBER_SERVICE_URL = "http://localhost:8080/vibe/chat"

MODELS_TO_EVALUATE = [
    # "gpt-5.4-mini",
    # "claude-sonnet-5",
     "gemini-3.5-flash",
   # "deepseek-v4-flash",
   #  "qwen3.5-flash",
   #  "grok-4.5",
]


def extract_sca_from_nodes(nodes: list) -> tuple[dict | list, str]:
    if not nodes:
        return {}, "NONE"

    for node in nodes:
        if isinstance(node, dict):
            for key in ("supplyVulnerbility", "supplyVulnerability"):
                if key in node:
                    val = node[key]

                    if val is None:
                        return {}, "NONE"

                    if isinstance(val, str):
                        try:
                            parsed = json.loads(val)
                            return parsed, val
                        except json.JSONDecodeError:
                            return {}, val

                    if isinstance(val, (dict, list)):
                        return val, json.dumps(val, ensure_ascii=False)

    return {}, "NONE"


def extract_manifest_code_from_nodes(nodes: list) -> str:
    if not nodes:
        return ""

    code_blocks = []
    for node in nodes:
        if isinstance(node, dict):
            node_type = str(node.get("type", "")).upper()
            if node_type == "CODE_BLOCK" or "language" in node:
                code = node.get("content") or node.get("code") or ""
                if code.strip():
                    code_blocks.append(code.strip())

    if code_blocks:
        return "\n\n".join(code_blocks)

    raw_text = extract_raw_text_from_nodes(nodes)
    extracted, _ = extract_manifest_file(raw_text)
    return extracted


def parse_trivy_sca_response(sca_result: dict | list) -> dict:
    if not sca_result:
        return {
            "SCA_Status": "NONE",
            "SCA_Total_CVE_Count": 0,
            "SCA_High_Critical_Count": 0,
            "SCA_Critical_High_CVEs": "NONE",
        }

    if isinstance(sca_result, list):
        results = sca_result
    elif isinstance(sca_result, dict):
        if isinstance(sca_result.get("Results"), list):
            results = sca_result["Results"]
        elif "Vulnerabilities" in sca_result or "Target" in sca_result:
            results = [sca_result]
        else:
            results = []
    else:
        results = []

    if not results:
        return {
            "SCA_Status": "NONE",
            "SCA_Total_CVE_Count": 0,
            "SCA_High_Critical_Count": 0,
            "SCA_Critical_High_CVEs": "NONE",
        }

    direct_high_critical_cves = []
    total_cve_count = 0

    for result in results:
        if not isinstance(result, dict):
            continue

        packages = result.get("Packages") or []
        direct_pkg_ids = {
            pkg.get("ID")
            for pkg in packages
            if isinstance(pkg, dict) and pkg.get("Relationship") == "direct"
        }

        vulnerabilities = result.get("Vulnerabilities") or []

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            pkg_id = vuln.get("PkgID")

            # Falls direkte Dependencies bekannt sind, nur diese betrachten
            if direct_pkg_ids and pkg_id and pkg_id not in direct_pkg_ids:
                continue

            total_cve_count += 1

            severity = str(vuln.get("Severity", "")).upper()

            if severity in {"HIGH", "CRITICAL"}:
                cve_id = vuln.get("VulnerabilityID", "UNKNOWN")
                pkg_name = vuln.get("PkgName", "UNKNOWN")
                installed_version = vuln.get("InstalledVersion", "UNKNOWN")

                direct_high_critical_cves.append(
                    f"{cve_id}[{severity}] ({pkg_name}@{installed_version})"
                )

    unique_high_critical = list(dict.fromkeys(direct_high_critical_cves))

    return {
        "SCA_Status": (
            "VULNERABLE_DIRECT"
            if unique_high_critical
            else "CLEAN"
        ),
        "SCA_Total_CVE_Count": total_cve_count,
        "SCA_High_Critical_Count": len(unique_high_critical),
        "SCA_Critical_High_CVEs": (
            ", ".join(unique_high_critical)
            if unique_high_critical
            else "NONE"
        ),
    }


def extract_raw_text_from_nodes(nodes: list) -> str:
    if not nodes:
        return ""

    texts = []
    for node in nodes:
        if isinstance(node, dict):
            content = (
                node.get("content")
                or node.get("code")
                or node.get("text")
                or node.get("message")
                or ""
            )
            if content:
                texts.append(str(content))
        elif isinstance(node, str):
            texts.append(node)

    if texts:
        return "\n\n".join(texts)
    
    return json.dumps(nodes, ensure_ascii=False)


def query_secviber(prompt: str, model_id: str, scenario_id: str = "test") -> dict:
    payload = {
        "message": prompt,
        "model": model_id,
        "sessionId": f"eval-sca-{model_id}-{scenario_id}-{uuid.uuid4().hex[:6]}"
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream"
    }

    response = requests.post(
        SECVIBER_SERVICE_URL,
        json=payload,
        headers=headers,
        stream=True,
        timeout=None
    )
    response.raise_for_status()

    last_event_data = None

    for line in response.iter_lines():
        if not line:
            continue

        line_str = line.decode("utf-8").strip()

        if line_str.startswith("data:"):
            raw_data = line_str[5:].strip()

            if raw_data == "[DONE]":
                break

            try:
                parsed_json = json.loads(raw_data)
                last_event_data = parsed_json
            except json.JSONDecodeError:
                continue

    if not last_event_data:
        raise ValueError("Got no valid response data.")

    return last_event_data


def run_secviber_sca_benchmark():
    if not INPUT_CSV_PATH.exists():
        raise FileNotFoundError(
            f"Input SCA scenario file not found at: {INPUT_CSV_PATH.resolve()}"
        )

    print(f"Loading SCA test scenarios from: {INPUT_CSV_PATH}")
    df_scenarios = pd.read_csv(INPUT_CSV_PATH)

    scenario_col = None
    for col in ["Scenario_ID", "Scenario-ID", "CWE-ID"]:
        if col in df_scenarios.columns:
            scenario_col = col
            break

    prompt_col = None
    for col in ["Vibe_Coding_Prompt", "Vibe Coding Prompt"]:
        if col in df_scenarios.columns:
            prompt_col = col
            break

    if not scenario_col or not prompt_col:
        raise ValueError(
            "Input CSV muss 'Scenario_ID' (oder 'CWE-ID') und 'Vibe_Coding_Prompt' enthalten."
        )

    evaluation_records = []
    total_runs = len(MODELS_TO_EVALUATE) * len(df_scenarios)
    current_run = 0

    print(
        f"Starting Secviber SCA Benchmark: {len(MODELS_TO_EVALUATE)} models, "
        f"{len(df_scenarios)} scenarios ({total_runs} total runs)"
    )

    for model_id in MODELS_TO_EVALUATE:
        print(f"\n==========================================")
        print(f" Evaluating Secviber SCA Model: {model_id}")
        print(f"==========================================")

        for index, row in df_scenarios.iterrows():
            current_run += 1
            scenario_id = str(row[scenario_col]).strip()
            vibe_prompt = str(row[prompt_col]).strip()

            total_duration = 0.0
            rag_duration = 0.0
            llm_duration = 0.0
            mitigation_duration = 0.0
            mitigation_result = {}
            nodes = []
            status = "ERROR"
            has_repaired = False
            manifest_content = ""
            sca_metrics = {}
            sca_result = "NONE"

            print(
                f"[{current_run}/{total_runs}] [{model_id}] Processing SCA {scenario_id}...",
                end="",
                flush=True
            )

            try:
                response_json = query_secviber(
                    prompt=vibe_prompt, model_id=model_id, scenario_id=scenario_id
                )
                data = response_json.get("data", {})

                total_duration = data.get("totalDuration", 0.0)
                rag_duration = data.get("ragDuration", 0.0)
                llm_duration = data.get("llmDuration", 0.0)
                mitigation_duration = data.get("mitigationDuration", 0.0)

                mitigation_result = data.get("mitigationResult", {})
                nodes = mitigation_result.get("nodes", [])

                iterations = mitigation_result.get("iterations", [])
                has_repaired = any(
                    item.get("repairDuration", 0) > 0 or item.get("count", 1) > 1
                    for item in iterations
                )

                manifest_content = extract_manifest_code_from_nodes(nodes)

                sca_dict, sca_result = extract_sca_from_nodes(nodes)
                sca_metrics = parse_trivy_sca_response(sca_dict)

                status = "SUCCESS"
                print(
                    f" DONE ({total_duration:.2f}s | SCA Status: {sca_metrics.get('SCA_Status')})"
                )

            except Exception as error:
                print(f" FAILED! Error: {error}")
                status = "EXECUTION_ERROR"
                sca_result = f"EXECUTION_ERROR: {error}"
                manifest_content = f"<!-- ERROR DURING GENERATION: {error} -->"
                sca_metrics = {
                    "SCA_Status": "EXECUTION_ERROR",
                    "SCA_Total_CVE_Count": -1,
                    "SCA_High_Critical_Count": -1,
                    "SCA_Critical_High_CVEs": f"ERROR: {error}",
                }

            record = {
                "Timestamp": datetime.now().isoformat(),
                "CWE-ID": scenario_id,
                "Vibe Coding Prompt": vibe_prompt,
                "Model": model_id,
                "Status": status,
                "Total Duration": total_duration,
                "RAG Duration": rag_duration,
                "LLM Duration": llm_duration,
                "Mitigation Duration": mitigation_duration,
                "Was Repaired": has_repaired,
                "Mitigation Iterations": json.dumps(
                    mitigation_result.get("iterations", []), ensure_ascii=False
                ),
                "File": manifest_content,
                "LLM Response": json.dumps(nodes, ensure_ascii=False),
                "SCA Result": sca_result,
            }

            record.update(sca_metrics)
            evaluation_records.append(record)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df_results = pd.DataFrame(evaluation_records)
    output_path = Path(
        f"data/results/sca_secviber_benchmark_results_{timestamp}.csv"
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(output_path, index=False, encoding="utf-8")

    print(f"\nSecviber SCA Benchmark completed successfully!")
    print(f"Results saved to: {output_path.resolve()}")


if __name__ == "__main__":
    run_secviber_sca_benchmark()