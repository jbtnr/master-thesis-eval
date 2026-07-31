import json
import re
import uuid
from datetime import datetime
from pathlib import Path
import pandas as pd
import requests

INPUT_CSV_PATH = Path("data/vibe_coding_scenarios.csv")
SECVIBER_SERVICE_URL = "http://localhost:8080/vibe/chat"

MODELS_TO_EVALUATE = [
  #  "gemini-3.5-flash",
  #  "gpt-5.4-mini",
  #  "claude-sonnet-5",
   # "deepseek-v4-flash",
   # "qwen3.5-flash",
   # "grok-4.5",
]


def extract_sast_result_from_nodes(nodes: list) -> str:
    if not nodes:
        return "NONE"

    findings = []
    for node in nodes:
        if not isinstance(node, dict):
            continue

        vuln_data = node.get("vulnerbility") or node.get("vulnerability")
        if not vuln_data:
            continue

        vuln_list = vuln_data if isinstance(vuln_data, list) else [vuln_data]

        for vuln in vuln_list:
            if not isinstance(vuln, dict):
                continue

            rule_id = vuln.get("check_id") or vuln.get("rule_id") or vuln.get("checkId") or ""
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
        return ", ".join(list(dict.fromkeys(findings)))

    return "NONE"


def query_secviber(prompt: str, model_id: str, cwe_id: str = "test") -> dict:
    payload = {
        "message": prompt,
        "model": model_id,
        "sessionId": f"eval-{model_id}-cwe{cwe_id}-{uuid.uuid4().hex[:6]}"
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
        timeout=(15, 300)
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
        raise ValueError("SSE Stream finished without delivering valid payload.")

    return last_event_data


def run_benchmark():
    if not INPUT_CSV_PATH.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_CSV_PATH.resolve()}")

    df_scenarios = pd.read_csv(INPUT_CSV_PATH)

    required_columns = {"CWE-ID", "Vibe Coding Prompt"}
    if not required_columns.issubset(df_scenarios.columns):
        raise ValueError(f"Required columns missing: {required_columns}")

    evaluation_records = []
    total_runs = len(MODELS_TO_EVALUATE) * len(df_scenarios)
    current_run = 0

    print(f"Starting Secviber Benchmark: {len(MODELS_TO_EVALUATE)} models, {len(df_scenarios)} scenarios ({total_runs} total runs)")

    for model_id in MODELS_TO_EVALUATE:
        print(f"\n==========================================")
        print(f" Evaluating Model: {model_id}")
        print(f"==========================================")

        for index, row in df_scenarios.iterrows():
            current_run += 1
            cwe_id = str(row["CWE-ID"]).strip()
            vibe_prompt = str(row["Vibe Coding Prompt"]).strip()

            total_duration = 0.0
            rag_duration = 0.0
            llm_duration = 0.0
            mitigation_duration = 0.0
            mitigation_result = {}
            nodes = []
            iterations = []
            sast_result = "EXECUTION_ERROR"
            status = "ERROR"
            has_repaired = False

            print(f"[{current_run}/{total_runs}] [{model_id}] Processing CWE-{cwe_id}...", end="", flush=True)

            try:
                response_json = query_secviber(prompt=vibe_prompt, model_id=model_id, cwe_id=cwe_id)
                data = response_json.get("data", {})

                total_duration = data.get("totalDuration", 0.0)
                rag_duration = data.get("ragDuration", 0.0)
                llm_duration = data.get("llmDuration", 0.0)
                mitigation_duration = data.get("mitigationDuration", 0.0)

                mitigation_result = data.get("mitigationResult", {})
                nodes = mitigation_result.get("nodes", [])

                iterations = mitigation_result.get("iterations", [])
                has_repaired = any(item.get("repairDuration", 0) > 0 or item.get("count", 1) > 1 for item in iterations)

                sast_result = extract_sast_result_from_nodes(nodes)
                status = "SUCCESS"
                print(f" DONE ({total_duration:.2f}s | SAST: {sast_result})")

            except Exception as error:
                print(f" FAILED! Error: {error}")
                status = "EXECUTION_ERROR"

            evaluation_records.append({
                "Timestamp": datetime.now().isoformat(),
                "CWE-ID": cwe_id,
                "Vibe Coding Prompt": vibe_prompt,
                "Model": model_id,
                "Status": status,
                "Total Duration": total_duration,
                "RAG Duration": rag_duration,
                "LLM Duration": llm_duration,
                "Mitigation Duration": mitigation_duration,
                "Was Repaired": has_repaired,
                "Mitigation Iterations": json.dumps(mitigation_result.get("iterations", []), ensure_ascii=False),
                "LLM Response": json.dumps(nodes, ensure_ascii=False),
                "SAST Result": sast_result,
            })

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    df_results = pd.DataFrame(evaluation_records)
    output_path = Path(f"data/results/sast_secviber_benchmark_results_{timestamp}.csv")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df_results.to_csv(output_path, index=False, encoding="utf-8")

    print(f"\nBenchmark finished successfully! Saved to: {output_path.resolve()}")


if __name__ == "__main__":
    run_benchmark()