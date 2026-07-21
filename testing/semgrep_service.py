from typing import Any, Dict, List, Optional
import requests


class SemgrepService:

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")
        self.scan_endpoint = f"{self.base_url}/scan"

    def scan_code_blocks(
        self, code_blocks: List[Dict[str, str]]
    ) -> Optional[Dict[str, Any]]:
        payload = {"codeBlocks": code_blocks}

        try:
            response = requests.post(
                self.scan_endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=60,
            )
            response.raise_for_status()
            return response.json()

        except requests.exceptions.ConnectionError:
            print(
                f"[ERROR] Semgrep service not available."
            )
            return None
        except requests.exceptions.HTTPError as e:
            print(
                f"[ERROR] Semgrep service response: {response.status_code}: {response.text}"
            )
            return None
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Error when calling semgrep service: {e}")
            return None


def scan_single_java_file(
    code_content: str,
    file_name: str = "GeneratedClass.java",
    sast_url: str = "http://localhost:8000",
) -> Optional[Dict[str, Any]]:
    client = SemgrepService(base_url=sast_url)

    code_block = {
        "language": "java",
        "content": code_content,
        "fileName": file_name,
    }

    return client.scan_code_blocks([code_block])
