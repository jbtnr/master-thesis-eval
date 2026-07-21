from typing import Any, Dict, Optional
import requests


class TrivyService:

    def __init__(self, base_url: str = "http://localhost:8001"):
        self.base_url = base_url.rstrip("/")
        self.scan_endpoint = f"{self.base_url}/scan-dependencies"

    def scan_manifest(
        self, content: str, file_name: str = "pom.xml"
    ) -> Optional[Dict[str, Any]]:
        """Sends build manifest content to the FastAPI Trivy SCA service.

        Matches ScanRequest schema: {"files": {virtual_path: content}}
        """
        payload = {"files": {file_name: content}}

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
                f"[ERROR] Trivy SCA service at {self.scan_endpoint} is unreachable."
            )
            print("        Ensure the Docker container is running on port 8001.")
            return None
        except requests.exceptions.HTTPError as e:
            print(
                f"[ERROR] Trivy SCA service responded with HTTP {response.status_code}: {response.text}"
            )
            return None
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Unexpected request error during SCA scan: {e}")
            return None


def scan_single_manifest_file(
    manifest_content: str,
    file_name: str = "pom.xml",
    trivy_url: str = "http://localhost:8001",
) -> Optional[Dict[str, Any]]:
    """Helper function to directly scan a single manifest file content string."""
    client = TrivyService(base_url=trivy_url)
    return client.scan_manifest(content=manifest_content, file_name=file_name)