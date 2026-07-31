from pathlib import Path
import re

def extract_manifest_file(llm_response: str) -> tuple[str, str]:
    if not llm_response or not llm_response.strip():
        return "", "pom.xml"

    xml_pattern = r"```(?:xml|maven|pom)\s*\n?(.*?)```"
    xml_matches = re.findall(xml_pattern, llm_response, re.DOTALL)
    if xml_matches:
        longest_match = max(xml_matches, key=len).strip()
        return longest_match, "pom.xml"

    gradle_pattern = r"```(?:gradle|groovy|kotlin)\s*\n?(.*?)```"
    gradle_matches = re.findall(gradle_pattern, llm_response, re.DOTALL)
    if gradle_matches:
        longest_match = max(gradle_matches, key=len).strip()
        filename = (
            "build.gradle.kts"
            if "val " in longest_match or "implementation(" in longest_match
            else "build.gradle"
        )
        return longest_match, filename

    generic_pattern = r"```\s*\n?(.*?)```"
    generic_matches = re.findall(generic_pattern, llm_response, re.DOTALL)
    if generic_matches:
        longest_match = max(generic_matches, key=len).strip()
        if longest_match.startswith("<") or "</project>" in longest_match:
            return longest_match, "pom.xml"
        return longest_match, "build.gradle"

    trimmed = llm_response.strip()
    if trimmed.startswith("<") or "</project>" in trimmed:
        return trimmed, "pom.xml"

    return trimmed, "build.gradle"

def extract_java_code(llm_response: str) -> str:
    if not llm_response or not llm_response.strip():
        return ""

    java_block_pattern = r"```(?:java|JAVA)\s*\n?(.*?)```"
    java_matches = re.findall(java_block_pattern, llm_response, re.DOTALL)

    if java_matches:
        longest_match = max(java_matches, key=len)
        return longest_match.strip()

    generic_block_pattern = r"```\s*\n?(.*?)```"
    generic_matches = re.findall(generic_block_pattern, llm_response, re.DOTALL)

    if generic_matches:
        longest_match = max(generic_matches, key=len)
        return longest_match.strip()

    return llm_response.strip()

def save_java_file(
    code: str, output_path: str | Path, filename: str = "GeneratedClass.java"
):
    path = Path(output_path)
    path.mkdir(parents=True, exist_ok=True)

    file_file = path / filename
    file_file.write_text(code, encoding="utf-8")
    return file_file