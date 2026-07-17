import urllib.request
import yaml
import re

URL = "https://semgrep.dev/c/p/owasp-top-ten"

print("Downloading ruleset...")
req = urllib.request.Request(
    URL, 
    headers={'User-Agent': 'Mozilla/5.0'} 
)

try:
    with urllib.request.urlopen(req) as response:
        ruleset_data = response.read().decode('utf-8')
except Exception as e:
    print(f"Error while downloading: {e}")
    exit(1)

print("Parsing ruleset...")
data = yaml.safe_load(ruleset_data)

java_cwes = set()
rule_count = 0

for rule in data.get('rules', []):
    languages = [lang.lower() for lang in rule.get('languages', [])]
    if 'java' in languages:
        rule_count += 1
        metadata = rule.get('metadata', {})
        cwe_field = metadata.get('cwe', [])
        
        if isinstance(cwe_field, str):
            cwe_field = [cwe_field]
        elif not isinstance(cwe_field, list):
            cwe_field = []
            
        for cwe_str in cwe_field:
            match = re.search(r'CWE-\d+', cwe_str, re.IGNORECASE)
            if match:
                java_cwes.add(match.group(0).upper())

print("\n=== RESULTS ===")
print(f"Analysed rules: {rule_count}")
print(f"Found ({len(java_cwes)} CWEs relevant for java):")
print(sorted(list(java_cwes)))