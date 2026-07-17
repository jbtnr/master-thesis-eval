import urllib.request
import yaml
import re
import csv

URL = "https://semgrep.dev/c/p/owasp-top-ten"
INPUT_CSV = "clean_filtered_cwe_table.csv"
OUTPUT_CSV = "clean_filtered_cwe_table_with_rules.csv"

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

cwe_to_rules = {}

print("Extracting CWE mappings from Semgrep rules...")
for rule in data.get('rules', []):
    rule_id = rule.get('id')
    metadata = rule.get('metadata', {})
    
    found_cwes = re.findall(r'CWE-(\d+)', str(metadata))
    
    for cwe_num in set(found_cwes):
        cwe_id_str = str(int(cwe_num)) 
        if cwe_id_str not in cwe_to_rules:
            cwe_to_rules[cwe_id_str] = []
        cwe_to_rules[cwe_id_str].append(rule_id)

print(f"Found mappings for {len(cwe_to_rules)} distinct CWEs in the ruleset.")

print(f"Updating CSV file '{INPUT_CSV}'...")
try:
    with open(INPUT_CSV, mode='r', encoding='utf-8') as infile, \
         open(OUTPUT_CSV, mode='w', encoding='utf-8', newline='') as outfile:
        
        reader = csv.DictReader(infile)
        
        if reader.fieldnames is None:
            print("Error: CSV file is empty or has no headers.")
            exit(1)
            
        fieldnames = reader.fieldnames + ['Semgrep Rule ID']
        
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        
        match_count = 0
        row_count = 0
        
        for row in reader:
            row_count += 1
            cwe_id = row.get('CWE-ID', '').strip()
            
            matching_rules = cwe_to_rules.get(cwe_id, [])
            if matching_rules:
                row['Semgrep Rule ID'] = ", ".join(matching_rules)
                match_count += 1
            else:
                row['Semgrep Rule ID'] = ""
                
            writer.writerow(row)
            
    print("\nProcessing complete:")
    print(f" -> Total rows processed: {row_count}")
    print(f" -> Rows successfully matched with Semgrep rules: {match_count}")
    print(f" -> Output saved to: '{OUTPUT_CSV}'")

except FileNotFoundError:
    print(f"Error: The file '{INPUT_CSV}' was not found in the current directory.")
except Exception as e:
    print(f"An error occurred while processing the CSV: {e}")