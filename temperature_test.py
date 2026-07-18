from openai import OpenAI
import sys
import os

OUTPUT_CSV = "sca_vibe_coding_scenarios.csv"

if not os.environ.get("OPENAI_API_KEY"):
    print("Error: Please set the OPENAI_API_KEY environment variable.")
    sys.exit(1)

client = OpenAI()

try:
    response = client.chat.completions.create(
        model="gpt-5.4-mini",
        messages=[
            {"role": "user", "content": "Test. Funktioniert der Parameter 'Temperature' noch?"}
        ],
        temperature=0
    )
    
    raw_content = response.choices[0].message.content
    print(raw_content)

except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)