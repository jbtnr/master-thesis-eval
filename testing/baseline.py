import os
from openai import OpenAI

MODELS_CONFIG = {
    "gpt-5.4-mini": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
    },
    "claude-sonnet-5": {
        "base_url": "https://api.anthropic.com/v1/",
        "api_key_env": "ANTHROPIC_API_KEY",
    },
    "gemini-3.5-flash": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
        "api_key_env": "GEMINI_API_KEY",
    },
    "deepseek-v4-flash": {
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
    },
    "qwen3.5-flash": {
        "base_url": "https://ws-lnpd81yvzo2w9s9g.eu-central-1.maas.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "DASHSCOPE_API_KEY",
    },
    "grok-4.5": {
        "base_url": "https://api.x.ai/v1",
        "api_key_env": "XAI_API_KEY",
    },
}

def query_llm(model_id: str, prompt: str) -> str:
    config = MODELS_CONFIG[model_id]
    api_key = os.getenv(config["api_key_env"])
    
    client = OpenAI(
        base_url=config["base_url"],
        api_key=api_key
    )

    if "claude" in model_id:
        response = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "user", "content": prompt}
            ],
        )
    else:
        response = client.chat.completions.create(
            model=model_id,
            messages=[
                {"role": "user", "content": prompt}
            ],
            temperature=0.0
        )

    
    return response.choices[0].message.content