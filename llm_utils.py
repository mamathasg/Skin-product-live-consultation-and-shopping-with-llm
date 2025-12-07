import requests
import os

QWEN_API_KEY = os.getenv("QWEN_API_KEY")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen3-6b-instruct")
DASHSCOPE_BASE = os.getenv("DASHSCOPE_BASE")

def ask_llm(prompt):
    headers = {
        "Authorization": f"Bearer {QWEN_API_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": QWEN_MODEL,
        "input": prompt
    }

    url = f"{DASHSCOPE_BASE}/chat/completions"
    response = requests.post(url, json=payload, headers=headers)

    if response.status_code != 200:
        return f"⚠️ LLM Error: {response.text}"

    data = response.json()
    return data["choices"][0]["message"]["content"]
