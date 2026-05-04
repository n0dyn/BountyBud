import json
import os

config_path = os.path.expanduser("~/.openclaw/openclaw.json")

if not os.path.exists(config_path):
    print(f"Error: Config not found at {config_path}")
    exit(1)

with open(config_path, 'r') as f:
    config = json.load(f)

providers = config.get("models", {}).get("providers", {})

# 1. Remove unwanted sections
if "minimax" in providers:
    del providers["minimax"]
    print("Removed minimax provider.")

if "ollama-local" in providers:
    del providers["ollama-local"]
    print("Removed ollama-local provider.")

# 2. Add the 4-GPU Workhorse Models
workhorse_ip = "10.147.19.65"

providers["bountybud-workhorse"] = {
    "baseUrl": f"http://{workhorse_ip}:8800/v1",
    "apiKey": "none",
    "api": "openai-completions",
    "models": [
        {
            "id": "qwen-3.5-32b",
            "name": "BountyBud: Researcher (Qwen 32B)",
            "reasoning": False,
            "contextWindow": 64000,
            "maxTokens": 4096,
            "input": ["text"]
        }
    ]
}

providers["bountybud-specialists"] = {
    "baseUrl": f"http://{workhorse_ip}:8802/v1",
    "apiKey": "none",
    "api": "openai-completions",
    "models": [
        {
            "id": "foundation-sec-8b-r",
            "name": "BountyBud: Brain (Vulnerability Reasoning)",
            "reasoning": True,
            "contextWindow": 32000,
            "maxTokens": 8192,
            "input": ["text"]
        }
    ]
}

# Note: Hand (8803) can be added here too if you want to chat with it
providers["bountybud-exploit"] = {
    "baseUrl": f"http://{workhorse_ip}:8803/v1",
    "apiKey": "none",
    "api": "openai-completions",
    "models": [
        {
            "id": "redsage-8b",
            "name": "BountyBud: Hand (Exploit Writer)",
            "reasoning": False,
            "contextWindow": 32000,
            "maxTokens": 4096,
            "input": ["text"]
        }
    ]
}

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)

print("✅ OpenClaw configuration updated successfully.")
