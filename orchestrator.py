import os
import json
import logging
import time
import requests
from typing import List, Dict, Any, Optional

# Setup Logging to both Console and File
DATA_DIR = os.path.expanduser("~/.bountybud")
os.makedirs(DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(DATA_DIR, "orchestrator.log")

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# File Handler
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setFormatter(formatter)

# Console Handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger = logging.getLogger("BountyBudOrchestrator")
logger.setLevel(logging.INFO)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

class ModelRouter:
    """
    Hardware-Aware Router for the 4x GPU + 256GB RAM Rig.
    Routes between vLLM (GPUs) and ktransformers (System RAM).
    """
    def __init__(self):
        # Configuration for the Hardware Map
        self.endpoints = {
            "archivist":  os.getenv("URL_ARCHIVIST",  "http://localhost:8001/v1"), # System RAM (ktransformers)
            "strategist": os.getenv("URL_STRATEGIST", "http://localhost:8001/v1"), # System RAM (ktransformers)
            "researcher": os.getenv("URL_RESEARCHER", "http://localhost:8000/v1"), # GPU 0 & 1 (vLLM)
            "brain":      os.getenv("URL_BRAIN",      "http://localhost:8002/v1"), # GPU 2 (vLLM)
            "hand":       os.getenv("URL_HAND",       "http://localhost:8003/v1"), # GPU 3 (vLLM)
        }
        
        self.models = {
            "archivist":  "llama-4-scout-109b",
            "strategist": "deepseek-r1-671b",
            "researcher": "qwen-3.5-32b",
            "brain":      "foundation-sec-8b-r",
            "hand":       "redsage-8b"
        }

        # Strict Context Limits for VRAM/RAM Stability
        self.context_limits = {
            "archivist":  10_000_000, # 10M (System RAM)
            "strategist": 128_000,    # 128k (System RAM)
            "researcher": 64_000,     # 64k (GPU 0/1)
            "brain":      32_000,     # 32k (GPU 2 - Room for Thinking Tokens)
            "hand":       32_000      # 32k (GPU 3 - Room for Thinking Tokens)
        }

    def call_model(self, role: str, prompt: str, system_prompt: str = "") -> str:
        url = self.endpoints.get(role)
        model = self.models.get(role)
        max_tokens = self.context_limits.get(role, 4096)

        logger.info(f"[{role.upper()}] Routing to {model} at {url} (Limit: {max_tokens}k)")

        # In a real setup, this would be a requests.post call to the vLLM/ktransformers API
        # payload = {
        #     "model": model,
        #     "messages": [
        #         {"role": "system", "content": system_prompt},
        #         {"role": "user", "content": prompt}
        #     ],
        #     "max_tokens": 4096, # Response length
        #     "temperature": 0.1
        # }
        
        # MOCK LOGIC for testing the pipeline flow
        if os.getenv("MOCK_PIPELINE", "true") == "true":
            return self._mock_response(role)
            
        try:
            response = requests.post(f"{url}/chat/completions", json=payload, timeout=300)
            return response.json()['choices'][0]['message']['content']
        except Exception as e:
            logger.error(f"Error calling {role}: {e}")
            return "{}"

    def _mock_response(self, role: str) -> str:
        """Deterministic mock responses for testing the Context Funnel."""
        if role == "archivist":
            return json.dumps({
                "hot_zones": [
                    {"id": 1, "snippet": "POST /api/v1/download?file=../../etc/passwd", "context": "Line 45201: Hidden field 'admin=true' detected in previous session."},
                    {"id": 2, "snippet": "GET /config/db.php.bak", "context": "Line 1209: Direct access to backup file identified."}
                ]
            })
        elif role == "researcher":
            return json.dumps({"tech_stack": ["nginx", "php 8.1", "mysql"], "endpoints": ["/api/v1/download", "/config/db.php.bak"]})
        elif role == "brain":
            return json.dumps({"hypothesis": "LFI leading to sensitive file disclosure via the 'file' parameter.", "target": "/api/v1/download"})
        elif role == "hand":
            return json.dumps({"poc_command": "curl -s 'http://target/api/v1/download?file=../../etc/passwd'"})
        elif role == "strategist":
            return json.dumps({"is_real": True, "confidence": 0.98, "reasoning": "Output contains valid /etc/passwd structure. Not a honeypot."})
        return "{}"

class BountyBudPipeline:
    """
    The Context Funnel Orchestration Engine.
    Implements the Wide Lens (Archivist) -> Microscope (Brain) workflow.
    """
    def __init__(self, target: str):
        self.target = target
        self.router = ModelRouter()
        self.state = {
            "target": target,
            "hot_zones": [],
            "findings": []
        }

    def run_discovery(self, depth: int = 3):
        """Step 0: The Scout - Use Katana to automatically generate traffic logs."""
        logger.info(f"=== STEP 0: THE SCOUT (Discovery) ===")
        logger.info(f"Running automated crawl on {self.target} to generate logs...")
        
        # In a real setup, this would execute the actual tool via the MCP server
        # For example: katana -u https://target -d 3 -proxy http://localhost:8080
        cmd = f"katana -u {self.target} -d {depth} -jc -kf -proxy http://localhost:8080"
        logger.info(f"Executing: {cmd}")
        
        # Simulate crawl time
        time.sleep(2) 
        logger.info("Discovery complete. Proxy logs populated.")

    def query_kb(self, query: str) -> str:
        """Query the internal BountyBud Knowledge Base for expert techniques."""
        try:
            # Connect to the local Flask API for RAG
            url = f"http://localhost:5000/api/kb/search?q={query}&limit=3"
            resp = requests.get(url, timeout=5)
            data = resp.json().get("data", [])
            context = "\n".join([f"--- {d['title']} ---\n{d['content'][:1000]}" for d in data])
            return context if context else "No specific KB entries found."
        except Exception as e:
            logger.error(f"KB Query failed: {e}")
            return "Knowledge Base offline. Proceeding with base model knowledge."

    def run_autonomous_funnel(self, raw_logs: Optional[str] = None):
        logger.info(f"--- STARTING CONTEXT FUNNEL FOR {self.target} ---")
        
        # If no logs provided, run discovery first
        if not raw_logs or len(raw_logs) < 100:
            self.run_discovery()
            raw_logs = self.fetch_traffic_logs()
        
        # STEP 1: THE ARCHIVIST (The Wide Lens)
        # Goal: Swallow the 1GB log and find the "Hot Zones"
        logger.info("Step 1: Archivist filtering logs (10M Context)...")
        archivist_prompt = f"Identify the 5-6 'hot zones' in these logs where vulnerabilities are likely. Logs: {raw_logs[:2000]}..."
        archivist_resp = self.router.call_model("archivist", archivist_prompt)
        self.state["hot_zones"] = json.loads(archivist_resp).get("hot_zones", [])
        logger.info(f"Archivist identified {len(self.state['hot_zones'])} hot zones.")

        # STEP 2: THE RESEARCHER (API Mapping)
        logger.info("Step 2: Researcher mapping tech stack and endpoints...")
        research_resp = self.router.call_model("researcher", f"Map endpoints for target {self.target}")
        tech_context = json.loads(research_resp)

        # STEP 3 & 4: THE BRAIN & THE HAND (The Microscope)
        # Goal: Process each Hot Zone individually with 32k window
        for zone in self.state["hot_zones"]:
            logger.info(f"--- Processing Hot Zone {zone['id']} ---")
            
            # THE BRAIN: Deep reasoning on the small snippet
            # INJECT KNOWLEDGE HERE
            kb_context = self.query_kb(zone['snippet'])
            brain_prompt = f"Analyze this specific hot zone snippet for a root cause. USE THIS EXPERT CONTEXT: {kb_context}. Snippet: {zone['snippet']}. Context: {tech_context}"
            brain_resp = self.router.call_model("brain", brain_prompt)
            hypothesis = json.loads(brain_resp)
            logger.info(f"Brain Hypothesis: {hypothesis.get('hypothesis')}")

            # THE HAND: Generate and run PoC
            hand_prompt = f"Generate a PoC command for this hypothesis: {hypothesis}"
            hand_resp = self.router.call_model("hand", hand_prompt)
            poc = json.loads(hand_resp)
            
            # Simulate Execution
            poc_result = f"root:x:0:0:root:/root:/bin/bash (Result of {poc.get('poc_command')})"
            
            # STEP 5: THE STRATEGIST (The Final Judge)
            # Goal: High-RAM model kills false positives
            strat_prompt = f"Verify if this PoC result is a real vulnerability or a honeypot. PoC: {poc.get('poc_command')}, Result: {poc_result}"
            strat_resp = self.router.call_model("strategist", strat_prompt)
            assessment = json.loads(strat_resp)
            
            if assessment.get("is_real"):
                logger.info("🔥 REAL VULNERABILITY CONFIRMED 🔥")
                self.state["findings"].append({
                    "zone": zone['id'],
                    "hypothesis": hypothesis,
                    "assessment": assessment
                })

        logger.info(f"--- PIPELINE COMPLETE: {len(self.state['findings'])} Verified Findings ---")
        return self.state["findings"]

if __name__ == "__main__":
    pipeline = BountyBudPipeline("target.corp")
    # Simulate feeding 50MB of raw logs (truncated for mock)
    findings = pipeline.run_autonomous_funnel("... 50MB of raw traffic logs ...")
    print("\nFINAL VERIFIED FINDINGS:")
    print(json.dumps(findings, indent=2))
