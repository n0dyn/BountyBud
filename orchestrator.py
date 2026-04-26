import os
import json
import logging
import time
import requests
import random
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

def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agents)

class ModelRouter:
    """
    Hardware-Aware Router for the 4x GPU + 256GB RAM Rig.
    Routes between vLLM (GPUs) and ktransformers (System RAM).
    """
    def __init__(self):
        # Configuration for the Hardware Map (Updated for Workhorse reality)
        self.endpoints = {
            "archivist":  os.getenv("URL_ARCHIVIST",  "http://localhost:8801/v1"), # System RAM
            "strategist": os.getenv("URL_STRATEGIST", "http://localhost:8804/v1"), # System RAM
            "researcher": os.getenv("URL_RESEARCHER", "http://localhost:8800/v1"), # GPU 0 & 1
            "brain":      os.getenv("URL_BRAIN",      "http://localhost:8802/v1"), # GPU 2
            "hand":       os.getenv("URL_HAND",       "http://localhost:8803/v1"), # GPU 3
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

        # Default 2026-Aware System Prompts with Intent Guidance
        if not system_prompt:
            # Load dynamic program context if available
            program_rules = getattr(self, 'state', {}).get("program_rules", {})
            rules_str = f"\nRULES OF ENGAGEMENT:\n{program_rules.get('policy', '')[:500]}\nEXCLUSIONS: {program_rules.get('exclusions', [])}" if program_rules else ""

            if role == "archivist":
                system_prompt = (
                    "You are the Archivist (Llama 4 Scout). Your goal is PATTERN MATCHING for 2026-era vulnerabilities. "
                    "You are looking for 'Hot Zones' where logic fails. Focus on: hydration blocks, PostMessage short-circuits, "
                    "and 405/401 API differentials. Your rationale is to filter massive data into high-signal snippets for the Brain. "
                    f"{rules_str}"
                )
            elif role == "brain":
                system_prompt = (
                    "You are the Brain (Foundation-sec-8B-R), a specialized Vulnerability Scientist. "
                    "Your intent is to find the ROOT CAUSE. Do not guess; reason through the logic flow from input source to sensitive sink. "
                    "CHAIN PERSISTENCE: Stick to one high-fidelity lead until it is proven or disproven. Do not context-switch. "
                    "Use your 32k window to think step-by-step (<think> tags). Your reasoning will guide the Hand's exploit code. "
                    f"{rules_str}"
                )
            elif role == "hand":
                system_prompt = (
                    "You are the Hand (RedSage-8B), an Expert Exploit Writer. "
                    "Your intent is to prove the Brain's hypothesis with a functional PoC. "
                    "You generate MINIMAL, high-impact curl or python code. Your reason for existence is to confirm impact. "
                    f"{rules_str}"
                )
            elif role == "strategist":
                system_prompt = (
                    "You are the Strategist (DeepSeek-R1), the ultimate Devil's Advocate and Triage Expert. "
                    "Your intent is to ELIMINATE false positives by applying the 'So What?' Rule: a finding is only valid if it has undeniable business impact. "
                    "You must KILL findings that fall into these traps: "
                    "1. Null Subject Auth Bypass (token with no privileges), "
                    "2. Browser-Blocked Payloads (e.g., Cookie scoping rejected by RFC 6265), "
                    "3. Empty Sandbox XSS (executing on isolated CDN/User-content domains), "
                    "4. No-Op Broken Access Control (200 OK with no state change), "
                    "5. Low-Impact Assets (non-core blogs without RCE potential). "
                    "Cynically prove why a finding is FAKE or LOW-IMPACT. If you verify it, provide a step-by-step evidence trace of financial or data-loss damage. "
                    f"{rules_str}"
                )

        logger.info(f"[{role.upper()}] Routing to {model} (Intent: Finding {role} result)")

        # MOCK LOGIC for testing the pipeline flow
        if os.getenv("MOCK_PIPELINE", "true") == "true":
            return self._mock_response(role)
            
        # ── Robust Retry Logic ──
        max_retries = 3
        for attempt in range(max_retries):
            try:
                headers = {"User-Agent": get_random_user_agent()}
                payload = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 4096,
                    "temperature": 0.1 # Minimal temperature for maximum accuracy
                }
                # 15 Minute Timeout (900s) for deep reasoning models
                response = requests.post(f"{url}/chat/completions", json=payload, headers=headers, timeout=900)
                response.raise_for_status()
                return response.json()['choices'][0]['message']['content']
            except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
                if attempt < max_retries - 1:
                    wait_time = (attempt + 1) * 5
                    logger.warning(f"Model call failed ({e}). Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Error calling {role} after {max_retries} attempts: {e}")
                    return "{}"
            except Exception as e:
                logger.error(f"Unexpected error calling {role}: {e}")
                return "{}"
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
            return json.dumps({
                "is_real": True, 
                "confidence": 0.98, 
                "reasoning": "Output contains valid /etc/passwd structure. Not a honeypot.",
                "false_positive_check": "Passed. Valid Unix passwd file format detected."
            })
        return "{}"

class BountyBudPipeline:
    """
    The Context Funnel Orchestration Engine.
    Implements the Wide Lens (Archivist) -> Microscope (Brain) workflow.
    """
    def __init__(self, target: str, profile: str = "STEALTH"):
        self.target = target
        self.profile = profile.upper()
        self.router = ModelRouter()
        self.state = {
            "target": target,
            "profile": self.profile,
            "hot_zones": [],
            "findings": []
        }
        
        # Configure pacing based on profile
        if self.profile == "STEALTH":
            self.min_delay = 5.0
            self.max_delay = 10.0
        elif self.profile == "CONSERVATIVE":
            self.min_delay = 1.0
            self.max_delay = 3.0
        else: # AGGRESSIVE (Default/Previous)
            self.min_delay = 0.0
            self.max_delay = 0.5

    def apply_pacing(self):
        """Apply jittered delay to stay under the radar."""
        delay = random.uniform(self.min_delay, self.max_delay)
        if delay > 0:
            logger.info(f"Stealth Mode: Waiting {delay:.2f}s before next request...")
            time.sleep(delay)

    def check_rate_limits(self, response_headers: Dict[str, str]):
        """Monitor X-RateLimit headers and pause if necessary."""
        # Normalize headers to lowercase
        headers = {k.lower(): v for k, v in response_headers.items()}
        remaining = int(headers.get('x-ratelimit-remaining', 100))
        
        if remaining < 10:
            reset_time = int(headers.get('x-ratelimit-reset', 60))
            logger.warning(f"RATE LIMIT NEAR: {remaining} left. Cooling down for {reset_time}s...")
            time.sleep(reset_time + 1)

    def run_discovery(self, depth: int = 3):
        """Step 0: The Scout - Use Katana to automatically generate traffic logs."""
        logger.info(f"=== STEP 0: THE SCOUT (Discovery) ===")
        logger.info(f"Running automated crawl on {self.target} in {self.profile} mode...")
        
        # In a real setup, this would execute the actual tool via the MCP server
        # For example: katana -u https://target -d 3 -proxy http://localhost:8080
        cmd = f"katana -u {self.target} -d {depth} -jc -kf -proxy http://localhost:8080"
        if self.profile == "STEALTH":
            cmd += " -rd 5000" # 5s delay in katana
        
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

    def run_target_profiling(self):
        """Step 0.5: Profiling - Differentiator Probing & Hydration Mining."""
        logger.info(f"=== STEP 0.5: TARGET PROFILING ===")
        
        # 1. Hydration Mining (__NEXT_DATA__)
        logger.info(f"Mining hydration state for {self.target}...")
        # In real setup: curl -s URL | grep -oP '(?<=<script id="__NEXT_DATA__" type="application/json">).*?(?=</script>)'
        self.state["hydration_data"] = {"baseUrl": "/api/v1", "leaked_preview_token": "None (Mock)"}
        
        # 2. Differentiator Probing (SPA vs Real API)
        logger.info(f"Probing differentiators (Content-Length / Type)...")
        # In real setup: for p in paths; do curl ...; done
        self.state["is_spa"] = True
        self.state["api_indicators"] = ["405 Method Not Allowed on /auth", "401 Unauthorized on /config"]
        
        logger.info("Profiling complete.")

    def load_program_context(self) -> Dict[str, Any]:
        """Load the latest guidelines and scope for this target's program."""
        scope_file = os.path.expanduser("~/.bountybud/scopes.json")
        if os.path.exists(scope_file):
            try:
                with open(scope_file, 'r') as f:
                    data = json.load(f)
                    # Find the program this target belongs to
                    for key, guidelines in data.get("guidelines", {}).items():
                        # Simple match: if target is in the program handle
                        if guidelines.get("handle") in self.target or any(self.target in s for s in data.get("programs", {}).get(key, [])):
                            return guidelines
            except Exception as e:
                logger.error(f"Failed to load program context: {e}")
        return {}

    def get_lessons_learned(self, indicators: List[str]) -> str:
        """Query the local learning.jsonl to find what has worked/failed on similar indicators."""
        learning_file = os.path.expanduser("~/.bountybud/learning.jsonl")
        if not os.path.exists(learning_file):
            return "No previous lessons learned for this target profile."
            
        lessons = []
        try:
            with open(learning_file, 'r') as f:
                for line in f:
                    entry = json.loads(line)
                    # Match by technical indicators or vulnerability type
                    if any(ind.lower() in str(entry).lower() for ind in indicators):
                        outcome = entry.get("outcome")
                        tech = entry.get("technique")
                        lessons.append(f"- {tech}: {outcome.upper()}")
            
            return "\n".join(lessons[-10:]) if lessons else "No specific history matches."
        except Exception as e:
            logger.error(f"Failed to read learning DB: {e}")
            return ""

    def run_autonomous_funnel(self, raw_logs: Optional[str] = None):
        logger.info(f"--- STARTING {self.profile} CONTEXT FUNNEL FOR {self.target} ---")
        
        # Load the legal guidelines and bounty rules
        program_context = self.load_program_context()
        if program_context:
            logger.info(f"Program guidelines loaded. Enforcing {len(program_context.get('bounty_table', []))} bounty rules.")
            # Inject guidelines into the router's base prompts
            self.state["program_rules"] = program_context
        
        # If no logs provided, run discovery first
        if not raw_logs or len(raw_logs) < 100:
            self.run_discovery()
            raw_logs = "MOCK LOG DATA" 
            
        # Perform profiling to sharpen the funnel
        self.run_target_profiling()
        
        # STEP 1: THE ARCHIVIST (The Wide Lens)
        logger.info("Step 1: Archivist filtering logs (10M Context)...")
        self.apply_pacing()
        archivist_prompt = f"Identify the 5-6 'hot zones' in these logs where vulnerabilities are likely. Logs: {raw_logs[:2000]}..."
        archivist_resp = self.router.call_model("archivist", archivist_prompt)
        self.state["hot_zones"] = json.loads(archivist_resp).get("hot_zones", [])
        logger.info(f"Archivist identified {len(self.state['hot_zones'])} hot zones.")

        # STEP 2: THE RESEARCHER (API Mapping)
        logger.info("Step 2: Researcher mapping tech stack and endpoints...")
        self.apply_pacing()
        
        # Inject lessons learned to sharpen the reconnaissance
        lessons = self.get_lessons_learned(self.state.get("api_indicators", []))
        research_prompt = (
            f"Map endpoints for target {self.target}. "
            f"HISTORICAL LESSONS LEARNED:\n{lessons}\n"
            "Use this history to avoid failed tools and prioritize successful bypasses."
        )
        research_resp = self.router.call_model("researcher", research_prompt)
        tech_context = json.loads(research_resp)

        # STEP 3 & 4: THE BRAIN & THE HAND (The Microscope)
        for zone in self.state["hot_zones"]:
            logger.info(f"--- Processing Hot Zone {zone['id']} ---")
            
            # THE BRAIN: Deep reasoning on the small snippet
            self.apply_pacing()
            kb_context = self.query_kb(zone['snippet'])
            brain_prompt = f"Analyze this specific hot zone snippet for a root cause. USE THIS EXPERT CONTEXT: {kb_context}. Snippet: {zone['snippet']}. Context: {tech_context}"
            brain_resp = self.router.call_model("brain", brain_prompt)
            hypothesis = json.loads(brain_resp)
            logger.info(f"Brain Hypothesis: {hypothesis.get('hypothesis')}")

            # THE HAND: Generate and run PoC
            self.apply_pacing()
            hand_prompt = f"Generate a PoC command for this hypothesis: {hypothesis}"
            hand_resp = self.router.call_model("hand", hand_prompt)
            poc = json.loads(hand_resp)
            
            # Simulate Execution
            poc_result = f"root:x:0:0:root:/root:/bin/bash (Result of {poc.get('poc_command')})"
            
            # STEP 5: THE STRATEGIST (The Final Judge)
            self.apply_pacing()
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

        logger.info(f"--- PIPELINE COMPLETE: {len(self.state['findings'])} Verified Findings ---")
        return self.state["findings"]

if __name__ == "__main__":
    pipeline = BountyBudPipeline("target.corp")
    # Simulate feeding 50MB of raw logs (truncated for mock)
    findings = pipeline.run_autonomous_funnel("... 50MB of raw traffic logs ...")
    print("\nFINAL VERIFIED FINDINGS:")
    print(json.dumps(findings, indent=2))
