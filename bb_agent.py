import os
import json
import time
import logging
import requests
from typing import List, Dict, Any
from orchestrator import ModelRouter, BountyBudPipeline

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("BountyBudLocalAgent")

class SovereignArchitect:
    """
    A fully local autonomous agent that uses vLLM models to drive
    the BountyBud toolset without any cloud dependencies.
    """
    def __init__(self, target: str):
        self.target = target
        self.router = ModelRouter()
        self.pipeline = BountyBudPipeline(target)
        self.history = []
        self.max_steps = 20 # Prevent infinite loops
        
    def get_action(self) -> Dict[str, Any]:
        """Ask the Local Manager (Qwen 32B) for the next step."""
        system_prompt = (
            "You are the Sovereign Architect of BountyBud. You are a world-class security researcher. "
            f"Your current target is {self.target}. Your goal is to find Critical/High vulnerabilities. "
            "You have access to specialized tools and worker models: 'archivist', 'brain', 'hand', 'strategist'. "
            "Respond ONLY with a JSON object: {\"thought\": \"...\", \"action\": \"tool_name\", \"params\": {...}}"
        )
        
        # We use the Researcher (Port 8800) as the primary reasoning engine
        prompt = f"Target: {self.target}\nRecent History: {json.dumps(self.history[-5:])}\nWhat is the next logical step to find a bug?"
        
        try:
            response_raw = self.router.call_model("researcher", prompt, system_prompt=system_prompt)
            # Try to extract JSON if the model included conversational text
            if "{" in response_raw:
                json_str = response_raw[response_raw.find("{"):response_raw.rfind("}")+1]
                return json.loads(json_str)
            return {"thought": "Error parsing model response", "action": "wait", "params": {}}
        except Exception as e:
            logger.error(f"Manager reasoning failed: {e}")
            return {"thought": "Error", "action": "stop", "params": {}}

    def execute_agent_action(self, action: str, params: Dict[str, Any]) -> str:
        """Map the AI's requested action to actual local functions/tools."""
        logger.info(f"🤖 AGENT ACTION: {action} with {params}")
        
        if action == "scout":
            self.pipeline.run_discovery()
            return "Discovery complete. Proxy logs populated."
        
        elif action == "profile":
            self.pipeline.run_target_profiling()
            return "Target profiling complete. Hydration and API indicators found."
            
        elif action == "delegate":
            # Delegate to a specialized model (e.g., Archivist, Brain)
            role = params.get("role")
            task_prompt = params.get("prompt")
            result = self.router.call_model(role, task_prompt)
            return f"Specialized {role} returned: {result}"
            
        elif action == "run_tool":
            # Execute a specific CLI tool via the existing mcp_server logic
            # In real setup: this would call subprocess.run
            tool_cmd = params.get("command")
            logger.info(f"Executing local tool: {tool_cmd}")
            return f"Tool {tool_cmd} executed. (Simulated output for POC)"

        elif action == "stop":
            return "HUNT_STOPPED"
            
        return f"Unknown action: {action}"

    def run_autonomous_loop(self):
        """The main autonomous reasoning loop."""
        logger.info(f"🚀 Sovereign Architect starting hunt on {self.target}...")
        
        for step in range(self.max_steps):
            logger.info(f"--- STEP {step+1}/{self.max_steps} ---")
            
            # 1. THINK
            plan = self.get_action()
            logger.info(f"Thought: {plan.get('thought')}")
            
            action = plan.get("action")
            params = plan.get("params", {})
            
            if action == "stop":
                logger.info("Agent decided to stop the hunt.")
                break
                
            # 2. ACT
            observation = self.execute_agent_action(action, params)
            
            # 3. OBSERVE
            self.history.append({
                "step": step,
                "thought": plan.get("thought"),
                "action": action,
                "observation": observation
            })
            
            if observation == "HUNT_STOPPED": break
            
        logger.info("--- SOVEREIGN HUNT COMPLETE ---")

if __name__ == "__main__":
    import sys
    target_domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    agent = SovereignArchitect(target_domain)
    agent.run_autonomous_loop()
