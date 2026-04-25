import os
import json
import logging
import requests
import time
from typing import List, Dict, Any, Optional

logger = logging.getLogger("BountyBudScopeMonitor")
DATA_DIR = os.path.expanduser("~/.bountybud")
SCOPE_FILE = os.path.join(DATA_DIR, "scopes.json")

class ScopeMonitor:
    """
    Native Python Fetcher for HackerOne and Bugcrowd scopes.
    Keeps private data local and secure.
    """
    def __init__(self):
        self.h1_token = os.getenv("H1_TOKEN")
        self.bugcrowd_token = os.getenv("BUGCROWD_TOKEN")
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        if os.path.exists(SCOPE_FILE):
            try:
                with open(SCOPE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load scope state: {e}")
        return {"programs": {}}

    def _save_state(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        try:
            with open(SCOPE_FILE, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save scope state: {e}")

    def fetch_h1_scope(self, handle: str) -> List[str]:
        """Fetch structured scopes from HackerOne using 2026 GraphQL API."""
        if not self.h1_token:
            logger.warning("H1_TOKEN not set. Skipping H1 fetch.")
            return []

        # 2026 Method: Use the main GraphQL endpoint with H1-Token
        url = "https://hackerone.com/graphql"
        
        # Token might be formatted as 'identifier:secret' from previous attempts,
        # extract just the secret part for the H1-Token header.
        secret = self.h1_token.split(':')[-1] if ':' in self.h1_token else self.h1_token
        
        headers = {
            "H1-Token": secret,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        
        # Query for structured scopes
        query = """
        query GetProgramScope($handle: String!) {
          team(handle: $handle) {
            structured_scopes(first: 100, archived: false) {
              nodes {
                asset_identifier
                eligible_for_bounty
                instruction
              }
            }
          }
        }
        """
        
        try:
            resp = requests.post(url, headers=headers, json={"query": query, "variables": {"handle": handle}}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            nodes = data.get("data", {}).get("team", {}).get("structured_scopes", {}).get("nodes", [])
            in_scope = []
            for node in nodes:
                if node.get("eligible_for_bounty") and node.get("instruction") != "out-of-scope":
                    in_scope.append(node.get("asset_identifier"))
            
            return list(filter(None, in_scope))
        except Exception as e:
            logger.error(f"Failed to fetch H1 GraphQL scope for {handle}: {e}")
            return []

    def fetch_bugcrowd_scope(self, code: str) -> List[str]:
        """Fetch targets from Bugcrowd API using 2026 Semantic Versioning."""
        if not self.bugcrowd_token:
            logger.warning("BUGCROWD_TOKEN not set. Skipping Bugcrowd fetch.")
            return []

        # 2026 Bugcrowd API uses SemVer and target_groups for granular control
        url = f"https://api.bugcrowd.com/programs/{code}/target_groups"
        headers = {
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Authorization": f"Token {self.bugcrowd_token}",
            "Bugcrowd-Version": "v1.1.2" # April 2026 Stable Release
        }
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            # 2026 Structure: Target Groups -> Targets
            in_scope = []
            target_groups = data.get("target_groups", [])
            for group in target_groups:
                # Only pull from in-scope groups
                if group.get("in_scope"):
                    targets = group.get("targets", [])
                    for t in targets:
                        in_scope.append(t.get("name"))
            return list(filter(None, in_scope))
        except Exception as e:
            logger.error(f"Failed to fetch Bugcrowd scope for {code}: {e}")
            return []

    def fetch_h1_guidelines(self, handle: str) -> Dict[str, Any]:
        """Fetch program brief, bounty table, and exclusions from H1 using GraphQL."""
        if not self.h1_token: return {}
        
        url = "https://hackerone.com/graphql"
        secret = self.h1_token.split(':')[-1] if ':' in self.h1_token else self.h1_token
        headers = {
            "H1-Token": secret,
            "Content-Type": "application/json"
        }
        
        # 2026 Query for full program details
        query = """
        query GetGuidelines($handle: String!) {
          team(handle: $handle) {
            policy
            submission_instructions
            bounty_table {
              nodes {
                severity
                bounty_amount
              }
            }
          }
        }
        """
        try:
            resp = requests.post(url, headers=headers, json={"query": query, "variables": {"handle": handle}}, timeout=20)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("team", {})
                return {
                    "policy": data.get("policy", ""),
                    "submission_instructions": data.get("submission_instructions", ""),
                    "bounty_table": data.get("bounty_table", {}).get("nodes", [])
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to fetch H1 GraphQL guidelines for {handle}: {e}")
            return {}

    def fetch_bc_guidelines(self, code: str) -> Dict[str, Any]:
        """Fetch program brief and reward ranges from Bugcrowd."""
        if not self.bugcrowd_token: return {}

        url = f"https://api.bugcrowd.com/programs/{code}"
        headers = {
            "Accept": "application/vnd.bugcrowd.v4+json",
            "Authorization": f"Token {self.bugcrowd_token}",
            "Bugcrowd-Version": "v1.1.2"
        }
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            if resp.status_code == 200:
                data = resp.json().get("program", {})
                return {
                    "policy": data.get("policy_brief", ""),
                    "reward_ranges": data.get("reward_ranges", {}),
                    "out_of_scope_desc": data.get("out_of_scope_description", "")
                }
            return {}
        except Exception as e:
            logger.error(f"Failed to fetch Bugcrowd guidelines for {code}: {e}")
            return {}

    def check_for_updates(self, h1_handles: List[str] = [], bc_codes: List[str] = []) -> List[Dict[str, Any]]:
        """
        Poll all programs and return a list of newly added assets.
        Also updates local cache of guidelines and rules of engagement.
        """
        new_assets = []
        
        # Initialize state keys if missing
        if "guidelines" not in self.state:
            self.state["guidelines"] = {}

        # Poll HackerOne
        for handle in h1_handles:
            current_scope = self.fetch_h1_scope(handle)
            # Always fetch guidelines to keep rules up-to-date
            self.state["guidelines"][f"h1:{handle}"] = self.fetch_h1_guidelines(handle)
            
            if not current_scope: continue
            
            old_scope = self.state["programs"].get(f"h1:{handle}", [])
            delta = [asset for asset in current_scope if asset not in old_scope]
            
            if delta:
                logger.info(f"Detected {len(delta)} new assets for H1:{handle}")
                for asset in delta:
                    new_assets.append({"program": handle, "platform": "hackerone", "asset": asset})
                
            self.state["programs"][f"h1:{handle}"] = current_scope

        # Poll Bugcrowd
        for code in bc_codes:
            current_scope = self.fetch_bugcrowd_scope(code)
            # Always fetch guidelines
            self.state["guidelines"][f"bc:{code}"] = self.fetch_bc_guidelines(code)

            if not current_scope: continue
            
            old_scope = self.state["programs"].get(f"bc:{code}", [])
            delta = [asset for asset in current_scope if asset not in old_scope]
            
            if delta:
                logger.info(f"Detected {len(delta)} new assets for BC:{code}")
                for asset in delta:
                    new_assets.append({"program": code, "platform": "bugcrowd", "asset": asset})
                
            self.state["programs"][f"bc:{code}"] = current_scope

        if new_assets:
            self._save_state()
            
        return new_assets

if __name__ == "__main__":
    # Test script
    logging.basicConfig(level=logging.INFO)
    monitor = ScopeMonitor()
    # Example: monitor.check_for_updates(h1_handles=["spotify"], bc_codes=["netflix"])
