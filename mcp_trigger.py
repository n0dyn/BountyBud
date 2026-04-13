import mcp.server.fastmcp as fastmcp
import requests
import os
from dotenv import load_dotenv

# Load the environment variables
load_dotenv()
mcp = fastmcp.FastMCP("BountyBud_Remote")

@mcp.tool()
def start_remote_hunt(target_url: str):
    """
    Commands the 4-GPU Workhorse to start an autonomous hunt.
    All reasoning, traffic, and audit logs are stored ON THE WORKHORSE.
    """
    # Use the environment variable, but allow for dynamic override if needed
    api_url = os.getenv("WORKHORSE_API_URL")
    if not api_url:
        return "Error: WORKHORSE_API_URL not set in .env"

    payload = {"target": target_url}

    try:
        # Send the trigger to the Workhorse API
        response = requests.post(api_url, json=payload, timeout=10)
        return response.json().get("message", "Hunt initiated successfully.")
    except Exception as e:
        return f"Error connecting to Workhorse API at {api_url}: {e}"

if __name__ == "__main__":
    mcp.run()
