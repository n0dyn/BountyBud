from flask import Flask, request, jsonify
import threading
import os
import time
import logging
from orchestrator import BountyBudPipeline
from scope_monitor import ScopeMonitor

app = Flask(__name__)
logger = logging.getLogger("BountyBudAPIWorker")

def run_hunt(target):
    """Background task to run the autonomous pipeline."""
    try:
        pipeline = BountyBudPipeline(target)
        pipeline.run_autonomous_funnel()
    except Exception as e:
        logger.error(f"Error in background hunt for {target}: {e}")

def scope_poller():
    """Periodically poll for scope changes and trigger discovery."""
    monitor = ScopeMonitor()
    h1_handles = os.getenv("H1_HANDLES", "").split(",")
    bc_codes = os.getenv("BC_CODES", "").split(",")
    
    # Clean lists
    h1_handles = [h.strip() for h in h1_handles if h.strip()]
    bc_codes = [c.strip() for c in bc_codes if c.strip()]
    
    poll_interval = int(os.getenv("SCOPE_POLL_INTERVAL", "21600")) # Default 6 hours

    logger.info(f"Scope poller started. Monitoring {len(h1_handles)} H1 and {len(bc_codes)} BC programs.")

    while True:
        try:
            new_assets = monitor.check_for_updates(h1_handles, bc_codes)
            if new_assets:
                logger.info(f"Poller detected {len(new_assets)} new assets! Triggering discovery.")
                for item in new_assets:
                    asset = item["asset"]
                    # Skip non-domain assets (like mobile apps) for auto-discovery
                    if "." in asset:
                        logger.info(f"Auto-triggering discovery for {asset}")
                        thread = threading.Thread(target=run_hunt, args=(asset,))
                        thread.start()
        except Exception as e:
            logger.error(f"Scope poller error: {e}")
            
        time.sleep(poll_interval)

@app.route('/start_hunt', methods=['POST'])
def start_hunt():
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({"message": "Error: No target provided"}), 400

    # Start the hunt in a separate thread so the API remains responsive
    thread = threading.Thread(target=run_hunt, args=(target,))
    thread.start()

    return jsonify({
        "message": f"Hunt for {target} started on the Workhorse rig.",
        "status": "initiated"
    })

if __name__ == "__main__":
    # Start the scope poller in the background
    poller_thread = threading.Thread(target=scope_poller, daemon=True)
    poller_thread.start()
    
    # Listen on all interfaces so the Head machine can connect
    app.run(host='0.0.0.0', port=5000)
