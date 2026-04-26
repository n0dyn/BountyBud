from flask import Flask, request, jsonify
import threading
import os
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from orchestrator import BountyBudPipeline
from scope_monitor import ScopeMonitor
from notifications import send_telegram_msg

app = Flask(__name__)
logger = logging.getLogger("BountyBudSwarm")

# GALAXY-CLASS SWARM CONFIG
# Managed pool for concurrent hunts and recursive pivots
MAX_CONCURRENT_HUNTS = int(os.getenv("MAX_CONCURRENT_HUNTS", "5"))
executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_HUNTS)
active_tasks = {}

def run_swarm_task(target, profile="STEALTH"):
    """Managed execution block for a single hunt/pivot."""
    task_id = f"{target}_{int(time.time())}"
    active_tasks[task_id] = {
        "target": target,
        "status": "running",
        "start_time": time.ctime(),
        "profile": profile
    }
    
    try:
        logger.info(f"🐝 Swarm Task Started: {target} (ID: {task_id})")
        pipeline = BountyBudPipeline(target, profile=profile)
        pipeline.run_autonomous_funnel()
        active_tasks[task_id]["status"] = "completed"
        active_tasks[task_id]["end_time"] = time.ctime()
    except Exception as e:
        logger.error(f"❌ Swarm Task Failed ({target}): {e}")
        active_tasks[task_id]["status"] = "failed"
        active_tasks[task_id]["error"] = str(e)

def scope_poller():
    """Periodically poll for scope changes and trigger discovery."""
    monitor = ScopeMonitor()
    h1_handles = os.getenv("H1_HANDLES", "").split(",")
    bc_codes = os.getenv("BC_CODES", "").split(",")
    
    h1_handles = [h.strip() for h in h1_handles if h.strip()]
    bc_codes = [c.strip() for c in bc_codes if c.strip()]
    
    poll_interval = int(os.getenv("SCOPE_POLL_INTERVAL", "21600"))

    logger.info(f"Surveillance Active: Monitoring {len(h1_handles)} H1 and {len(bc_codes)} BC programs.")

    while True:
        try:
            new_assets = monitor.check_for_updates(h1_handles, bc_codes)
            if new_assets:
                # Send Telegram Alert
                msg = f"🔥 *BountyBud: {len(new_assets)} NEW ASSETS DETECTED* 🔥\n"
                for item in new_assets:
                    msg += f"- *{item['platform'].upper()}*: `{item['program']}` -> `{item['asset']}`\n"
                    # Add to Swarm immediately if it's a domain
                    if "." in item["asset"]:
                        executor.submit(run_swarm_task, item["asset"])
                
                msg += "\n🚀 Swarm tasks initiated for all domain assets."
                send_telegram_msg(msg)
        except Exception as e:
            logger.error(f"Scope poller error: {e}")
            
        time.sleep(poll_interval)

@app.route('/status', methods=['GET'])
def get_swarm_status():
    """Returns the current state of all active and completed swarm tasks."""
    return jsonify({
        "swarm_size": MAX_CONCURRENT_HUNTS,
        "active_tasks_count": len([t for t in active_tasks.values() if t["status"] == "running"]),
        "tasks": active_tasks
    })

@app.route('/start_hunt', methods=['POST'])
def start_hunt():
    data = request.get_json()
    target = data.get('target')
    profile = data.get('profile', 'STEALTH')
    
    if not target:
        return jsonify({"message": "Error: No target provided"}), 400

    # Submit task to the Swarm Executor (Non-blocking)
    executor.submit(run_swarm_task, target, profile)

    return jsonify({
        "message": f"Target {target} added to the BountyBud Swarm.",
        "status": "queued_in_swarm",
        "profile": profile
    })

if __name__ == "__main__":
    # Start the scope poller in the background
    poller_thread = threading.Thread(target=scope_poller, daemon=True)
    poller_thread.start()
    
    # Listen on all interfaces
    app.run(host='0.0.0.0', port=5000)
