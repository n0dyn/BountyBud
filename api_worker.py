from flask import Flask, request, jsonify
import threading
import os
from orchestrator import BountyBudPipeline

app = Flask(__name__)

def run_hunt(target):
    """Background task to run the autonomous pipeline."""
    try:
        pipeline = BountyBudPipeline(target)
        pipeline.run_autonomous_funnel()
    except Exception as e:
        print(f"Error in background hunt for {target}: {e}")

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
    # Listen on all interfaces so the Head machine can connect
    app.run(host='0.0.0.0', port=5000)
