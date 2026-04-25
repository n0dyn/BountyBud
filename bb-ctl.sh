#!/bin/bash

# ==============================================================================
# BountyBud Remote Controller (Run this on the Head Machine)
# ==============================================================================

# Load environment
if [ -f .env ]; then
    export $(cat .env | xargs)
else
    echo "Error: .env file not found."
    exit 1
fi

REMOTE="${WORKHORSE_SSH_USER}@${WORKHORSE_IP}"
REMOTE_PATH="~/dev/BountyBud"

case "$1" in
    sync)
        echo "🔄 Syncing code to Workhorse ($REMOTE)..."
        rsync -avz --exclude 'venv' --exclude '.git' --exclude '.env' --exclude '__pycache__' ./ "$REMOTE:$REMOTE_PATH"
        echo "✅ Sync complete."
        ;;
    
    start)
        echo "🚀 Starting AI Security Team on Workhorse..."
        # Start models and worker in detached tmux sessions on the remote
        ssh "$REMOTE" "cd $REMOTE_PATH && tmux new-session -d -s BB_MODELS './launch_pipeline.sh'"
        ssh "$REMOTE" "cd $REMOTE_PATH && tmux new-session -d -s BB_WORKER 'source venv/bin/activate && python3 api_worker.py'"
        echo "✅ Services initiated. Use './bb-ctl.sh status' to verify."
        ;;

    stop)
        echo "🛑 Stopping all Workhorse services..."
        ssh "$REMOTE" "tmux kill-session -t BB_MODELS; tmux kill-session -t BB_WORKER; pkill -f vllm; pkill -f ktransformers; pkill -f api_worker"
        echo "✅ Services stopped."
        ;;

    status)
        echo "📊 Workhorse Status ($WORKHORSE_IP):"
        ssh "$REMOTE" "echo '--- AI Model Ports ---'; ss -tulpn | grep -E '880[0-4]'; echo '--- API Worker ---'; ss -tulpn | grep :5000"
        ;;

    logs)
        echo "📜 Tailing Orchestrator Logs from Workhorse..."
        ssh "$REMOTE" "tail -f ~/.bountybud/orchestrator.log"
        ;;

    *)
        echo "Usage: $0 {sync|start|stop|status|logs}"
        echo "  sync   - Pushes latest code changes to the Workhorse"
        echo "  start  - Starts the 5-model pipeline and API worker"
        echo "  stop   - Kills all remote processes"
        echo "  status - Checks if model ports and worker are active"
        echo "  logs   - Tails the real-time hunt logs"
        exit 1
esac
