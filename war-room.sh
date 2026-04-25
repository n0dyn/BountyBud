#!/bin/bash

# ==============================================================================
# BountyBud War Room Dashboard - 4x GPU / 256GB RAM Real-Time Monitor
# ==============================================================================

# Load environment
if [ -f .env ]; then
    export $(cat .env | xargs)
else
    echo "Error: .env file not found."
    exit 1
fi

REMOTE="${WORKHORSE_SSH_USER}@${WORKHORSE_IP}"
SESSION="BountyBud_WarRoom"

# Check if tmux is installed
if ! command -v tmux &> /dev/null; then
    echo "tmux not found. Please install: sudo apt install tmux"
    exit 1
fi

# Create new tmux session, detached
tmux new-session -d -s $SESSION

# Pane 1 (Top Left): Remote Orchestrator Logs
tmux send-keys -t $SESSION "ssh $REMOTE 'tail -f ~/.bountybud/orchestrator.log'" C-m

# Split vertically
tmux split-window -h -t $SESSION

# Pane 2 (Top Right): Remote Mitmproxy (requires SSH Tunneling)
# We tunnel the remote port 8081 (web UI) to local port 8081
tmux send-keys -t $SESSION "ssh -L 8081:localhost:8081 $REMOTE 'mitmweb --mode regular --no-web-open-browser'" C-m

# Split Pane 1 horizontally
tmux select-pane -t 0
tmux split-window -v -t $SESSION

# Pane 3 (Bottom Left): Remote Hardware Resources
tmux send-keys -t $SESSION "ssh -t $REMOTE 'nvtop'" C-m

# Split Pane 2 horizontally
tmux select-pane -t 2
tmux split-window -v -t $SESSION

# Pane 4 (Bottom Right): Remote Port Monitoring
tmux send-keys -t $SESSION "ssh $REMOTE 'echo --- Monitoring Model Ports ---; watch -n 1 \"ss -tulpn | grep -E 880\[0-4\]\"'" C-m

# Select the top-left pane as default
tmux select-pane -t 0

# Attach to session
tmux attach-session -t $SESSION
