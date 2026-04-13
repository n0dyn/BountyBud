#!/bin/bash

# ==============================================================================
# BountyBud War Room Dashboard - 4x GPU / 256GB RAM Real-Time Monitor
# ==============================================================================

SESSION="BountyBud_WarRoom"

# Check if tmux is installed
if ! command -v tmux &> /dev/null; then
    echo "tmux not found. Please install: sudo apt install tmux"
    exit 1
fi

# Create new tmux session, detached
tmux new-session -d -s $SESSION

# Pane 1 (Top Left): Orchestrator Logs
tmux send-keys -t $SESSION "tail -f ~/.bountybud/orchestrator.log" C-m

# Split vertically
tmux split-window -h -t $SESSION

# Pane 2 (Top Right): Mitmproxy / Live Traffic
# Note: This pane will show the live HTTP requests being generated
tmux send-keys -t $SESSION "mitmweb --mode regular --no-web-open-browser" C-m

# Split Pane 1 horizontally
tmux select-pane -t 0
tmux split-window -v -t $SESSION

# Pane 3 (Bottom Left): Hardware Resources (nvtop & btop)
# We use btop for RAM and nvtop for GPUs
tmux send-keys -t $SESSION "nvtop" C-m

# Split Pane 2 horizontally
tmux select-pane -t 2
tmux split-window -v -t $SESSION

# Pane 4 (Bottom Right): Model Server Logs (Tail all 5 ports)
tmux send-keys -t $SESSION "echo '--- Monitoring Model Ports 8000-8004 ---'; watch -n 1 'ss -tulpn | grep -E \"800[0-4]\"'" C-m

# Select the top-left pane as default
tmux select-pane -t 0

# Attach to session
tmux attach-session -t $SESSION
