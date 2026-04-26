#!/bin/bash

# ==============================================================================
# 🚀 BOUNTYBUD MISSION CONTROL v3.0 - THE DEFINITIVE EDITION
# ==============================================================================

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
else
    echo "❌ Error: .env file not found."
    exit 1
fi

REMOTE="${WORKHORSE_SSH_USER}@${WORKHORSE_IP}"
SESSION="BountyBud_WarRoom"

# Kill existing session
tmux kill-session -t $SESSION 2>/dev/null

# --- Global Tmux Config (The "Elite" Feel) ---
tmux new-session -d -s $SESSION
tmux set -g mouse on               # ALLOW SCROLLING WITH MOUSE WHEEL
tmux set -g pane-border-style fg=colour238
tmux set -g pane-active-border-style fg=colour39 # Cyan active border
tmux set -g status-style bg=default
tmux set -g status-left-length 50
tmux set -g status-left "#[fg=cyan,bold]🛰️  MISSION CONTROL #[fg=white]| #[fg=green,bold]Target: ${TARGET:-uber.com} "
tmux set -g status-right "#[fg=white]%H:%M:%S #[fg=cyan,bold]v3.0"

# --- Pane 1: THE ORCHESTRATOR (Scrollable Logs) ---
tmux rename-window -t $SESSION:0 'MISSION_LOG'
tmux send-keys -t $SESSION:0 "echo -e '\033[1;34m[SENTRY] Connecting to Workhorse Logic Stream...\033[0m'; ssh $REMOTE 'tail -f ~/.bountybud/orchestrator.log'" C-m

# --- Pane 2: THE HARDWARE (Remote Resource Pulse) ---
tmux split-window -h -p 40 -t $SESSION:0
tmux send-keys -t $SESSION:0.1 "echo -e '\033[1;34m[SENTRY] Connecting to GPU/RAM Pulse...\033[0m'; ssh -t $REMOTE 'nvtop || btop'" C-m

# --- Pane 3: THE TRAFFIC (Live Tunnel) ---
tmux select-pane -t $SESSION:0.1
tmux split-window -v -p 50 -t $SESSION:0.1
tmux send-keys -t $SESSION:0.2 "echo -e '\033[1;34m[SENTRY] Opening Auto-Healing Tunnel to Mitmproxy (Localhost:8081)...\033[0m'; while true; do ssh -L 8081:localhost:8081 $REMOTE '~/dev/BountyBud/venv/bin/mitmweb --mode regular@9999 --no-web-open-browser'; sleep 2; done" C-m

# --- Pane 4: THE NETWORK (Port Health) ---
tmux select-pane -t $SESSION:0.0
tmux split-window -v -p 20 -t $SESSION:0.0
tmux send-keys -t $SESSION:0.3 "ssh $REMOTE 'watch -n 1 \"echo [PORT STATUS]; ss -tulpn | grep -E 880\\\[0-4\\\]\"'" C-m

# Focus the log and attach
tmux select-pane -t $SESSION:0.0
tmux attach-session -t $SESSION
