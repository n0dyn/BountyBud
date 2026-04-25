#!/bin/bash

# ==============================================================================
# 🛰️ BOUNTYBUD MISSION CONTROL v2.0 - ELITE EDITION
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

# --- Visual Setup ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Kill existing session if it exists
tmux kill-session -t $SESSION 2>/dev/null

# --- Mission Control Initialization ---
echo -e "${BLUE}🛰️ Initializing BountyBud Mission Control...${NC}"

# Create session and hide the status bar for a clean look
tmux new-session -d -s $SESSION
tmux set-option -t $SESSION status-style "bg=colour235,fg=colour136"
tmux set-option -t $SESSION status-left-length 30
tmux set-option -t $SESSION status-left "#[fg=green]Target: #[fg=white]${TARGET:-ACTIVE_HUNT} "
tmux set-option -t $SESSION status-right "#[fg=blue]%H:%M:%S #[fg=white]%d-%b-%y"

# --- Pane 1: THE ORCHESTRATOR (Main Logic) ---
# Large left pane for model reasoning
tmux rename-window -t $SESSION:0 'MISSION_LOG'
tmux send-keys -t $SESSION:0 "echo -e '${GREEN}LOG: Streaming logic from Workhorse...${NC}'; ssh $REMOTE 'tail -f ~/.bountybud/orchestrator.log'" C-m

# --- Pane 2: THE HARDWARE (GPU/RAM) ---
# Split right side for hardware monitoring
tmux split-window -h -p 40 -t $SESSION:0
tmux send-keys -t $SESSION:0.1 "ssh -t $REMOTE 'nvtop || btop'" C-m

# --- Pane 3: THE TRAFFIC (Mitmproxy) ---
# Split bottom-right for live HTTP traffic
tmux select-pane -t $SESSION:0.1
tmux split-window -v -p 50 -t $SESSION:0.1
tmux send-keys -t $SESSION:0.2 "ssh -L 8081:localhost:8081 $REMOTE 'mitmweb --mode regular --no-web-open-browser'" C-m

# --- Pane 4: THE NETWORK (Ports) ---
# Split bottom-left for a small port-sentry
tmux select-pane -t $SESSION:0.0
tmux split-window -v -p 20 -t $SESSION:0.0
tmux send-keys -t $SESSION:0.3 "echo -e '${BLUE}PORT SENTRY: Monitoring 8800-8804...${NC}'; ssh $REMOTE 'watch -n 1 \"ss -tulpn | grep -E 880\[0-4\]\"'" C-m

# Final polish: Focus on the log
tmux select-pane -t $SESSION:0.0
tmux attach-session -t $SESSION
