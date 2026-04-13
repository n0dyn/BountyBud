#!/bin/bash

# ==============================================================================
# BountyBud Model Downloader - Optimized for 256GB RAM / 4x 16GB GPU
# ==============================================================================

# Ensure huggingface-cli is installed
if ! command -v huggingface-cli &> /dev/null; then
    echo "huggingface-cli not found. Installing..."
    pip install -U "huggingface_hub[cli]"
fi

# Define Model Directory
MODEL_DIR="$HOME/models"
mkdir -p "$MODEL_DIR"

echo "--- Starting Download of the 5-Model Pipeline ---"

# 1. Researcher (GPU 0,1) - Qwen 32B (AWQ for vLLM)
echo "[1/5] Downloading Researcher: Qwen2.5-32B-Instruct-AWQ..."
huggingface-cli download Qwen/Qwen2.5-32B-Instruct-AWQ --local-dir "$MODEL_DIR/researcher" --local-dir-use-symlinks False

# 2. The Brain (GPU 2) - Foundation-sec-8B-R (vLLM)
echo "[2/5] Downloading The Brain: foundation-sec-8B-R..."
huggingface-cli download foundation-sec/foundation-sec-8B-R --local-dir "$MODEL_DIR/brain" --local-dir-use-symlinks False

# 3. The Hand (GPU 3) - RedSage-8B (vLLM)
echo "[3/5] Downloading The Hand: RedSage-8B-V0.1..."
huggingface-cli download RedSage/RedSage-8B-V0.1 --local-dir "$MODEL_DIR/hand" --local-dir-use-symlinks False

# 4. Archivist (System RAM) - Llama 3.1 70B/109B (GGUF for ktransformers)
# Note: Using Llama-3.1-70B-Instruct-GGUF as the current high-parameter stable choice
echo "[4/5] Downloading Archivist: Llama-3.1-70B-Instruct-GGUF (Q4_K_M)..."
huggingface-cli download MaziyarPanahi/Llama-3.1-70B-Instruct-GGUF Llama-3.1-70B-Instruct.Q4_K_M.gguf --local-dir "$MODEL_DIR/archivist" --local-dir-use-symlinks False

# 5. Strategist (System RAM) - DeepSeek-R1 671B (GGUF for ktransformers)
# Note: Using the 1.5bpw or 2.0bpw GGUF to fit in 256GB RAM comfortably.
echo "[5/5] Downloading Strategist: DeepSeek-R1-GGUF (IQ2_XXS)..."
huggingface-cli download unsloth/DeepSeek-R1-GGUF DeepSeek-R1-IQ2_XXS.gguf --local-dir "$MODEL_DIR/strategist" --local-dir-use-symlinks False

echo "--- Downloads Complete. Models are located in $MODEL_DIR ---"
