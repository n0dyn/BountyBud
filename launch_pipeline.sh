#!/bin/bash

# ==============================================================================
# BountyBud Hardware Orchestrator - 256GB RAM / 4x 4060 Ti (16GB)
# ==============================================================================

# --- CONVENTIONS ---
# GPU 0,1: Reserved for Researcher (Qwen 32B)
# GPU 2:   Reserved for The Brain (Foundation-sec 8B)
# GPU 3:   Reserved for The Hand (RedSage 8B)
# RAM:     Reserved for Archivist (109B) & Strategist (671B) via ktransformers

echo "--- Initializing BountyBud AI Infrastructure ---"

# 1. Start Researcher (GPU 0 & 1) - vLLM
# Using 2 GPUs to fit 32B model at 4-bit/8-bit comfortably.
echo "[1/5] Launching Researcher (Qwen 3.5 32B) on GPU 0,1..."
CUDA_VISIBLE_DEVICES=0,1 python3 -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-32B-Instruct-AWQ \
    --tensor-parallel-size 2 \
    --port 8000 \
    --gpu-memory-utilization 0.90 \
    --max-model-len 64000 &

# 2. Start The Brain (GPU 2) - vLLM
# Capped at 32k context to preserve VRAM for Thinking Tokens.
echo "[2/5] Launching The Brain (Foundation-sec-8B-R) on GPU 2..."
CUDA_VISIBLE_DEVICES=2 python3 -m vllm.entrypoints.openai.api_server \
    --model foundation-sec/foundation-sec-8B-R \
    --port 8002 \
    --gpu-memory-utilization 0.85 \
    --max-model-len 32000 &

# 3. Start The Hand (GPU 3) - vLLM
# Capped at 32k context.
echo "[3/5] Launching The Hand (RedSage-8B) on GPU 3..."
CUDA_VISIBLE_DEVICES=3 python3 -m vllm.entrypoints.openai.api_server \
    --model RedSage/RedSage-8B-V0.1 \
    --port 8003 \
    --gpu-memory-utilization 0.85 \
    --max-model-len 32000 &

# 4. Start Archivist (System RAM) - ktransformers
# 109B model requires ~60GB System RAM at 4-bit.
echo "[4/5] Launching Archivist (Llama 4 Scout 109B) in System RAM..."
ktransformers --model-path llama-4-scout-109b-gguf \
    --port 8001 \
    --ctx-size 10000000 \
    --cpu-infer 1 &

# 5. Start Strategist (System RAM) - ktransformers
# 671B model requires ~130GB+ System RAM at 1.5bpw/2.0bpw.
echo "[5/5] Launching Strategist (DeepSeek-R1 671B) in System RAM..."
ktransformers --model-path deepseek-r1-671b-gguf \
    --port 8004 \
    --ctx-size 128000 \
    --cpu-infer 1 &

echo "--- All services initiated. Use 'tail -f logs/*' to monitor ---"
wait
