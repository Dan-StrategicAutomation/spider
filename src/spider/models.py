"""Model routing -- manages DSPy LM instances for different node types.

PRIMARY: Qwen3.5 Abliterated via Ollama (uncensored, local, fits your 3070)
FALLBACK: OpenRouter cloud models (when Ollama is unavailable)
"""

import subprocess

import dspy

from spider.config import SpiderConfig


def _ollama_available(base_url: str = "http://localhost:11434") -> bool:
    """Check if Ollama is running and responding."""
    try:
        import requests

        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False


def _is_model_pulled(model_name: str, base_url: str = "http://localhost:11434") -> bool:
    """Check if a model is already downloaded in Ollama."""
    try:
        import requests

        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=5)
        if resp.status_code != 200:
            return False
        tags = resp.json().get("models", [])
        return any(model_name in m.get("name", "") for m in tags)
    except Exception:
        return False


def pull_model(model_name: str, base_url: str = "http://localhost:11434") -> bool:
    """Pull a model into Ollama if not already present."""
    if _is_model_pulled(model_name, base_url):
        return True  # Already have it
    try:
        subprocess.run(["ollama", "pull", model_name], capture_output=True, text=True, timeout=3600)
        return True
    except Exception:
        return False


def get_lm(config: SpiderConfig, role: str = "primary") -> dspy.LM:
    """Get the appropriate DSPy LM for the given role.

    Role routing:
    - primary: Main agent (9B -- fits 8GB VRAM)
    - eval: Self-evaluation (4B -- lightweight, runs alongside)
    - fast: Quick payload generation (4B -- low latency)
    - reasoning: Attack chain planning (27B if available, else 9B)
    - fallback: Cloud model when Ollama is down
    """
    if config.openrouter_api_key and not _ollama_available(config.ollama_base_url):
        # Ollama down, use cloud fallback
        return dspy.LM(
            model=config.fallback_model,
            api_key=config.openrouter_api_key,
        )

    role_models = {
        "primary": config.primary_model,
        "eval": config.eval_model,
        "fast": config.eval_model,  # 4B is fast enough for eval + fast tasks
        "reasoning": config.primary_model,
        "fallback": config.fallback_model,
    }

    model_name = role_models.get(role, config.primary_model)

    # For cloud fallback role
    if role == "fallback" and config.openrouter_api_key:
        return dspy.LM(
            model=config.fallback_model,
            api_key=config.openrouter_api_key,
        )

    # Ollama model -- LiteLLM routes via "ollama/" prefix
    litellm_model = model_name.lstrip("ollama/")
    return dspy.LM(
        model=f"ollama/{litellm_model}",
        api_base=config.ollama_base_url,
    )


def configure_spider(config: SpiderConfig) -> dspy.LM:
    """Configure DSPy globally with the primary Ollama model.

    Call this once at application startup.
    """
    lm = get_lm(config, role="primary")
    dspy.configure(lm=lm)
    return lm


# Model selection matrix for Qwen3.5 Abliterated
# RTX 3070 Laptop (8GB VRAM):
#   - 9B Q4 (6.6GB) = primary agent, leaves ~1.4GB for system
#   - 4B Q4 (3.3GB) = eval model, runs alongside 9B
#   Total VRAM: 6.6 + 3.3 = 9.9GB -- BOTH CANNOT RUN SIMULTANEOUSLY on 8GB
#
# OPTIMIZED for 8GB VRAM:
#   - Primary: 9B Q4 (6.6GB) for all agent nodes
#   - Eval: use SAME 9B model but swap context (not simultaneous loading)
#   - Use cloud eval when primary model is loaded
#
# IF you have more VRAM available:
#   - 27B Q4 (17GB) = heavy reasoning, attack chain building
#   - 122B Q4 (81GB) = maximum quality (multiple GPUs needed)

MODEL_VRAM_REQUIREMENTS = {
    "huihui_ai/qwen3.5-abliterated:0.8B": 1.0,  # 1 GB Q4
    "huihui_ai/qwen3.5-abliterated:2B": 1.9,  # 1.9 GB Q4
    "huihui_ai/qwen3.5-abliterated:4B": 3.3,  # 3.3 GB Q4
    "huihui_ai/qwen3.5-abliterated:9b": 6.6,  # 6.6 GB Q4 <-- primary for 3070
    "huihui_ai/qwen3.5-abliterated:27b": 17.0,  # 17 GB Q4
    "huihui_ai/qwen3.5-abliterated:35b": 24.0,  # 24 GB Q4
    "huihui_ai/qwen3.5-abliterated:122B": 81.0,  # 81 GB Q4
}
