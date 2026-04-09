"""SpiderConfig -- centralized pydantic-settings configuration."""

from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SpiderConfig(BaseSettings):
    """Configuration for SPIDER.

    All settings can be set via environment variables with SPIDER_ prefix
    or via a .env file in the project root.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",
        extra="ignore",
    )

    # ── LLM Configuration ──────────────────────────────────────────────

    @field_validator(
        "excluded_targets", "allowed_targets", "lab_targets", "available_tools", mode="before"
    )
    @classmethod
    def split_csv(cls, v: Any) -> Any:
        """Split comma-separated strings into lists, bypassing strict JSON parsing."""
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json

                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    # PRIMARY: Qwen3.5 Abliterated via Ollama (uncensored, local, fast)
    # FALLBACK: OpenRouter cloud models (when local is unavailable)

    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama endpoint for primary model execution",
    )

    # Primary agent model -- Qwen3.5 abliterated (uncensored for pentesting)
    # Sizes available on Ollama: 0.8B(1GB), 2B(1.9GB), 4B(3.3GB), 9B(6.6GB), 27B(17GB), 35B(24GB)
    # RTX 3070 Laptop (8GB VRAM): use 9B (6.6GB) for main agent
    primary_model: str = Field(
        default="huihui_ai/qwen3.5-abliterated:9b",
        description="Primary Qwen3.5 abliterated model for DSPy nodes (Ollama)",
    )

    # Self-evaluation model -- smaller is fine, runs alongside primary
    eval_model: str = Field(
        default="huihui_ai/qwen3.5-abliterated:4b",
        description="Lighter model for self-evaluation and reward scoring (Ollama)",
    )

    # Cloud fallback -- used only when Ollama is unavailable
    openrouter_api_key: str = Field(default="", description="OpenRouter API key for cloud fallback")
    fallback_model: str = Field(
        default="anthropic/claude-sonnet-4-5-20250929",
        description="Cloud model fallback when Ollama is unavailable",
    )

    # Safety Configuration
    allowed_targets: Any = Field(
        default_factory=list,
        description="CIDR ranges or hosts allowed for testing",
    )
    excluded_targets: Any = Field(
        default_factory=lambda: ["0.0.0.0", "127.0.0.1", "localhost"],
        description="Explicitly excluded targets",
    )
    rules_of_engagement: str = Field(
        default=(
            "No destructive actions without human approval. "
            "No production targets without explicit written authorization."
        ),
        description="Rules of engagement enforced by the orchestrator",
    )

    # Sandbox Configuration
    sandbox_timeout: int = Field(
        default=300,
        description="Maximum seconds for tool execution in sandbox",
    )
    sandbox_image: str = Field(
        default="kalilinux/kali-rolling",
        description="Docker image for sandboxed tool execution",
    )

    # DSPy Configuration
    max_refine_retries: int = Field(
        default=3,
        description="Maximum Refine retry attempts per node",
    )
    refine_threshold: float = Field(
        default=0.7,
        description="Quality threshold for Refine reward acceptance",
    )
    max_graph_nodes: int = Field(
        default=8,
        description="Maximum nodes in a generated topology",
    )

    # Intelligence API Configuration
    nvd_api_key: str = Field(default="", description="NIST NVD API key for higher rate limits")
    shodan_api_key: str = Field(default="", description="Shodan API key for recon")
    virustotal_api_key: str = Field(default="", description="VirusTotal API key for intel")

    # Lab Configuration
    lab_targets: Any = Field(
        default_factory=lambda: ["dvwa", "juice-shop", "metasploitable2"],
        description="Safe test lab target hostnames",
    )
    lab_network: str = Field(
        default="172.20.0.0/24",
        description="Internal lab network CIDR",
    )

    # Langfuse Observability
    langfuse_public_key: str = Field(default="")
    langfuse_secret_key: str = Field(default="")
    langfuse_base_url: str = Field(default="https://cloud.langfuse.com")

    # Available security tools list (for Weaver tool selection)
    available_tools: Any = Field(
        default_factory=lambda: [
            "nmap_scan",
            "whois_lookup",
            "dns_enum",
            "subdomain_enum",
            "gobuster_scan",
            "ffuf_scan",
            "nikto_scan",
            "enum4linux",
            "nuclei_scan",
            "nmap_nse",
            "cve_intelligence",
            "exploit_matcher",
            "payload_generator",
            "attack_chain_builder",
            "adaptive_tester",
            "sqlmap_run",
            "hydra_run",
            "metasploit_run",
            "bloodhound_run",
            "crackmapexec_run",
            "responder_run",
        ],
        description="All registered tool names available to DSPy nodes",
    )


# Available tool roles for Weaver instruction
AVAILABLE_TOOL_ROLES = [
    "recon",
    "enumeration",
    "vulnerability_scanning",
    "cve_intelligence",
    "exploit_matching",
    "payload_generation",
    "attack_chain_building",
    "exploitation",
    "post_exploitation",
    "reporting",
]
