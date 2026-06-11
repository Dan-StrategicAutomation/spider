"""SpiderConfig -- centralized pydantic-settings configuration."""

from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator
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
        populate_by_name=True,
    )

    # ── LLM Configuration ──────────────────────────────────────────────

    @field_validator("excluded_targets", "allowed_targets", "lab_targets", mode="before")
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
        validation_alias=AliasChoices("SPIDER_OLLAMA_BASE_URL", "OLLAMA_BASE_URL"),
        description="Ollama endpoint for primary model execution",
    )

    model_provider: Literal["auto", "ollama", "openrouter"] = Field(
        default="auto",
        validation_alias=AliasChoices("SPIDER_MODEL_PROVIDER", "MODEL_PROVIDER"),
        description=(
            "LLM provider routing: auto uses Ollama when available and OpenRouter fallback, "
            "ollama forces local Ollama, openrouter forces OpenRouter."
        ),
    )

    # Primary agent model -- Qwen3.5 abliterated (uncensored for pentesting)
    # Sizes available on Ollama: 0.8B(1GB), 2B(1.9GB), 4B(3.3GB), 9B(6.6GB), 27B(17GB), 35B(24GB)
    # RTX 3070 Laptop (8GB VRAM): use 9B (6.6GB) for main agent
    primary_model: str = Field(
        default="huihui_ai/qwen3.5-abliterated:9b",
        validation_alias=AliasChoices("SPIDER_PRIMARY_MODEL", "PRIMARY_MODEL"),
        description="Primary Qwen3.5 abliterated model for DSPy nodes (Ollama)",
    )

    # Self-evaluation model -- smaller is fine, runs alongside primary
    eval_model: str = Field(
        default="huihui_ai/qwen3.5-abliterated:4b",
        validation_alias=AliasChoices("SPIDER_EVAL_MODEL", "EVAL_MODEL"),
        description="Lighter model for self-evaluation and reward scoring (Ollama)",
    )

    # Cloud fallback -- used only when Ollama is unavailable
    openrouter_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_OPENROUTER_API_KEY", "OPENROUTER_API_KEY"),
        description="OpenRouter API key for cloud fallback",
    )
    fallback_model: str = Field(
        default="anthropic/claude-sonnet-4-5-20250929",
        validation_alias=AliasChoices("SPIDER_FALLBACK_MODEL", "FALLBACK_MODEL"),
        description="Cloud model fallback when Ollama is unavailable",
    )

    # Safety Configuration
    allowed_targets: Any = Field(
        default_factory=list,
        validation_alias=AliasChoices("SPIDER_ALLOWED_TARGETS", "ALLOWED_TARGETS"),
        description="CIDR ranges or hosts allowed for testing",
    )
    excluded_targets: Any = Field(
        default_factory=lambda: ["0.0.0.0", "127.0.0.1", "localhost"],
        validation_alias=AliasChoices("SPIDER_EXCLUDED_TARGETS", "EXCLUDED_TARGETS"),
        description="Explicitly excluded targets",
    )
    rules_of_engagement: str = Field(
        default=(
            "No destructive actions without human approval. "
            "No production targets without explicit written authorization."
        ),
        validation_alias=AliasChoices("SPIDER_RULES_OF_ENGAGEMENT", "RULES_OF_ENGAGEMENT"),
        description="Rules of engagement enforced by the orchestrator",
    )

    # Sandbox Configuration
    sandbox_timeout: int = Field(
        default=300,
        validation_alias=AliasChoices("SPIDER_SANDBOX_TIMEOUT", "SANDBOX_TIMEOUT"),
        description="Maximum seconds for tool execution in sandbox",
    )
    sandbox_image: str = Field(
        default="kalilinux/kali-rolling",
        validation_alias=AliasChoices("SPIDER_SANDBOX_IMAGE", "SANDBOX_IMAGE"),
        description="Docker image for sandboxed tool execution",
    )

    # DSPy Configuration
    use_refine: bool = Field(
        default=True,
        validation_alias=AliasChoices("SPIDER_USE_REFINE", "USE_REFINE"),
        description="Enable/Disable dspy.Refine loops for self-improvement",
    )
    max_refine_retries: int = Field(
        default=3,
        validation_alias=AliasChoices("SPIDER_MAX_REFINE_RETRIES", "MAX_REFINE_RETRIES"),
        description="Maximum Refine retry attempts per node",
    )
    refine_threshold: float = Field(
        default=0.7,
        validation_alias=AliasChoices("SPIDER_REFINE_THRESHOLD", "REFINE_THRESHOLD"),
        description="Quality threshold for Refine reward acceptance",
    )
    max_graph_nodes: int = Field(
        default=8,
        validation_alias=AliasChoices("SPIDER_MAX_GRAPH_NODES", "MAX_GRAPH_NODES"),
        description="Maximum nodes in a generated topology",
    )

    # Intelligence API Configuration
    nvd_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_NVD_API_KEY", "NVD_API_KEY"),
        description="NIST NVD API key for higher rate limits",
    )
    shodan_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_SHODAN_API_KEY", "SHODAN_API_KEY"),
        description="Shodan API key for recon",
    )
    virustotal_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_VIRUSTOTAL_API_KEY", "VIRUSTOTAL_API_KEY"),
        description="VirusTotal API key for intel",
    )

    # Lab Configuration
    lab_targets: Any = Field(
        default_factory=lambda: ["dvwa", "juice-shop", "metasploitable2"],
        validation_alias=AliasChoices("SPIDER_LAB_TARGETS", "LAB_TARGETS"),
        description="Safe test lab target hostnames",
    )
    lab_network: str = Field(
        default="172.20.0.0/24",
        validation_alias=AliasChoices("SPIDER_LAB_NETWORK", "LAB_NETWORK"),
        description="Internal lab network CIDR",
    )

    # Langfuse Observability
    langfuse_public_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_LANGFUSE_PUBLIC_KEY", "LANGFUSE_PUBLIC_KEY"),
    )
    langfuse_secret_key: str = Field(
        default="",
        validation_alias=AliasChoices("SPIDER_LANGFUSE_SECRET_KEY", "LANGFUSE_SECRET_KEY"),
    )
    langfuse_base_url: str = Field(
        default="https://cloud.langfuse.com",
        validation_alias=AliasChoices(
            "SPIDER_LANGFUSE_BASE_URL", "SPIDER_LANGFUSE_HOST", "LANGFUSE_BASE_URL", "LANGFUSE_HOST"
        ),
    )
