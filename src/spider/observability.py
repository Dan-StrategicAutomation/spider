"""Observability module -- handles Langfuse and DSPy instrumentation."""

import os

from langfuse import get_client
from loguru import logger
from openinference.instrumentation.dspy import DSPyInstrumentor

from spider.config import SpiderConfig


def setup_observability(config: SpiderConfig):
    """Set up Langfuse observability and DSPy instrumentation.

    This uses the native Langfuse v4 integration pattern where get_client()
    automatically registers the OpenTelemetry span processor.
    """
    if not config.langfuse_public_key or not config.langfuse_secret_key:
        logger.warning("Langfuse keys missing. Observability disabled.")
        return

    # 1. Set environment variables for Langfuse SDK
    os.environ["LANGFUSE_PUBLIC_KEY"] = config.langfuse_public_key
    os.environ["LANGFUSE_SECRET_KEY"] = config.langfuse_secret_key
    os.environ["LANGFUSE_HOST"] = config.langfuse_base_url

    logger.info(f"Initializing Langfuse Native SDK (Host: {config.langfuse_base_url})")

    # 2. Initialize Langfuse client
    try:
        langfuse = get_client()
        if langfuse.auth_check():
            logger.success("Langfuse native SDK initialized and authenticated.")
        else:
            logger.warning("Langfuse SDK authentication failed. Check your keys.")
    except Exception as e:
        logger.error(f"Failed to initialize Langfuse SDK: {e}")

    try:
        DSPyInstrumentor().instrument()
        logger.success("DSPy instrumentation active.")
    except Exception as e:
        logger.error(f"Failed to instrument DSPy: {e}")


def flush_observability():
    """Manually flush Langfuse and OpenTelemetry spans."""
    try:
        langfuse = get_client()
        langfuse.flush()
        logger.info("Langfuse traces flushed.")
    except Exception as e:
        logger.debug(f"Failed to flush traces: {e}")
