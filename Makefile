.PHONY: smoke test lint format

smoke:
	uv run --all-extras spider --help

test:
	uv run --all-extras python -m pytest tests/ -q -m "not integration"

lint:
	uv run --all-extras ruff check src/ tests/

format:
	uv run --all-extras ruff format src/ tests/
