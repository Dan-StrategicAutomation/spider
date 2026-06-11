.PHONY: smoke test lint format-check

UV := uv
PYTEST := $(UV) run --extra dev python -m pytest
RUFF := $(UV) run --extra dev ruff
SPIDER := $(UV) run spider

smoke:
	$(SPIDER) --help >/dev/null
	$(PYTEST) tests/test_cli.py -q

test:
	$(PYTEST) tests/ -q

lint:
	$(RUFF) check src/ tests/

format-check:
	$(RUFF) format --check src/ tests/
