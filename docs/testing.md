# Testing Methodology

## Test Architecture

```
tests/
├── test_safety/           # Scope guard, HITL, and sandbox policy tests
├── test_tools/            # Tool wrapper tests (mocked external execution)
├── test_engine/           # Weaver, runner, and topology tests
├── test_intelligence/     # CVE, EPSS, KEV, and repository/cache tests
└── test_integration/      # Full graph against lab targets
```

## Lab Setup

```bash
docker compose -f lab/docker-compose.yml up -d
```

Spins up:
- DVWA (web app testing)
- Juice Shop (modern web app)
- Metasploitable2 (network services)

All on isolated bridge network. No external internet.

## Running Tests

```bash
# Full suite
uv run pytest tests/ -q

# Focused suites
uv run pytest tests/test_safety/ -q
uv run pytest tests/test_tools/ -q
uv run pytest tests/test_engine/ -q
uv run pytest tests/test_intelligence/ -q

# Integration against lab
uv run pytest tests/test_integration/ -q
```

## Expected Findings

Documented known vulnerabilities for each lab target so we can measure
SPIDER's detection accuracy.
