# Testing Methodology

## Test Architecture

```
tests/
├── test_scopes/           # Scope guard tests (MUST PASS first)
│   └── test_scope_guard.py
├── test_sandbox/          # Sandbox isolation tests
│   └── test_docker_env.py
├── test_tools/            # Tool wrapper tests (mocked)
│   ├── test_adapter.py
│   ├── test_recon_tools.py
│   └── test_enum_tools.py
├── test_nodes/            # DSPy node module tests (mocked LM)
│   └── test_orchestrator.py
└── test_integration/      # Full graph against lab targets
    └── test_lab.py
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
pytest tests/ -q

# Safety tests first (MUST PASS)
pytest tests/test_scopes/ -q
pytest tests/test_sandbox/ -q

# Integration against lab
pytest tests/test_integration/ -q
```

## Expected Findings

Documented known vulnerabilities for each lab target so we can measure
SPIDER's detection accuracy.
