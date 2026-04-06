# SPIDER

**Symbiotic Pentesting Investigation & DSPy Exploitation Runtime**

A DSPy-native penetration testing framework that combines traditional security
tools with LLM-driven reasoning, self-evaluation, and autonomous problem-solving.

> [!WARNING]
> SPIDER is designed for **authorized penetration testing and security research only**.
> Always obtain explicit written authorization before testing any system you do not own.
> Misuse of this tool for unauthorized access is illegal.

## Features

- **DSPy-Native Reasoning** -- All self-improvement via `dspy.Refine`, no Python retry loops
- **Automated Attack Chains** -- LLM builds multi-step exploit paths from discovered vulnerabilities
- **Custom Intelligence** -- NVD, CISA KEV, EPSS, and Exploit-DB cross-referencing
- **Adaptive Testing** -- When a scan fails, SPIDER reasons why and adapts its approach
- **Safety-First** -- Scope guards, HITL gates, sandboxed execution, immutable audit logs
- **Terminal UI** -- Modern Textual dashboard with live findings and attack chain visualization

## Architecture

SPIDER executes pentests as a directed acyclic graph (DAG) of DSPy modules:

```
Recon (ReAct) -> Enumeration (Parallel) -> Vuln Analysis -> Exploit Planning -> Exploitation (HITL) -> Report
```

Every node is wrapped with `dspy.Refine(module, N=3, reward_fn, threshold)` for
quality-driven self-improvement. Failed or incomplete output triggers automatic retry.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Configure
export SPIDER_OPENROUTER_API_KEY=sk-or-...
export SPIDER_ALLOWED_TARGETS=192.168.1.0/24

# Run against safe test lab
docker compose -f lab/docker-compose.yml up -d
spider scan --target 172.20.0.2 --mode recon

# Launch TUI
spider tui
```

## Documentation

- [Architecture](docs/architecture.md) -- System design, DSPy graph topology
- [DSPy Engine](docs/dspy-engine.md) -- Weaver, Runner, Refine patterns
- [Security Tools](docs/tools.md) -- Tool catalog, custom tools
- [Safety](docs/safety.md) -- Scope guards, HITL, sandbox, auditing
- [Testing](docs/testing.md) -- Lab setup, test methodology
- [TUI](docs/tui.md) -- Terminal UI documentation
- [AGENTS.md](AGENTS.md) -- AI development guidelines

## Safety

SPIDER enforces safety at multiple levels:

1. **Scope Guard** -- Hard target scope validation at every tool invocation
2. **HITL Gates** -- All exploitation requires explicit human approval
3. **Sandbox** -- Tools run in isolated Docker containers
4. **Audit** -- Immutable append-only log of all actions

## Contributing

This project is under active development. See CONTRIBUTING.md for guidelines.

## License

Apache License 2.0 -- see [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security testing only. The authors are not responsible
for misuse or unauthorized access. Always follow responsible disclosure practices.
