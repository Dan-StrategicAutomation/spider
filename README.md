# SPIDER

**Symbiotic Pentesting Investigation & DSPy Exploitation Runtime**

```
 ######  ########  #### ########  ######## ########
##    ## ##     ##  ##  ##     ## ##       ##     ##
##       ##     ##  ##  ##     ## ##       ##     ##
 ######  ########   ##  ##     ## ######   ########
      ## ##         ##  ##     ## ##       ##   ##
##    ## ##         ##  ##     ## ##       ##    ##
 ######  ##        #### ########  ######## ##     ##
```

> A DSPy-native penetration testing framework powered by **Qwen3.5 Abliterated** on Ollama.
> Self-improving, self-learning, and self-evaluating. Gets smarter every session.

> [!WARNING]
> SPIDER is designed for **authorized penetration testing and security research only**.
> Always obtain explicit written authorization before testing any system you do not own.
> Misuse of this tool for unauthorized access is illegal.

---

## What Makes SPIDER Different

Other AI pentest tools (METATRON, HexStrike, Tengu, LuaN1ao) are **single-shot** -- they
run cold every time, parse text with regex, and forget everything after the session ends.

**SPIDER gets warmer.** Every session teaches it something new:

| Feature | METATRON | HexStrike | Tengu | **SPIDER** |
|---------|----------|-----------|-------|------------|
| Local LLM | ✅ Ollama | ❌ Cloud only | ❌ Cloud only | ✅ Ollama |
| Uncensored model | ✅ Custom Modelfile | ❌ | ❌ | ✅ Qwen3.5 Abliterated |
| DSPy-native | ❌ | ❌ | ❌ | ✅ |
| Self-improving prompts | ❌ | ❌ | ❌ | ✅ GEPA + MIPROv2 |
| Learns from failures | ❌ | ❌ | ❌ | ✅ |
| Parallel execution | ❌ | ❌ | ❌ | ✅ Wave-based DAG |
| Exploit discovery engine | ❌ | ❌ | ❌ | ✅ Novel pattern detection |
| Persistent knowledge | ❌ | ❌ | ❌ | ✅ SQLite + JSON store |
| Auto-optimizes over time | ❌ | ❌ | ❌ | ✅ |

## Model Setup

### Primary: Qwen3.5 Abliterated (Ollama)

SPIDER uses **`huihui_ai/qwen3.5-abliterated`** -- an uncensored version of Qwen3.5
with refusal vectors removed via OBLITERATUS. It won't block security tool calls,
exploit generation, or offensive reasoning.

**Choose your size:**

| Model | VRAM | Use |
|-------|------|-----|
| `huihui_ai/qwen3.5-abliterated:9b` | 6.6 GB | **Primary agent** -- fits RTX 3070 (8GB) |
| `huihui_ai/qwen3.5-abliterated:4b` | 3.3 GB | Fast eval / payload gen |
| `huihui_ai/qwen3.5-abliterated:27b` | 17 GB | Heavy reasoning (more VRAM needed) |

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull the models you need
ollama pull huihui_ai/qwen3.5-abliterated:9b
ollama pull huihui_ai/qwen3.5-abliterated:4b
```

A custom `Modelfile` is included that configures the system prompt, temperature,
and context window for pentesting. Build it with:

```bash
ollama create spider-qwen35 -f Modelfile
```

Then set `SPIDER_PRIMARY_MODEL=spider-qwen35` in your `.env`.

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/Dan-StrategicAutomation/spider.git
cd spider

# 2. Create virtual environment
python -m venv venv && source venv/bin/activate

# 3. Install
pip install -e ".[dev]"

# 4. Configure
cp .env.example .env
# Edit .env and set your model + allowed targets

# 5. Make sure Ollama is running
ollama list  # Should show huihui_ai/qwen3.5-abliterated

# 6. Launch SPIDER
python -m spider.cli
```

## Usage

### Interactive CLI

SPIDER's CLI follows the METATRON UX pattern -- color-coded menus, numbered choices,
interactive prompts -- but with DSPy-native power:

```
    ███████╗██████╗  ██████╗ ██████╗ ██╗   ██╗███╗   ██╗████████╗
    ██╔════╝██╔══██╗██╔═══██╗██╔══██╗██║   ██║████╗  ██║╚══██╔══╝
    ███████╗██████╔╝██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║
    ╚════██║██╔═══╝ ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║
    ███████║██║     ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║
    ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝

    DSPy-Native Pentesting Framework  |  Qwen3.5 Abliterated  |  Ollama
    ───────────────────────────────────────────────────────────────

  [1]  New Scan
  [2]  View History
  [3]  Pull Models (Ollama)
  [4]  Configuration
  [5]  Exit
  ────────────────────────────────────────────────────────────────────
spider> 1

──────────────────── NEW SCAN ────────────────────
[?] Enter target IP or domain: 192.168.1.100

[+] Session created — ID 1

──────────────────── SCAN MODE ────────────────────
  [1] Recon only (safe, autonomous)
  [2] Full pentest (includes HITL-gated exploitation)
  [3] Custom goal (natural language)
  ──────────────────────────────────────────────────
Mode: 2

──────────────────── SCANNING ─────────────────────
[*] Target: 192.168.1.100
[*] Goal: Perform a full penetration test against 192.168.1.100...
```

### Scan Modes

1. **Recon Only** -- Safe, fully autonomous. Network discovery, port scanning,
   service enumeration, technology detection.
2. **Full Pentest** -- Recon + enumeration + vulnerability analysis + exploit
   planning + exploitation (each exploit requires human approval).
3. **Custom Goal** -- Natural language. Describe what you want to test and SPIDER
   weaves a custom DSPy topology via GraphWeaver.

## Architecture

```
Recon (ReAct) ──→ Enumeration (Parallel) ──→ Vuln Analysis ──→
                                                       ↓
                                    Exploit Planning ←──┘
                                                       ↓
                          Exploitation (HITL-Gated) ──→ Report
```

Every node wrapped with `dspy.Refine(module, N=3, reward_fn, threshold)`.
Failed output triggers automatic retry with different rollout IDs.

**See [docs/architecture.md](docs/architecture.md) for full system design.**

**See [docs/advanced-dspy-design.md](docs/advanced-dspy-design.md) for the learning pipeline.**

## Safety

| Layer | Enforcement |
|-------|-------------|
| **Scope Guard** | Hard target scope validation at EVERY tool invocation |
| **HITL Gates** | All exploitation requires explicit human approval |
| **Sandbox** | Tools run in isolated Docker containers (no privileged mode) |
| **Audit** | Immutable append-only log of every action |
| **Rate Limits** | NVD API caching, EPSS rate limiting, tool timeouts |

## Documentation

| Document | Contents |
|----------|----------|
| [Architecture](docs/architecture.md) | System design, DSPy graph topology, components |
| [DSPy Engine](docs/dspy-engine.md) | Weaver, Runner, Refine, self-evaluation |
| [Advanced DSPy Design](docs/advanced-dspy-design.md) | GEPA, MIPROv2, learning pipeline, exploit discovery |
| [Parallelism](docs/parallelism.md) | Wave-based parallelism, async execution |
| [Security Tools](docs/tools.md) | Tool catalog, custom tools, integration guide |
| [Safety](docs/safety.md) | Scope guards, HITL, sandbox, auditing |
| [AGENTS.md](AGENTS.md) | AI development guidelines |
| [PLAN.md](PLAN.md) | Implementation roadmap |

## Testing

```bash
# Start the vulnerable test lab
docker compose -f lab/docker-compose.yml up -d

# Run the full test suite
pytest tests/ -q

# Run only safety tests (MUST PASS before any pentesting)
pytest tests/test_safety/ -q

# Run integration tests against lab targets
pytest tests/test_integration/ -q
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security testing only. The authors are not responsible
for misuse or unauthorized access. Always follow responsible disclosure practices.
The Qwen3.5 Abliterated model has reduced safety filtering -- users are solely
responsible for monitoring outputs and ensuring legal/ethical usage.
