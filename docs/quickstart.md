# Quick Start

## Prerequisites

- Python 3.10+
- Ollama installed and running
- Docker (for sandbox and test lab)

## Setup

```bash
# Clone and install
git clone https://github.com/Dan-StrategicAutomation/spider.git
cd spider
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"

# Pull models
ollama pull huihui_ai/qwen3.5-abliterated:9b
ollama pull huihui_ai/qwen3.5-abliterated:4b

# Configure
cp .env.example .env
# Edit: set SPIDER_ALLOWED_TARGETS=192.168.1.0/24
```

## First Run

```bash
python -m spider.cli
```

1. Select `[1] New Scan`
2. Enter target: `192.168.1.100`
3. Select mode: `[1] Recon only` (safe, autonomous)
4. Watch SPIDER discover hosts, ports, services, and technologies

## Full Pentest

For a full pentest with HITL-gated exploitation:
1. Set your target in `SPIDER_ALLOWED_TARGETS`
2. Select `[2] Full pentest`
3. Approve each exploit action when prompted
