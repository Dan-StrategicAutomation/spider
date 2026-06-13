## 2024-06-11 - [Initial Exploration]
**Learning:** Evaluated various components (weaver, runner, tools) for performance improvements.
**Action:** Considering options like optimizing topological wave calculations, thread pool limits, or redundant API lookups.

## 2024-06-11 - [Optimize EPSS API Fetching]
**Learning:** Found an N+1 API call bottleneck in `_fetch_epss` when querying `api.first.org`. When looking up multiple CVEs, it was making individual HTTP requests.
**Action:** The API supports querying multiple CVEs via a comma-separated list (`?cve=x,y,z`). I refactored the function to batch request up to 50 CVEs per request to avoid multiple overheads per CVE. Next time I work with APIs in a loop, check if they support batched/bulk queries.

## 2026-06-11 - [Safe CLI Smoke Path]

**Learning:** `uv run spider --help` exits through argparse before SPIDER initializes models, sessions, or scans, and `uv run --extra dev python -m pytest tests/test_cli.py -q` uses the project environment instead of a global pytest shim while mocking orchestration for CLI behavior checks.

**Action:** Use `make smoke` for the fastest safe CLI feedback loop before broader pytest or ruff checks.
## 2024-03-08 - SQLite context manager behavior
**Learning:** `with sqlite3.connect(...) as conn:` only manages the database transaction, not the connection closure. The connection remains open and must be explicitly closed via `.close()`. Failing to do so in high-frequency operations like cache queries leads to rapid file descriptor exhaustion (`sqlite3.OperationalError: unable to open database file`).
**Action:** Always maintain a persistent `sqlite3.Connection` object instead of continuously reconnecting and discarding the reference, especially when wrapping SQLite into a cache interface.
