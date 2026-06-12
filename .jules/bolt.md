## 2024-06-11 - [Initial Exploration]
**Learning:** Evaluated various components (weaver, runner, tools) for performance improvements.
**Action:** Considering options like optimizing topological wave calculations, thread pool limits, or redundant API lookups.

## 2024-06-11 - [Optimize EPSS API Fetching]
**Learning:** Found an N+1 API call bottleneck in `_fetch_epss` when querying `api.first.org`. When looking up multiple CVEs, it was making individual HTTP requests.
**Action:** The API supports querying multiple CVEs via a comma-separated list (`?cve=x,y,z`). I refactored the function to batch request up to 50 CVEs per request to avoid multiple overheads per CVE. Next time I work with APIs in a loop, check if they support batched/bulk queries.

## 2026-06-11 - [Safe CLI Smoke Path]

**Learning:** `uv run spider --help` exits through argparse before SPIDER initializes models, sessions, or scans, and `uv run --extra dev python -m pytest tests/test_cli.py -q` uses the project environment instead of a global pytest shim while mocking orchestration for CLI behavior checks.

**Action:** Use `make smoke` for the fastest safe CLI feedback loop before broader pytest or ruff checks.

## 2024-05-18 - Precomputing O(1) Lookups in GraphRunner
**Learning:** Found redundant O(N) linear scans happening in the hot path of the async task runner in `spider/engine/runner.py`. Iterating and filtering the list of `self.topology.nodes` within `run_one` loop changes execution time to O(N^2) as node count increases.
**Action:** When a static list is heavily referenced inside execution loops, ensure it's precomputed into an O(1) dictionary map during class initialization.
