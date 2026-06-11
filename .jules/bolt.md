## 2024-06-11 - [Initial Exploration]
**Learning:** Evaluated various components (weaver, runner, tools) for performance improvements.
**Action:** Considering options like optimizing topological wave calculations, thread pool limits, or redundant API lookups.

## 2024-06-11 - [Optimize EPSS API Fetching]
**Learning:** Found an N+1 API call bottleneck in `_fetch_epss` when querying `api.first.org`. When looking up multiple CVEs, it was making individual HTTP requests.
**Action:** The API supports querying multiple CVEs via a comma-separated list (`?cve=x,y,z`). I refactored the function to batch request up to 50 CVEs per request to avoid multiple overheads per CVE. Next time I work with APIs in a loop, check if they support batched/bulk queries.

## 2026-06-11 - [Safe CLI Smoke Test]

**Learning:** `uv run --all-extras spider --help` exercises CLI import and argument parsing without initializing models, touching targets, or starting a scan. Running `uv run spider` without extras can prune dev-only tools from `.venv`.

**Action:** Use `make smoke` as the fastest safe CLI verification before deeper tests; the Make target keeps `--all-extras` enabled so pytest and Ruff stay installed.
