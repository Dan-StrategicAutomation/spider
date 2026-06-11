# Parallel Execution Architecture

Parallelism is critical to SPIDER for speed. The framework achieves parallelism
at multiple layers: graph execution, tool execution, and intelligence lookups.

## Layer 1: Wave-Based Graph Parallelism

The core execution model processes nodes in **topological waves**. All nodes in
the same wave have their dependencies satisfied and can run in parallel via
`asyncio.gather`.

```python
# engine/runner.py
async def forward_async(self, **kwargs) -> dspy.Prediction:
    waves = self.topology.topological_waves()  # [[recon], [web_enum, svc_enum], [vuln], ...]
    all_results = {**kwargs}

    for wave in waves:
        # ALL nodes in this wave execute simultaneously
        outcomes = await asyncio.gather(
            *(run_one(nid) for nid in wave)
        )
```

### Default Wave Schedule

```
Wave 0  [1 node]     Recon (ReAct)          -- sequential (discovers what to parallelize)
Wave 1  [2 nodes]    Web Enum + Svc Enum     -- PARALLEL
Wave 2  [1 node]     Vuln Analysis           -- sequential (needs both wave 1 outputs)
Wave 3  [1 node]     Exploit Planning        -- sequential
Wave 4  [1 node]     Executor (HITL)         -- sequential (user gated)
Wave 5  [1 node]     Reporter                -- sequential (synthesis)

Time saved vs sequential: ~40% (wave 1 runs 2 nodes simultaneously)
```

The Weaver can generate topologies with much higher parallelism:

```
Wave 0  [1]   Recon
Wave 1  [4]   Web Enum + Svc Enum + DNS Recon + Subdomain Enum  -- 4x PARALLEL
Wave 2  [3]   Vuln Analysis + Config Audit + Cred Check         -- 3x PARALLEL
Wave 3  [2]   Exploit Planning + Attack Chain Builder           -- 2x PARALLEL
Wave 4  [1]   Executor (HITL)

Time saved vs sequential: ~60%+
```

## Layer 2: Tool-Level Parallelism

Within a single ReAct node, tools can be called in parallel. The `dspy.ReAct`
agent can call multiple tools and await them simultaneously:

```python
# When recon calls nmap, whois, and dns_enum, these can run in parallel:
# Node 1: nmap_scan(target)     -- running (~60s)
# Node 2: whois_lookup(domain)  -- running (~5s)
# Node 3: dns_enum(domain)      -- running (~3s)

# Total time: max(60, 5, 3) = 60 seconds (vs 68s sequential)
```

The tool adapter supports async execution for long-running tools:

```python
def nmap_scan_async(target: str) -> asyncio.Task:
    """Return an asyncio task for nmap (long-running background scan)."""
    return asyncio.create_task(_run_async("nmap", ...))
```

## Layer 3: Intelligence Parallelism

The `cve_intelligence` tool queries three sources in parallel:

```python
# intelligence layer - parallel fetches
async def fetch_all(service, version, cpe):
    nvd = asyncio.create_task(nvd_client.lookup(cpe))       # NVD API
    kev = asyncio.create_task(kev_client.check(cpe))        # CISA KEV
    epss = asyncio.create_task(epss_client.scores(cves))    # EPSS
    return await asyncio.gather(nvd, kev, epss)             # All 3 at once
```

## Layer 4: Multi-Target Parallelism

SPIDER can scan multiple targets in parallel by partitioning the target list:

```python
# Target-level parallelism
async def scan_targets(targets):
    # Split into batches of 10
    batches = [targets[i:i+10] for i in range(0, len(targets), 10)]
    # Each batch runs as a separate orchestrator instance
    results = await asyncio.gather(
        *(orchestrator.forward(target=t) for t in targets)
    )
```

## Performance Targets

| Scenario | Sequential | Parallel (target) | Speedup |
|----------|-----------|-------------------|---------|
| Single host pentest | ~15 min | ~6 min | 2.5x |
| 10 hosts (full) | ~2.5 hrs | ~45 min | 3.3x |
| 100 hosts (recon only) | ~8 hrs | ~1.5 hrs | 5.3x |

## dspy.asyncify Usage

All DSPy module calls are wrapped with `dspy.asyncify()` for parallel execution:

```python
# NOT async (blocks the event loop):
result = module(input=value)

# ASYNC (compatible with asyncio.gather):
result = await dspy.asyncify(module)(input=value)

# Parallel wave execution:
outcomes = await asyncio.gather(*(
    dspy.asyncify(self.node_modules[nid])(**self._wave_inputs(nid, all_results))
    for nid in wave
))
```

## Resource Management

Parallel execution is bounded by:
1. **Docker resource limits** -- CPU count, memory limits on sandbox containers
2. **Rate limits** -- NVD API (0.6/s), EPSS API, target throttling
3. **Max concurrent tools** -- Configurable per-tool concurrency limits
4. **Fail-fast** -- If any node in a wave fails, downstream waves are skipped

```python
# In config.py
max_concurrent_tools: int = Field(default=10)
max_concurrent_targets: int = Field(default=5)
```

## Thread Safety

The context store, audit logger, and HITL gate use threading primitives:

```python
# audit_logger.py
self._lock = threading.Lock()

# context_store.py
_store: ContextVar[dict[str, str] | None] = ContextVar("context_store", default=None)
```
