# Advanced DSPy Design: Learning, Self-Improvement, and Exploit Discovery

## Research Summary

After deep research into the DSPy 3.1.3 optimizer ecosystem, several critical
capabilities have been identified that dramatically improve SPIDER's speed,
reliability, and self-learning capabilities beyond basic `dspy.Refine`.

The key finding: **SPIDER needs a multi-tier optimization strategy**. Refine is
for runtime self-correction (what we have). But the real power comes from:
- **GEPA** (Genetic Prompt Evolution) -- learns from failures across sessions
- **MIPROv2** -- Bayesian instruction optimization for each node
- **BootstrapFewShot** -- generates proven few-shot demonstrations from lab targets
- **COPRO** -- contrastive prompt optimization when specific failures identified
- **Program persistence** -- save/compile/load optimized programs across runs

No existing pentest framework (HexStrike, LuaN1ao, Tengu) uses DSPy optimizers.
This is our biggest architectural advantage.

---

## Tier 1: Runtime Self-Correction (Current Design + Enhancements)

### dspy.Refine (Already Implemented)
Used within individual nodes for quality-driven retry with different rollouts.

**Enhancement**: Add per-node reward functions that incorporate **exploit
success probability** -- if a Recon node identifies a port but the
VulnAnalysis node says the service is unknown, the Recon reward should penalize
incomplete version detection.

### dspy.BestOfN (NEW)
For cases where we need MANY candidates and pick the best. Use case: **payload
generation** -- generate 50 payloads for XSS, keep the top-scoring one.

```python
def payload_waf_bypass_reward(args: dict, pred: dspy.Prediction) -> float:
    """Reward payload for valid syntax + WAF bypass potential."""
    payload = pred.payload
    score = 0.0
    if validate_syntax(payload, args["vuln_type"]): score += 0.3
    if passes_encoding_check(payload): score += 0.2
    if has_obfuscation_tech(payload): score += 0.2
    if matches_expected_pattern(payload, args["target_info"]): score += 0.3
    return score

best_payload_gen = dspy.BestOfN(
    module=dspy.ChainOfThought(PayloadSignature),
    N=50,
    reward_fn=payload_waf_bypass_reward,
    threshold=0.85,
)
```

### dspy.Refine vs dspy.BestOfN Usage Matrix

| Use Case | Pattern | Why |
|----------|---------|-----|
| Recon completeness | Refine(N=3) | Iterative improvement with tool feedback |
| Payload generation | BestOfN(N=50) | Need many candidates, pick best syntactically |
| Topology weaving | Refine(N=3) | Structural validation + quality score |
| Attack chain building | Refine(N=3) | Feasibility + stealth scoring |
| Exploit match ranking | Refine(N=3) | Cross-reference quality |
| WAF bypass payloads | BestOfN(N=50) | Brute-force variation with validation |
| Report generation | Refine(N=3) | Structure + completeness |

---

## Tier 2: Post-Session Learning (NEW -- Critical)

After each pentest session, SPIDER learns from its results. This is where the
system gets **genuinely smarter over time**.

### GEPA -- Genetic Prompt Evolution

GEPA is the most powerful DSPy optimizer for SPIDER's use case. It:
1. **Analyzes failures** -- Uses reflection LM to understand what went wrong
2. **Generates insights** -- Creates textual feedback on failure patterns
3. **Proposes mutations** -- Modifies instructions for ALL modules simultaneously
4. **Evolves prompts** -- Uses genetic algorithm with merge operations
5. **Pareto frontier** -- Tracks best-performing configurations across multiple metrics

**Application to SPIDER:**

```python
from dspy.teleprompt import GEPA

# After pentest session, collect all traces
def pentest_metric(inputs, outputs, trace, pred_name, captured_trace) -> float:
    """Evaluate full pentest trace quality."""
    score = 0.0
    # Did recon find all hosts?
    if hasattr(outputs, 'recon_findings'):
        score += len(outputs.recon_findings.hosts) * 0.1
    # Did vuln analysis find known CVEs?
    if hasattr(outputs, 'vuln_findings'):
        score += len(outputs.vuln_findings) * 0.05
    # Did we build attack chains?
    if hasattr(outputs, 'attack_chains'):
        score += len(outputs.attack_chains) * 0.15
    # Did exploitation succeed (if attempted)?
    if hasattr(outputs, 'exploit_results'):
        score += sum(1 for r in outputs.exploit_results if r.success) * 0.2
    return min(1.0, score)

gepa_optimizer = GEPA(
    metric=pentest_metric,
    reflection_lm=dspy.LM("openrouter/openai/gpt-4o-mini"),  # Cheap reflection
    max_metric_calls=500,  # Budget for optimization
    track_best_outputs=True,
)

# Compile on session results
optimized_spider = gepa_optimizer.compile(
    spider_orchestrator,
    trainset=session_trainset,  # All targets tested
)
optimized_spider.save("spider_optimized_gepa_v1.json")
```

**GEPA learns from failures by:**
- If Recon consistently misses a service type --> GEPA rewrites Recon instructions
- If VulnAnalysis produces false positives --> GEPA tightens matching criteria
- If ExploitPlanner builds infeasible chains --> GEPA adds constraint language
- If PayloadGen gets blocked by common WAF --> GEPA adds bypass techniques

**MERGE OPERATION:** GEPA can combine best instructions from multiple runs.
If run A has better recon prompts and run B has better vuln analysis, GEPA
merges them into a single superior program.

### MIPROv2 -- Bayesian Instruction Optimization

MIPROv2 jointly optimizes instructions AND few-shot examples using Bayesian
optimization. Use after 5+ lab pentest sessions:

```python
from dspy.teleprompt import MIPROv2

mipro = MIPROv2(
    metric=pentest_metric,
    auto="medium",
    num_threads=8,
    prompt_model=dspy.LM("openrouter/openai/gpt-4o-mini"),
)

# Compile on lab target dataset
optimized = mipro.compile(
    spider_program,
    trainset=lab_pentest_dataset,
    max_bootstrapped_demos=4,
    max_labeled_demos=4,
)
optimized.save("spider_mipro_medium.json")
```

**MIPROv2's power for SPIDER:**
- Bootstraps actual successful pentest traces as few-shot examples
- Generates optimized natural-language instructions for each node
- Bayesian search finds instruction combinations that work together
- Minibatch evaluation for efficient search across large target sets

### BootstrapFewShot -- Demonstration Generation

The simplest but highly effective optimizer. Generates proven few-shot
examples from lab targets:

```python
from dspy.teleprompt import BootstrapFewShotWithRandomSearch

fewshot = BootstrapFewShotWithRandomSearch(
    metric=pentest_metric,
    max_bootstrapped_demos=4,  # Generate 4 good examples per module
    num_candidate_programs=8,   # Try 8 random configurations
    num_threads=8,
)

# Run against DVWA, Juice Shop, Metasploitable2
compiled = fewshot.compile(spider_program, trainset=lab_targets)
compiled.save("spider_fewshot.json")
```

**What this gives us:**
- Each DSPy node gets 4 proven demonstrations of successful behavior
- Recon node learns what good reconnaissance looks like
- VulnAnalysis learns correct CVE-to-service matching patterns
- AttackChainBuilder learns proven multi-step attack patterns

---

## Tier 3: Continuous Learning Pipeline (NEW)

```
                    ┌─────────────────────────────────────────────┐
                    │         CONTINUOUS LEARNING PIPELINE        │
                    └─────────────────────────────────────────────┘

  SESSION 1        SESSION 2        SESSION 3        OPTIMIZATION
  (DVWA)           (Juice Shop)     (Metasploitable)  CYCLE
                                                             
  Run spider  ──→  Run spider  ──→  Run spider  ──→  GEPA optimizes
  Collect     ──→  Collect     ──→  Collect     ──→  all instructions
  traces      ──→  traces      ──→  traces      ──→  + few-shot demos
                                                             
                                                              ↓
  ┌─────────────────────────────────────────────────────────────┐
  │                  KNOWLEDGE STORE                             │
  │                                                             │
  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐ │
  │  | Optimized  | | Few-Shot   | | Failure    | | Exploit    | │
  │  | Programs   | | Demos      | | Patterns   | | Patterns   | │
  │  │ (JSON)     | │ (JSON)     │ │ (SQLite)   │ │ (SQLite)   │ │
  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘ │
  └─────────────────────────────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  NEW SESSION │
                    │  loads best  │
                    │  program     │
                    └─────────────┘
```

### Knowledge Store Architecture

```
~/.spider/knowledge/
├── programs/                    # Saved optimized DSPy programs
│   ├── gepa_v1_20260406.json   # Best GEPA-optimized program
│   ├── mipro_v1_20260406.json  # Best MIPROv2-optimized program
│   └── fewshot_v1.json         # Best few-shot program
├── traces/                      # Pentest execution traces
│   ├── session_20260406_001.jsonl
│   └── session_20260406_002.jsonl
├── failures/                    # Failure patterns for GEPA reflection
│   ├── false_positives.jsonl
│   ├── missed_vulns.jsonl
│   └── failed_exploits.jsonl
└── exploits/                    # Discoveries from real pentests
    ├── successful_exploits.jsonl
    └── bypassed_wafs.jsonl
```

### Session Learning Loop

```python
class SpiderKnowledgeBase:
    """Persistent learning store for SPIDER."""
    
    def record_session(self, session_id: str, results: dict, 
                       trace: dspy.Prediction, targets: list[str]):
        """Save all execution traces, failures, and successes."""
        session = {
            "id": session_id,
            "targets": targets,
            "timestamp": datetime.utcnow(),
            "findings_count": len(results.get("findings", [])),
            "exploits_succeeded": len([f for f in results.get("findings", []) 
                                       if f.get("exploit_success")]),
            "exploits_failed": len([f for f in results.get("findings", []) 
                                   if f.get("exploit_failed")]),
            "false_positives": [],
            "trace": _serialize_trace(trace),
        }
        self._save_trace(session)
        
        # Classify failures
        for finding in results.get("findings", []):
            if finding.get("false_positive"):
                self._record_failure("false_positive", finding)
            if finding.get("exploit_failed"):
                self._record_failure("exploit_failed", finding)
            if finding.get("missed_vuln"):
                self._record_failure("missed", finding)
    
    def build_trainset(self, min_sessions: int = 3) -> list[Example]:
        """Convert past sessions into DSPy training set."""
        trainset = []
        for session in self._load_sessions():
            if session["findings_count"] == 0:
                continue  # Skip unproductive sessions
            trainset.append(dspy.Example(
                target=session["targets"][0],
                results=session["findings"],
            ).with_inputs("target"))
        return trainset
    
    def optimize_and_save(self, program: SpiderOrchestrator, 
                          optimizer: str = "gepa"):
        """Run optimizer and save best program."""
        trainset = self.build_trainset()
        if len(trainset) < 3:
            return program  # Not enough data yet
        
        if optimizer == "gepa":
            opt = GEPA(metric=pentest_metric, reflection_lm=reflection_lm)
            result = opt.compile(program, trainset=trainset)
        elif optimizer == "mipro":
            opt = MIPROv2(metric=pentest_metric, auto="light")
            result = opt.compile(program, trainset=trainset)
        elif optimizer == "fewshot":
            opt = BootstrapFewShotWithRandomSearch(metric=pentest_metric)
            result = opt.compile(program, trainset=trainset)
        
        version = self._next_version(optimizer)
        result.save(f"~/.spider/knowledge/programs/{optimizer}_v{version}.json")
        return result
```

---

## Tier 4: Exploit Discovery Engine (NEW)

This is where SPIDER goes beyond known CVE databases and **discovers new
exploit patterns**. The key insight: DSPy's ReAct + tool use + self-evaluation
can find vulnerabilities that signature-based scanners miss.

### The Discovery Pipeline

```
Step 1: Recon finds unusual service/endpoint
    ↓ (not in known CVE databases)
Step 2: Adaptive Tester attempts novel interaction
    ↓ (LLM reasons about application behavior)
Step 3: Payload Generator creates custom payload
    ↓ (based on observed behavior, not templates)
Step 4: Self-Evaluation scores exploit quality
    ↓ (reward function: was it exploitable?)
Step 5: Success logged to exploit_patterns.jsonl
Step 6: GEPA incorporates into future programs
    ↓
Next session: Similar patterns trigger automatically
```

### Custom Module: NovelVulnDetector

```python
class VulnDetectionSignature(dspy.Signature):
    """Analyze service response for signs of vulnerability.
    Look for: unusual error messages, version disclosure,
    unexpected behavior, parameter handling anomalies.
    Generate test payloads and reason about expected results."""
    service_info: str = dspy.InputField()
    response_data: str = dspy.InputField()
    known_exploits: str = dspy.InputField(desc="Known exploits for this service")
    suspected_vulnerability: str = dspy.OutputField()
    test_payload: str = dspy.OutputField()
    expected_behavior: str = dspy.OutputField()
    confidence: float = dspy.OutputField(desc="Vuln suspicion confidence 0-1")


class AdaptiveTestModule(dspy.Module):
    """Test a suspected vulnerability adaptively.
    If the first test fails, reason why and adapt."""
    
    def __init__(self):
        super().__init__()
        self.analyzer = dspy.ChainOfThought(VulnDetectionSignature)
        self.refiner = dspy.Refine(
            module=dspy.ChainOfThought(RefinedTestSignature),
            N=5,  # More attempts for novel vulns
            reward_fn=novel_vuln_reward,
            threshold=0.6,  # Lower threshold for discovery
        )
    
    def forward(self, service_info, response_data, known_exploits=""):
        # Phase 1: Analyze for novel vulns
        analysis = self.analyzer(
            service_info=service_info,
            response_data=response_data,
            known_exploits=known_exploits,
        )
        
        if analysis.confidence < 0.3:
            return dspy.Prediction(found=False, reason="Low confidence")
        
        # Phase 2: Adaptive testing
        test_result = self.refiner(
            target=response_data,
            suspected_vuln=analysis.suspected_vulnerability,
            test_payload=analysis.test_payload,
        )
        
        # Phase 3: Log discovery if successful
        if test_result.success:
            self._log_discovery(analysis, test_result)
            
        return dspy.Prediction(
            found=test_result.success,
            vulnerability=analysis.suspected_vulnerability,
            proof=test_result.proof,
            confidence=analysis.confidence,
        )
```

### Exploit Pattern Storage

```python
class ExploitPattern(BaseModel):
    """A discovered successful exploit pattern."""
    service: str
    version_range: str
    vulnerability_type: str
    trigger_condition: str  # What triggers the vuln
    payload_template: str  # Generic pattern (not target-specific)
    proof_of_concept: str  # What happened
    reliability: float
    discovered_date: str
    discovered_by_model: str  # Which LLM found it
    waf_bypasses: list[str] = Field(default_factory=list)
    # How often this pattern works when tried
    success_rate: float = 1.0
    total_attempts: int = 1


class ExploitPatternLibrary:
    """Store and query discovered exploit patterns."""
    
    def log_success(self, pattern: ExploitPattern):
        # Check for similar existing patterns
        existing = self.find_similar(pattern)
        if existing:
            # Update success rate
            existing.total_attempts += 1
            existing.successful_attempts += 1
            existing.success_rate = (
                existing.successful_attempts / existing.total_attempts
            )
        else:
            # New pattern
            pattern.total_attempts = 1
            pattern.successful_attempts = 1
            self._save(pattern)
    
    def find_similar(self, pattern: ExploitPattern) -> ExploitPattern | None:
        """Find similar known patterns."""
        for stored in self._load_all():
            if (stored.service == pattern.service and
                stored.vulnerability_type == pattern.vulnerability_type):
                return stored
        return None
    
    def query_by_service(self, service: str) -> list[ExploitPattern]:
        """Get all known patterns for a service."""
        return [p for p in self._load_all() 
                if p.service == service.lower()]
```

### Integration with Reward Functions

The exploit pattern library feeds into reward functions:

```python
def recon_reward_with_memory(args: dict, pred: dspy.Prediction) -> float:
    """Enhanced recon reward that checks against known patterns."""
    findings = pred.findings
    score = 0.0
    if findings.hosts: score += 0.2
    if findings.ports: score += 0.2
    if findings.tech_stack: score += 0.2
    if findings.services: score += 0.2
    
    # Bonus: did recon find services we KNOW have exploitable patterns?
    pattern_lib = ExploitPatternLibrary()
    for svc in findings.services:
        known = pattern_lib.query_by_service(svc.name)
        if known:
            score += 0.05  # Bonus for finding known-vulnerable service
    
    return min(1.0, score)


def vuln_analysis_reward_with_memory(args: dict, pred: dspy.Prediction) -> float:
    """Vuln analysis that prioritizes pattern-library matches."""
    vulns = pred.vulnerabilities
    if not vulns: return 0.3
    score = min(0.6, len(vulns) * 0.1)
    
    # Big bonus: found something in pattern library
    pattern_lib = ExploitPatternLibrary()
    for v in vulns:
        if pattern_lib.find_by_cve(v.cve.cve_id):
            score += 0.1
        if pattern_lib.find_similar(v):
            score += 0.15  # Even bigger bonus for pattern match!
    
    # Novel discovery bonus
    if any(v.is_novel_discovery for v in vulns):
        score += 0.2
    
    return min(1.0, score)
```

---

## Performance Optimization Strategies

### 1. Smarter LM Routing (Multi-LM Strategy)

Different nodes need different model capabilities. Route intelligently:

```python
class MultiLMRouter:
    """Route DSPy nodes to appropriate models based on task complexity."""
    
    _ROUTING = {
        "recon": "anthropic/claude-sonnet-4-5-20250929",  # Tool-heavy
        "vuln_analysis": "anthropic/claude-sonnet-4-5-20250929",  # Knowledge-heavy
        "exploit_planner": "anthropic/claude-sonnet-4-5-20250929",  # Reasoning-heavy
        "payload_gen": "anthropic/claude-3.5-sonnet",  # Creative, cheaper
        "reporter": "google/gemini-3.1-flash-lite-preview",  # Text synthesis, cheap
        "self_eval": "nvidia/nemotron-3-super-120b-a12b:free",  # Cheap reward
    }
    
    def __init__(self, default_lm: dspy.LM, local_lm: dspy.LM | None = None):
        self.default_lm = default_lm
        self.local_lm = local_lm  # Ollama for cheap evaluation
    
    def route(self, node_type: str) -> dspy.LM:
        model_name = self._ROUTING.get(node_type, self.default_lm.model)
        # Use local LLM for self-evaluation
        if node_type == "self_eval" and self.local_lm:
            return self.local_lm
        return dspy.LM(model_name)
```

### 2. Aggressive Caching

```python
# Enable DSPy's built-in caching
dspy.configure_cache("sqlite", path="~/.spider/dspy_cache.db")

# Cache intelligence lookups
# cve_intelligence caches in memory + SQLite with 24h TTL
# exploit_matcher caches Exploit-DB responses
```

### 3. Parallel Intelligence Lookups

```python
async def parallel_lookup(cpe: str, service: str, version: str):
    """Fetch NVD, KEV, and EPSS in parallel."""
    nvd_task = asyncio.create_task(nvd.lookup_by_cpe(cpe))
    kev_task = asyncio.create_task(kev.check_service(service))
    epss_task = asyncio.create_task(epss.batch_score(cves))
    
    nvd_results, kev_results, epss_results = await asyncio.gather(
        nvd_task, kev_task, epss_task
    )
    return merge_results(nvd_results, kev_results, epss_results)
```

---

## Optimization Schedule

| Phase | Optimizer | When | Input | Output |
|-------|-----------|------|-------|--------|
| 1: Lab Testing | BootstrapFewShot | After 3 lab targets | DVWA, Juice Shop traces | few-shot demos |
| 2: Signature Tuning | MIPROv2 (light) | After 5 lab targets | Lab dataset | Optimized instructions |
| 3: Full Optimization | MIPROv2 (medium) | After 10 lab targets | Extended dataset | Better instructions + demos |
| 4: Failure Reflection | GEPA | After 5+ sessions (inc. failures) | Sessions with mixed results | Pareto-optimal prompts |
| 5: Fine-Tuning | BootstrapFinetune | After 50+ sessions | Large trace dataset | Fine-tuned model weights |

---

## The Self-Living System

After sufficient sessions, SPIDER becomes a **living system** that:

1. **Remembers** every pentest it has ever run (traces store)
2. **Learns** which prompts work best for which service types (GEPA)
3. **Collects** proven attack patterns (exploit_patterns.jsonl)
4. **Improves** automatically after each session (optimization pipeline)
5. **Discovers** novel vulnerabilities via adaptive testing
6. **Validates** discoveries against known patterns (false positive reduction)
7. **Optimizes** compute usage via model routing

The knowledge store is the key. Every failed exploit teaches the system how to
do better. Every successful discovery enriches the pattern library. Every
false positive tightens the validation criteria.

This is what NO existing pentest framework has -- not HexStrike, not LuaN1ao,
not Tengu. They all run "cold" every time. SPIDER gets **warm** -- it carries
knowledge forward, compiles its own prompts, and evolves its own instructions.
