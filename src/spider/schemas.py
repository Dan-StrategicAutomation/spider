"""Centralized Pydantic schemas for SPIDER.

ALL structured data models live here. Do not create ad-hoc models in other modules.
Topology schemas (NodeDef, GraphTopology) also live here for centralization.
"""

from enum import StrEnum
from pydantic import BaseModel, Field, field_validator


# ── Recon Schemas ────────────────────────────────────────────────────────────

class PortInfo(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str  # "tcp", "udp"
    state: str  # "open", "closed", "filtered"
    service: str  # "http", "ssh", "mysql", etc.
    version: str = ""
    extra: str = ""


class ServiceInfo(BaseModel):
    name: str
    version: str = ""
    port: int = 0
    extra: str = ""


class TechInfo(BaseModel):
    name: str
    version: str = ""
    category: str  # "webserver", "framework", "language", "cms", "database"
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class ReconResults(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    ports: list[PortInfo] = Field(default_factory=list)
    services: list[ServiceInfo] = Field(default_factory=list)
    tech_stack: list[TechInfo] = Field(default_factory=list)
    raw_output: str = ""


# ── Enumeration Schemas ──────────────────────────────────────────────────────

class WebParamInfo(BaseModel):
    url: str
    method: str  # "GET", "POST", etc.
    param_name: str
    param_type: str  # "query", "body", "cookie", "header"
    potential_vulns: list[str] = Field(default_factory=list)


class DirectoryEntry(BaseModel):
    path: str
    status_code: int
    content_type: str = ""
    size: int = 0


class WebFindings(BaseModel):
    directories: list[DirectoryEntry] = Field(default_factory=list)
    params: list[WebParamInfo] = Field(default_factory=list)
    technologies: list[TechInfo] = Field(default_factory=list)
    potential_vulns: list[str] = Field(default_factory=list)
    raw_output: str = ""


class ServiceDetails(BaseModel):
    service_name: str
    version: str = ""
    config_info: str = ""
    default_credentials_possible: bool = False
    known_weaknesses: list[str] = Field(default_factory=list)
    raw_output: str = ""


# ── Vulnerability Schemas ────────────────────────────────────────────────────

class CVEFinding(BaseModel):
    cve_id: str
    cvss_score: float = Field(ge=0.0, le=10.0, default=0.0)
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    epss_score: float = Field(ge=0.0, le=1.0, default=0.0)
    in_kev: bool = False
    has_public_exploit: bool = False
    summary: str = ""
    references: list[str] = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}
        if not v or v.upper() not in valid:
            return "NONE"
        return v.upper()


class ExploitMatch(BaseModel):
    exploit_id: str
    source: str  # "exploit-db", "metasploit", "github-poc"
    title: str
    platform: str = ""
    reliability: str = "average"  # "excellent", "good", "average", "manual"
    privileges_required: str = ""
    success_probability: float = Field(ge=0.0, le=1.0, default=0.5)
    metasploit_module: str | None = None
    exploit_db_id: int | None = None
    notes: str = ""


class VulnerabilityInfo(BaseModel):
    cve: CVEFinding
    affected_service: str = ""
    affected_version: str = ""
    matched_exploits: list[ExploitMatch] = Field(default_factory=list)
    remediation_hint: str = ""


class VulnerabilityList(BaseModel):
    vulnerabilities: list[VulnerabilityInfo] = Field(default_factory=list)
    total_critical: int = 0
    total_high: int = 0
    raw_output: str = ""


# ── Exploit Planning Schemas ─────────────────────────────────────────────────

class AttackStep(BaseModel):
    step_number: int
    action: str
    tool: str
    cve_id: str | None = None
    expected_outcome: str = ""
    hitl_required: bool = True
    risk_level: str = "medium"  # "low", "medium", "high", "critical"

    @field_validator("risk_level", mode="before")
    @classmethod
    def validate_risk(cls, v: str) -> str:
        valid = {"low", "medium", "high", "critical"}
        if not v or v.lower() not in valid:
            return "medium"
        return v.lower()


class AttackChain(BaseModel):
    name: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    final_objective: str = ""
    overall_risk: str = "medium"
    stealth_score: float = Field(ge=0.0, le=1.0, default=0.5)
    feasibility_score: float = Field(ge=0.0, le=1.0, default=0.5)


class AttackPlan(BaseModel):
    chains: list[AttackChain] = Field(default_factory=list)
    hitl_required_count: int = 0
    total_steps: int = 0
    raw_output: str = ""


# ── Exploitation Schemas ─────────────────────────────────────────────────────

class ExploitResult(BaseModel):
    success: bool = False
    access_level: str = ""  # "user", "admin", "system", "root"
    credentials_found: list[str] = Field(default_factory=list)
    output: str = ""
    chain_step_completed: int = 0
    next_step_ready: bool = False


# ── Post-Exploitation Schemas ────────────────────────────────────────────────

class PostExploitResult(BaseModel):
    success: bool = False
    escalation_achieved: str = ""  # "none", "user", "admin", "root"
    lateral_movement_possible: bool = False
    persistence_established: bool = False
    output: str = ""


# ── Reporting Schemas ────────────────────────────────────────────────────────

class ExecutiveSummary(BaseModel):
    overall_risk: str = ""
    critical_findings_count: int = 0
    high_findings_count: int = 0
    attack_paths_discovered: int = 0
    summary_text: str = ""


class FindingDetail(BaseModel):
    title: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    severity: str = ""
    description: str = ""
    proof_of_exploitation: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)


class PentestReport(BaseModel):
    target: str = ""
    scope: str = ""
    executive_summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    findings: list[FindingDetail] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    methodology: str = ""
    timeline: str = ""
    raw_output: str = ""


# ── Topology Schemas (Graph Definition) ──────────────────────────────────────

class NodeRole(StrEnum):
    CHAIN_OF_THOUGHT = "chain_of_thought"
    REACT = "react"
    PREDICT = "predict"
    PROGRAM_OF_THOUGHT = "program_of_thought"


class ToolDef(BaseModel):
    name: str
    description: str = ""
    parameters: list[dict] = Field(default_factory=list)


class NodeDef(BaseModel):
    id: str = Field(..., description="Unique snake_case ID")
    role: NodeRole
    name: str
    description: str = Field(..., description="System prompt for this node")
    inputs: list[str] = Field(default_factory=list)
    output: str = Field(..., description="Output field name")
    depends_on: list[str] = Field(default_factory=list)
    tools: list[ToolDef] = Field(default_factory=list)


class EdgeDef(BaseModel):
    source: str
    target: str
    label: str = ""


class GraphTopology(BaseModel):
    name: str
    objective: str
    nodes: list[NodeDef]
    edges: list[EdgeDef]
    runtime_inputs: list[str] = Field(default_factory=list)

    def topological_waves(self) -> list[list[str]]:
        """Returns waves of node IDs for parallel execution.

        Raises ValueError if the graph contains a cycle."""
        id_set = {n.id for n in self.nodes}
        in_degree: dict[str, int] = {n.id: 0 for n in self.nodes}
        adj: dict[str, list[str]] = {n.id: [] for n in self.nodes}
        for e in self.edges:
            if e.source in id_set and e.target in id_set:
                in_degree[e.target] += 1
                adj[e.source].append(e.target)
        waves: list[list[str]] = []
        queue = sorted([k for k, d in in_degree.items() if d == 0])
        while queue:
            waves.append(list(queue))
            next_q = []
            for node_id in queue:
                for nb in adj[node_id]:
                    in_degree[nb] -= 1
                    if in_degree[nb] == 0:
                        next_q.append(nb)
            queue = sorted(next_q)
        total_in_waves = len(set().union(*(set(w) for w in waves))) if waves else 0
        if total_in_waves != len(id_set):
            raise ValueError("Cycle detected in topology -- graph must be a DAG")
        return waves


# ── Evaluation / Helper Schemas ──────────────────────────────────────────────

class QualityScore(BaseModel):
    score: float = Field(ge=0.0, le=1.0, description="Quality score 0-1")
    reasoning: str = ""
    issues: list[str] = Field(default_factory=list)
    improvements: list[str] = Field(default_factory=list)


class TopologyScore(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    is_valid_dag: bool = True
    has_react_root: bool = True
    reasoning: str = ""


class AdaptationResult(BaseModel):
    test_name: str = ""
    initial_result: str = ""
    adaptation_made: str = ""
    new_result: str = ""
    success: bool = False
    attempts: int = 1


class GeneratedPayload(BaseModel):
    payload: str = ""
    encoding: str = "raw"
    vuln_type: str = ""
    expected_result: str = ""
    waf_bypass_notes: str = ""
    validation_status: str = "valid"
