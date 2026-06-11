"""Recon node -- root ReAct module for network discovery.

Discovers all hosts, ports, services, and technologies on the target.
Wrapped with dspy.Refine for self-improving reconnaissance quality.
"""

from typing import Any

import dspy

from spider.schemas import ReconResults, TargetSpec


class ReconSignature(dspy.Signature):
    """Perform comprehensive reconnaissance on the target.

    GROUNDING RULE: Base ALL findings strictly on tool output.
    If a tool returns an error or no data, report empty findings for that category.
    NEVER fabricate hosts, ports, services, or technologies.

    CRITICAL: Your final answer MUST be valid JSON matching the ReconResults schema.
    No conversational text. No preambles. Just the data."""

    target_spec: TargetSpec = dspy.InputField(desc="Authorized target descriptor to scan")
    recon_results: ReconResults = dspy.OutputField()


class ReconModule(dspy.Module):
    """ReAct reconnaissance module with dspy.Refine self-improvement.

    This is ALWAYS the root node of the pentest graph. It discovers
    the attack surface by calling security tools (nmap, whois, dns_enum,
    subdomain_enum) and synthesizing results into a ReconResults object.
    """

    def __init__(self, tools: list[dspy.Tool], config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        base = dspy.ReAct(ReconSignature, tools=tools, max_iters=15)

        def recon_reward(args: dict, pred: dspy.Prediction) -> float:
            """Reward recon completeness: hosts + ports + services + tech."""
            findings = pred.recon_results
            score = 0.0
            if findings.hosts:
                score += 0.3
            if findings.ports:
                score += 0.3
            if findings.tech_stack:
                score += 0.2
            if findings.services:
                score += 0.2
            return min(1.0, score)

        if self.config and self.config.use_refine:
            self.agent = dspy.Refine(
                module=base,
                N=self.config.max_refine_retries,
                reward_fn=recon_reward,
                threshold=0.7,
            )
        else:
            self.agent = base

    def forward(self, **kwargs):
        target_spec = kwargs.get("target_spec")
        with dspy.settings.context(temperature=0.1):
            return self.agent(target_spec=target_spec)
