"""Recon node -- root ReAct module for network discovery.

Discovers all hosts, ports, services, and technologies on the target.
Wrapped with dspy.Refine for self-improving reconnaissance quality.
"""

import dspy

from spider.schemas import ReconResults


class ReconSignature(dspy.Signature):
    """Perform comprehensive reconnaissance on the target.

    CRITICAL: Your final answer MUST be valid JSON matching the ReconResults schema.
    No conversational text. No preambles. Just the data."""

    target: str = dspy.InputField(desc="Target IP or hostname to scan")
    recon_results: ReconResults = dspy.OutputField()


class ReconModule(dspy.Module):
    """ReAct reconnaissance module with dspy.Refine self-improvement.

    This is ALWAYS the root node of the pentest graph. It discovers
    the attack surface by calling security tools (nmap, whois, dns_enum,
    subdomain_enum) and synthesizing results into a ReconResults object.
    """

    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
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

        self.agent = dspy.Refine(
            module=base,
            N=3,
            reward_fn=recon_reward,
            threshold=0.7,
        )

    def forward(self, **kwargs):
        target = kwargs.get("target", "")
        with dspy.settings.context(temperature=0.1):
            return self.agent(target=target)
