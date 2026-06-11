"""Vulnerability analysis node -- CVE matching and exploit availability.

Cross-references discovered services with NVD, CISA KEV, EPSS, and
Exploit-DB to identify known vulnerabilities.
"""

from typing import Any

import dspy

from spider.engine.self_eval import VulnAnalysisReward
from spider.schemas import ServiceDetails, VulnerabilityList, WebFindings


class VulnAnalysisSignature(dspy.Signature):
    """Analyze services and web findings for vulnerabilities.

    GROUNDING RULE: Only report vulnerabilities backed by tool output or intelligence data.
    If no vulnerabilities are found, return an empty list. NEVER fabricate CVEs or exploit data.

    CRITICAL: Your final answer MUST be valid JSON matching the VulnerabilityList schema.
    No conversational text. No preambles. Just the data."""

    web_findings: WebFindings = dspy.InputField()
    service_details: ServiceDetails = dspy.InputField()
    vulnerabilities: VulnerabilityList = dspy.OutputField()


class VulnerabilityAnalysisModule(dspy.Module):
    """Vulnerability analysis module."""

    def __init__(self, tools: list[dspy.Tool], config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        base_react = dspy.ReAct(VulnAnalysisSignature, tools=tools)

        if config and config.use_refine:
            self.analyzer = dspy.Refine(
                module=base_react,
                N=config.max_refine_retries,
                reward_fn=VulnAnalysisReward(),
                threshold=config.refine_threshold,
            )
        else:
            self.analyzer = base_react

    def forward(
        self, web_findings: WebFindings, service_details: ServiceDetails
    ) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(
                web_findings=web_findings,
                service_details=service_details,
            )
