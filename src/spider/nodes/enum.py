"""Enumeration nodes -- web and service enumeration.

Two parallel modules: WebEnumeration and ServiceEnumeration.
Both wrapped with dspy.Refine for quality improvement.
"""

import dspy

from spider.schemas import ServiceDetails, WebFindings


class WebEnumSignature(dspy.Signature):
    """Enumerate web applications on discovered targets.
    
    CRITICAL: Your final answer MUST be valid JSON matching the WebFindings schema.
    No conversational text. No preambles. Just the data."""
    recon_results: ReconResults = dspy.InputField()
    web_findings: WebFindings = dspy.OutputField()


class SvcEnumSignature(dspy.Signature):
    """Probe discovered services for version info and configurations.
    
    CRITICAL: Your final answer MUST be valid JSON matching the ServiceDetails schema.
    No conversational text."""
    recon_results: ReconResults = dspy.InputField()
    service_details: ServiceDetails = dspy.OutputField()


class WebEnumerationModule(dspy.Module):
    """Web enumeration module with dspy.Refine."""
    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
        analyzer = dspy.ChainOfThought(WebEnumSignature)

        def web_enum_reward(args: dict, pred: dspy.Prediction) -> float:
            findings = pred.web_findings
            score = 0.0
            if findings.directories:
                score += 0.3
            if findings.params:
                score += 0.2
            if findings.technologies:
                score += 0.3
            if findings.potential_vulns:
                score += 0.2
            return min(1.0, score)

        self.analyzer = dspy.Refine(
            module=analyzer,
            N=3,
            reward_fn=web_enum_reward,
            threshold=0.7,
        )

    def forward(self, recon_results: str) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(recon_results=recon_results)


class ServiceEnumerationModule(dspy.Module):
    """Service enumeration module with dspy.Refine."""
    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
        analyzer = dspy.ChainOfThought(SvcEnumSignature)

        def svc_enum_reward(args: dict, pred: dspy.Prediction) -> float:
            details = pred.service_details
            score = 0.0
            if details.service_name:
                score += 0.3
            if details.version:
                score += 0.3
            if details.known_weaknesses:
                score += 0.4
            return min(1.0, score)

        self.analyzer = dspy.Refine(
            module=analyzer,
            N=3,
            reward_fn=svc_enum_reward,
            threshold=0.7,
        )

    def forward(self, recon_results: str) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(recon_results=recon_results)
