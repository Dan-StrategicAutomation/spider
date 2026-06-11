"""Enumeration nodes -- web and service enumeration.

Two parallel modules: WebEnumeration and ServiceEnumeration.
Both wrapped with dspy.Refine for quality improvement.
"""

from typing import Any

import dspy

from spider.schemas import ReconResults, ServiceDetails, WebFindings


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
    """Web enumeration module."""

    def __init__(self, tools: list[dspy.Tool], config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        if tools:
            base_module = dspy.ReAct(WebEnumSignature, tools=tools)
        else:
            base_module = dspy.Predict(WebEnumSignature)

        if config and config.use_refine:
            self.analyzer = dspy.Refine(
                module=base_module,
                N=config.max_refine_retries,
                reward_fn=lambda _a, _p: float(len(_p.web_findings.directories) > 0),
                threshold=config.refine_threshold,
            )
        else:
            self.analyzer = base_module

    def forward(self, recon_results: ReconResults) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(recon_results=recon_results)


class ServiceEnumerationModule(dspy.Module):
    """Service enumeration module."""

    def __init__(self, tools: list[dspy.Tool], config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        if tools:
            base_module = dspy.ReAct(SvcEnumSignature, tools=tools)
        else:
            base_module = dspy.Predict(SvcEnumSignature)

        if config and config.use_refine:
            self.analyzer = dspy.Refine(
                module=base_module,
                N=config.max_refine_retries,
                reward_fn=lambda _a, _p: float(len(_p.service_details.service_name) > 0),
                threshold=config.refine_threshold,
            )
        else:
            self.analyzer = base_module

    def forward(self, recon_results: ReconResults) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(recon_results=recon_results)
