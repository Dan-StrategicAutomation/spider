"""Reporter node -- pentest report generation.

Synthesizes all findings into a structured report with executive summary,
technical details, attack chains, and remediation guidance.
"""

from typing import Any

import dspy

from spider.schemas import AttackPlan, PentestReport, ReconResults, VulnerabilityList


class ReconReporterSignature(dspy.Signature):
    """Generate a reconnaissance report from recon and vulnerability findings. Include:
    - Executive summary with overall risk rating
    - Discovered hosts, services, technologies, and exposures
    - Technical findings with CVSS scores where available
    - Remediation recommendations
    - Methodology and timeline."""

    recon_results: ReconResults = dspy.InputField()
    vulnerabilities: VulnerabilityList = dspy.InputField()
    report: PentestReport = dspy.OutputField()


class ReporterSignature(dspy.Signature):
    """Generate a comprehensive pentest report. Include:
    - Executive summary with overall risk rating
    - Technical findings with CVSS scores and proof
    - Attack chains discovered
    - Remediation recommendations
    - Methodology and timeline."""

    recon_results: ReconResults = dspy.InputField()
    vulnerabilities: VulnerabilityList = dspy.InputField()
    attack_plan: AttackPlan = dspy.InputField()
    report: PentestReport = dspy.OutputField()


class ReconReporterModule(dspy.Module):
    """Reconnaissance report generation module."""

    def __init__(self, tools: list[dspy.Tool] | None = None, config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        # Optimized: Predict is significantly more token-efficient for large analytical outputs
        self.generator = dspy.Predict(ReconReporterSignature)

    def forward(
        self,
        recon_results: ReconResults,
        vulnerabilities: VulnerabilityList,
    ) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.generator(
                recon_results=recon_results,
                vulnerabilities=vulnerabilities,
            )


class ReporterModule(dspy.Module):
    """Full pentest report generation module."""

    def __init__(self, tools: list[dspy.Tool] | None = None, config: Any | None = None, **kwargs):
        super().__init__()
        self.config = config
        # Optimized: Predict is significantly more token-efficient for large analytical outputs
        self.generator = dspy.Predict(ReporterSignature)

    def forward(
        self,
        recon_results: ReconResults,
        vulnerabilities: VulnerabilityList,
        attack_plan: AttackPlan,
    ) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.generator(
                recon_results=recon_results,
                vulnerabilities=vulnerabilities,
                attack_plan=attack_plan,
            )
