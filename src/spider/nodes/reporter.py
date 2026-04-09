"""Reporter node -- pentest report generation.

Synthesizes all findings into a structured report with executive summary,
technical details, attack chains, and remediation guidance.
"""

import dspy

from spider.schemas import AttackPlan, PentestReport, ReconResults, VulnerabilityList


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


class ReporterModule(dspy.Module):
    """Report generation module."""

    def __init__(self):
        super().__init__()
        generator = dspy.ChainOfThought(ReporterSignature)

        def report_reward(args: dict, pred: dspy.Prediction) -> float:
            rpt = pred.report
            score = 0.0
            if rpt.executive_summary.summary_text:
                score += 0.2
            if rpt.findings:
                score += 0.3
            if rpt.attack_chains:
                score += 0.2
            if rpt.remediation:
                score += 0.1
            if rpt.methodology:
                score += 0.1
            if rpt.timeline:
                score += 0.1
            return min(1.0, score)

        self.generator = dspy.Refine(
            module=generator,
            N=3,
            reward_fn=report_reward,
            threshold=0.8,
        )

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
