"""Self-evaluation modules for pentest output quality.

Used as reward functions for dspy.Refine on each node type.
"""

from typing import Any

import dspy

from spider.schemas import (
    QualityScore,
    ReconResults,
    ServiceDetails,
    VulnerabilityList,
    WebFindings,
)


class SelfEvalSignature(dspy.Signature):
    """Evaluate pentest output quality. Check:
    - Does the output address the goal?
    - Are findings specific and actionable (not vague)?
    - Is there sufficient evidence/detail to support claims?
    - Would a human pentester consider this result useful?"""

    goal: str = dspy.InputField()
    node_type: str = dspy.InputField(
        desc="Type of pentest node: recon, vuln_analysis, exploit_plan, report"
    )
    output: str = dspy.InputField()
    evaluation: QualityScore = dspy.OutputField()


class VulnerabilityRewardSignature(dspy.Signature):
    """Evaluate vulnerability analysis as a Refine reward.

    Score the submitted vulnerabilities against web and service evidence. Reward evidence presence,
    CVE/source references, consistency with service_details, absence of unsupported CVEs, and
    evidence-backed empty VulnerabilityList outputs when tools support no vulnerability findings.
    """

    web_findings: WebFindings = dspy.InputField()
    service_details: ServiceDetails = dspy.InputField()
    vulnerabilities: VulnerabilityList = dspy.InputField()
    evaluation: QualityScore = dspy.OutputField()


class WebEnumerationRewardSignature(dspy.Signature):
    """Evaluate web enumeration as a Refine reward.

    Score submitted web findings against recon evidence. Reward grounded directories, parameters,
    technologies, potential vulnerability notes, and evidence-backed empty results when probing
    found no web surface or no web findings.
    """

    recon_results: ReconResults = dspy.InputField()
    web_findings: WebFindings = dspy.InputField()
    evaluation: QualityScore = dspy.OutputField()


class SelfEvaluator(dspy.Module):
    """DSPy-native quality evaluator for pentest node outputs."""

    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(SelfEvalSignature)

    def evaluate(self, goal: str, result: dspy.Prediction) -> float:
        """Evaluate the overall quality of a complete pentest result prediction."""
        # For a full result, we judge the aggregate output
        return self(goal=goal, node_type="overall", pred=result)

    def forward(self, goal: str, node_type: str, pred: dspy.Prediction) -> float:
        output_val = str(pred)
        try:
            result = self.judge(goal=goal, node_type=node_type, output=output_val)
            # Use the wrap helper to handle cases where result.evaluation might
            # be a float or a dict instead of the QualityScore model
            eval_obj = QualityScore.wrap(getattr(result, "evaluation", 0.0))
            return float(eval_obj.score)
        except Exception as e:
            # Fallback for severe parsing failures
            import sys

            print(f"    [!] SelfEvaluator parsing failed: {e}", file=sys.stderr)
            return 0.0


class ReconReward:
    """Deterministic reward for recon phase completeness."""

    def __call__(self, args: dict, pred: dspy.Prediction) -> float:
        findings = pred.findings
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


class VulnAnalysisReward:
    """DSPy-native reward for grounded vulnerability analysis outputs."""

    def __init__(self, judge: dspy.Module | None = None):
        self.judge = judge or dspy.Predict(VulnerabilityRewardSignature)

    def __call__(self, args: dict[str, Any], pred: dspy.Prediction) -> float:
        vulnerabilities = getattr(pred, "vulnerabilities", None)
        if not isinstance(vulnerabilities, VulnerabilityList):
            return 0.0

        web_findings = args.get("web_findings")
        if not isinstance(web_findings, WebFindings):
            web_findings = WebFindings()

        service_details = args.get("service_details")
        if not isinstance(service_details, ServiceDetails):
            service_details = ServiceDetails()

        result = self.judge(
            web_findings=web_findings,
            service_details=service_details,
            vulnerabilities=vulnerabilities,
        )
        return _reward_score(result)


class WebEnumerationReward:
    """DSPy-native reward for grounded web enumeration outputs."""

    def __init__(self, judge: dspy.Module | None = None):
        self.judge = judge or dspy.Predict(WebEnumerationRewardSignature)

    def __call__(self, args: dict[str, Any], pred: dspy.Prediction) -> float:
        web_findings = getattr(pred, "web_findings", None)
        if not isinstance(web_findings, WebFindings):
            return 0.0

        recon_results = args.get("recon_results")
        if not isinstance(recon_results, ReconResults):
            recon_results = ReconResults()

        result = self.judge(recon_results=recon_results, web_findings=web_findings)
        return _reward_score(result)


def _reward_score(result: dspy.Prediction) -> float:
    return float(QualityScore.wrap(getattr(result, "evaluation", 0.0)).score)


class ExploitPlanReward:
    """Reward for attack chain feasibility and completeness."""

    def __call__(self, args: dict, pred: dspy.Prediction) -> float:
        chains = pred.attack_chains
        if not chains:
            return 0.0
        score = 0.0
        for chain in chains:
            if chain.steps:
                score += 0.2
            if chain.feasibility_score > 0.5:
                score += 0.15
            if chain.stealth_score > 0.5:
                score += 0.1
        return min(1.0, score)
