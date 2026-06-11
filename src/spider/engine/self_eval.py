"""Self-evaluation modules for pentest output quality.

Used as reward functions for dspy.Refine on each node type.
"""

import dspy

from spider.schemas import EvaluationContext, PentestGoal, QualityScore


class SelfEvalSignature(dspy.Signature):
    """Evaluate pentest output quality. Check:
    - Does the output address the goal?
    - Are findings specific and actionable (not vague)?
    - Is there sufficient evidence/detail to support claims?
    - Would a human pentester consider this result useful?"""

    evaluation_context: EvaluationContext = dspy.InputField()
    evaluation: QualityScore = dspy.OutputField()


class SelfEvaluator(dspy.Module):
    """DSPy-native quality evaluator for pentest node outputs."""

    def __init__(self):
        super().__init__()
        self.judge = dspy.ChainOfThought(SelfEvalSignature)

    def evaluate(self, goal: PentestGoal, result: dspy.Prediction) -> float:
        """Evaluate the overall quality of a complete pentest result prediction."""
        # For a full result, we judge the aggregate output.
        return self(
            evaluation_context=EvaluationContext(
                goal=goal,
                node_type="overall",
                output_snapshot=str(result),
            )
        )

    def forward(self, evaluation_context: EvaluationContext) -> float:
        try:
            result = self.judge(evaluation_context=evaluation_context)
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
    """Reward for vulnerability analysis quality."""

    def __call__(self, args: dict, pred: dspy.Prediction) -> float:
        vulns = pred.vulnerabilities
        if not vulns:
            return 0.3  # Not finding vulns isn't necessarily bad
        score = min(0.7, len(vulns) * 0.1)
        if any(v.cve.cvss_score > 7.0 for v in vulns):
            score += 0.15
        if any(v.cve.has_public_exploit for v in vulns):
            score += 0.1
        if any(v.cve.in_kev for v in vulns):
            score += 0.05
        return min(1.0, score)


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
