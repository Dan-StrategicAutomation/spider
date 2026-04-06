"""Executor node -- HITL-gated exploitation.

Requires human approval for each exploit step. Uses ReAct with tools
for actual exploitation attempts.
"""

import dspy

from spider.schemas import ExploitResult


class ExecutorSignature(dspy.Signature):
    """Execute exploitation attempts following the approved attack plan.
    Each step requires human approval before execution. Use available
    exploitation tools (sqlmap, hydra, metasploit) to gain access."""
    attack_plan: str = dspy.InputField()
    target: str = dspy.InputField()
    exploit_result: ExploitResult = dspy.OutputField()


class ExecutorModule(dspy.Module):
    """Exploit execution module with dspy.Refine.

    HITL gate is enforced outside this module -- the HITL gate checks
    each tool call before the ReAct agent can execute it.
    """
    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
        base = dspy.ReAct(ExecutorSignature, tools=tools, max_iters=10)

        def exec_reward(args: dict, pred: dspy.Prediction) -> float:
            result = pred.exploit_result
            score = 0.0
            if result.success:
                score += 0.5
            if result.access_level:
                score += 0.3
            if result.next_step_ready:
                score += 0.2
            return min(1.0, score)

        self.agent = dspy.Refine(
            module=base,
            N=3,
            reward_fn=exec_reward,
            threshold=0.6,
        )

    def forward(self, attack_plan: str, target: str) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.agent(attack_plan=attack_plan, target=target)
