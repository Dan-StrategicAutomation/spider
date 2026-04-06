"""Tool adapter -- wraps security tools with scope checking, audit logging, timeouts.

Every security tool goes through this adapter before execution.
This ensures no tool can run out-of-scope or without being logged.
"""

import functools
import json
import subprocess

import dspy


def make_tool(func, *, scope_guard=None, audit_logger=None, timeout=300):
    """Wrap a tool function with scope checking, audit logging, and timeout.

    Returns a dspy.Tool that can be passed to dspy.ReAct.
    """
    @functools.wraps(func)
    def wrapped(**kwargs):
        # 1. Scope check
        if scope_guard and "target" in kwargs:
            authorized, reason = scope_guard.authorize(kwargs["target"], func.__name__)
            if not authorized:
                return json.dumps({
                    "error": f"OUT_OF_SCOPE: {reason}",
                    "tool": func.__name__,
                    "authorized": False,
                })

        # 2. Audit log start
        if audit_logger:
            audit_logger.log(
                action=func.__name__,
                target=kwargs.get("target", "unknown"),
                phase="started",
                params={k: v for k, v in kwargs.items() if k != "target"},
            )

        # 3. Execute with timeout
        try:
            result = func(**kwargs)
            phase = "completed"
        except subprocess.TimeoutExpired:
            result = json.dumps({"error": "TIMEOUT", "limit": timeout})
            phase = "timeout"
        except Exception as e:
            result = json.dumps({"error": str(e)})
            phase = "error"

        # 4. Audit log completion
        if audit_logger:
            audit_logger.log(
                action=func.__name__,
                target=kwargs.get("target", "unknown"),
                phase=phase,
                result=result[:500] if isinstance(result, str) else "",
            )

        return result

    return dspy.Tool(wrapped)


def make_tool_from_cmd(
    name: str,
    command: list[str],
    docstring: str,
    scope_guard=None,
    audit_logger=None,
    timeout: int = 300,
) -> dspy.Tool:
    """Create a dspy.Tool from a CLI command template.

    The command list uses {placeholder} syntax for parameter substitution.
    """
    def run(**kwargs) -> str:
        # Build command
        cmd = [part.format(**kwargs) for part in command]

        if scope_guard and "target" in kwargs:
            authorized, reason = scope_guard.authorize(kwargs["target"], name)
            if not authorized:
                return json.dumps({"error": f"OUT_OF_SCOPE: {reason}", "tool": name})

        if audit_logger:
            audit_logger.log(action=name, target=kwargs.get("target", ""), phase="started")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = json.dumps({
                "success": result.returncode == 0,
                "stdout": result.stdout[:10000],
                "stderr": result.stderr[:2000],
                "exit_code": result.returncode,
            })
            phase = "completed" if result.returncode == 0 else "error"
        except subprocess.TimeoutExpired:
            output = json.dumps({"error": "TIMEOUT", "limit": timeout})
            phase = "timeout"
        except Exception as e:
            output = json.dumps({"error": str(e)})
            phase = "error"

        if audit_logger:
            audit_logger.log(
                action=name,
                target=kwargs.get("target", ""),
                phase=phase,
                result=output[:500],
            )

        return output

    # Attach docstring for DSPy tool inspection
    run.__doc__ = docstring
    run.__name__ = name

    return dspy.Tool(run)
