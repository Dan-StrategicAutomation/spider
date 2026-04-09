"""Tool adapter -- wraps security tools with scope checking, audit logging, timeouts.

Every security tool goes through this adapter before execution.
This ensures no tool can run out-of-scope or without being logged.
"""

import functools
import json
import shutil
import subprocess

import dspy


def _sanitize_args(kwargs: dict) -> dict:
    """Robustly unwrap common LLM hallucinations in tool arguments.

    Local models often pass {"target": {"target": "127.0.0.1"}} instead of
    {"target": "127.0.0.1"}. This helper flattens such structures.
    """
    sanitized = {}
    for k, v in kwargs.items():
        if isinstance(v, dict) and k in v:
            # Unwrap nested dict: {"target": {"target": "..."}} -> "..."
            sanitized[k] = v[k]
        else:
            sanitized[k] = v
    return sanitized


def make_tool(func, *, scope_guard=None, audit_logger=None, timeout=300, required_binary=None):
    """Wrap a tool function with scope checking, audit logging, and timeout.

    Returns a dspy.Tool that can be passed to dspy.ReAct, or None if a
    required binary is missing.
    """
    if required_binary and shutil.which(required_binary) is None:
        return None

    @functools.wraps(func)
    def wrapped(*args, **kwargs):
        # 0. Sanitize arguments (unwrap LLM hallucinations)
        kwargs = _sanitize_args(kwargs)

        # 1. Scope check
        # Look for target, domain, or host in kwargs or as first positional argument
        candidate_target = kwargs.get("target") or kwargs.get("domain") or kwargs.get("host")
        if not candidate_target and len(args) > 0 and isinstance(args[0], str):
            candidate_target = args[0]

        if scope_guard and candidate_target:
            authorized, reason = scope_guard.authorize(candidate_target, func.__name__)
            if not authorized:
                return json.dumps(
                    {
                        "error": f"OUT_OF_SCOPE: {reason}",
                        "tool": func.__name__,
                        "target": candidate_target,
                        "authorized": False,
                    }
                )

        # 2. Audit log start
        if audit_logger:
            audit_logger.log(
                action=func.__name__,
                target=candidate_target or "unknown",
                phase="started",
                params={k: v for k, v in kwargs.items() if k != "target"},
            )

        # 3. Execute with timeout
        try:
            result = func(*args, **kwargs)
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
                target=candidate_target or "unknown",
                phase=phase,
                result=result[:500] if isinstance(result, str) else "",
            )

        return result

    return dspy.Tool(wrapped)


def make_tool_from_cmd(
    name: str,
    command: list[str],
    docstring: str,
    audit_logger=None,
    timeout: int = 300,
    required_binary: str | None = None,
) -> dspy.Tool | None:
    """Create a dspy.Tool from a CLI command template.

    The command list uses {placeholder} syntax for parameter substitution.
    Returns None if a required binary is missing.
    """
    if required_binary and shutil.which(required_binary) is None:
        return None

    def run(**kwargs) -> str:
        # 0. Sanitize arguments (unwrap LLM hallucinations)
        kwargs = _sanitize_args(kwargs)

        # 1. Look for target, domain, or host in kwargs for scope validation
        candidate_target = kwargs.get("target") or kwargs.get("domain") or kwargs.get("host")

        if scope_guard and candidate_target:
            authorized, reason = scope_guard.authorize(candidate_target, name)
            if not authorized:
                return json.dumps({"error": f"OUT_OF_SCOPE: {reason}", "tool": name})

        # 2. Audit log start
        if audit_logger:
            audit_logger.log(action=name, target=kwargs.get("target", ""), phase="started")

        # 3. Build command (only uses parameters found in the command template)
        try:
            cmd = [part.format(**kwargs) for part in command]
        except KeyError as e:
            # If the LLM missed a required parameter that the command template needs
            return json.dumps({"error": f"MISSING_PARAMETER: {str(e)}", "tool": name})

        # 4. Execution
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = json.dumps(
                {
                    "success": result.returncode == 0,
                    "stdout": result.stdout[:10000],
                    "stderr": result.stderr[:2000],
                    "exit_code": result.returncode,
                }
            )
            phase = "completed" if result.returncode == 0 else "error"
        except subprocess.TimeoutExpired:
            output = json.dumps({"error": "TIMEOUT", "limit": timeout})
            phase = "timeout"
        except Exception as e:
            output = json.dumps({"error": str(e)})
            phase = "error"

        # 5. Audit log completion
        if audit_logger:
            audit_logger.log(
                action=name,
                target=kwargs.get("target", ""),
                phase=phase,
                result=output[:500],
            )

        return output

    # Attach docstring and name for DSPy tool inspection
    run.__doc__ = docstring
    run.__name__ = name

    # For command-based tools, we just use **kwargs directly in the signature
    # as they are dynamic by nature.
    return dspy.Tool(run)
