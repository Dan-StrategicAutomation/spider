"""SPIDER CLI -- main entry point with interactive pentest menus."""

import argparse
import json
import os
import sys
from pathlib import Path

import questionary

from spider.config import SpiderConfig
from spider.engine.orchestrator import SpiderOrchestrator
from spider.models import _ollama_available, configure_spider
from spider.observability import setup_observability
from spider.sandbox.audit_logger import AuditLogger
from spider.sandbox.hitl_gate import HITLGate
from spider.sandbox.scope_guard import ScopeGuard
from spider.schemas import ScanMode, validate_target_syntax

# ── Colors ──────────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ── Banner ──────────────────────────────────────────────────────────────

BANNER = f"""
{RED} ######  ########  #### ########  ######## ########
##    ## ##     ##  ##  ##     ## ##       ##     ##
##       ##     ##  ##  ##     ## ##       ##     ##
 ######  ########   ##  ##     ## ######   ########
      ## ##         ##  ##     ## ##       ##   ##
##    ## ##         ##  ##     ## ##       ##    ##
 ######  ##        #### ########  ######## ##     ##
{RESET}
    {DIM}DSPy-Native Pentesting Framework  |  Qwen3.5 Abliterated  |  Ollama{RESET}
    {DIM}───────────────────────────────────────────────────────────────{RESET}
"""


def banner():
    """Print the SPIDER banner."""
    os.system("clear")
    print(BANNER)


def divider(label=""):
    if label:
        print(f"\n{YELLOW}{'─' * 20} {label} {'─' * 20}{RESET}")
    else:
        print(f"\n{DIM}{'─' * 60}{RESET}")


def prompt(text):
    return input(f"\n{CYAN}{text}{RESET}").strip()


def success(text):
    print(f"\n{GREEN}[+] {text}{RESET}")


def warn(text):
    print(f"\n{YELLOW}[!] {text}{RESET}")


def error(text):
    print(f"\n{RED}[✗] {text}{RESET}")


def info(text):
    print(f"\n{BLUE}[*] {text}{RESET}")


def confirm(question) -> bool:
    ans = input(f"\n{CYAN}{question} {DIM}[y/N]{RESET}{CYAN}:{RESET} ").strip().lower()
    return ans == "y"


def cli_progress(step: str, detail: str):
    """Callback for engine progress reporting."""
    icon = f"{BLUE}[*]{RESET}"
    if "done" in step or "complete" in step or "ready" in step:
        icon = f"{GREEN}[+]{RESET}"
    elif "fail" in step or "error" in step:
        icon = f"{RED}[✗]{RESET}"
    elif "running" in step or "execute" in step or "weave" in step or "heal" in step:
        icon = f"{YELLOW}[>]{RESET}"

    # Indent sub-steps (node results)
    if "node_" in step or step == "wave":
        print(f"    {icon} {detail}")
    else:
        print(f"{icon} {detail}")


# ── Initialization ──────────────────────────────────────────────────────


def init_spider() -> tuple[SpiderConfig, SpiderOrchestrator]:
    """Initialize SPIDER configuration and orchestrator."""
    config = SpiderConfig()

    # Setup Langfuse / DSPy tracing
    setup_observability(config)

    divider("INITIALIZATION")
    info("Config loaded from .env / environment")

    # Pre-flight environment check
    from spider.tools.diagnostics import check_environment

    diag_results = check_environment()
    missing_req = [t for t in diag_results if t["required"] and not t["found"]]
    if missing_req:
        divider("ENVIRONMENT WARNING")
        error("Critical security tools are missing from your PATH:")
        for t in missing_req:
            print(f"  {RED}- {t['name']}:{RESET} {t['description']}")
        warn("Scans will likely fail. Please install these tools on your host.")

    missing_opt = [t for t in diag_results if not t["required"] and not t["found"]]
    if missing_opt:
        info(f"Optional tools missing: {', '.join([t['name'] for t in missing_opt])}")

    # Check Ollama
    if _ollama_available(config.ollama_base_url):
        success(f"Ollama running at {config.ollama_base_url}")
        info(f"Primary model: {config.primary_model}")
        info(f"Eval model: {config.eval_model}")
    else:
        error("Ollama not reachable")
        if config.openrouter_api_key:
            warn("Falling back to cloud model")
        else:
            error("No fallback configured. Set OPENROUTER_API_KEY")
            sys.exit(1)

    # Configure DSPy
    lm = configure_spider(config)
    info(f"DSPy configured with LM: {lm.model}")

    # Safety components
    scope_guard = ScopeGuard(
        allowed=config.allowed_targets,
        excluded=config.excluded_targets,
        lab_network=config.lab_network,
    )

    audit_logger = AuditLogger(log_path=Path.home() / ".spider" / "audit.log")

    hitl_gate = HITLGate(interactive=True)

    # Create orchestrator
    orchestrator = SpiderOrchestrator(
        config=config,
        scope_guard=scope_guard,
        audit_logger=audit_logger,
        hitl_gate=hitl_gate,
        progress_fn=cli_progress,
    )

    success(f"SPIDER initialized successfully with {len(orchestrator.tools)} tools")
    return config, orchestrator


# ── New Scan ────────────────────────────────────────────────────────────


def _build_goal(mode: ScanMode, target: str, custom_goal: str = "") -> str:
    """Build the goal string for a given scan mode and target."""
    if mode == ScanMode.CUSTOM:
        return custom_goal
    if mode == ScanMode.FULL:
        return (
            f"Perform a full penetration test against {target}. Discover vulnerabilities, "
            "build attack chains, and exploit them with human approval. "
            "Generate a complete report."
        )
    # RECON
    return (
        f"Perform comprehensive reconnaissance against {target}. Discover all "
        "hosts, ports, services, and technologies. Identify the attack surface."
    )


def run_scan_noninteractive(
    session_db, orchestrator, target: str, mode: ScanMode, custom_goal: str = ""
):
    """Run a single scan non-interactively (used by --scan flag)."""
    divider("NEW SCAN")
    info(f"Target: {target}")
    info(f"Mode: {mode.value}")

    # Check if target was scanned before
    past = session_db.find_by_target(target)
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")

    # Create session
    session_id = session_db.create_session(target)
    success(f"Session created — ID {session_id}")

    goal = _build_goal(mode, target, custom_goal=custom_goal)

    divider("SCANNING")
    info(f"Goal: {goal[:80]}...")

    try:
        result = orchestrator.run(goal=goal, target=target, mode=mode)

        # Check for orchestrator-level errors (e.g. scope)
        err = result.get("error") if isinstance(result, dict) else None
        if err and "OUT_OF_SCOPE" in str(err):
            error(f"Scan aborted: {err}")
            session_db.update_status(session_id, "failed")
            return

        success(f"Scan complete. Session ID: {session_id}")

        # Save results
        session_db.save_results(session_id, result)
        success(f"Results saved to session {session_id}")

        # Ensure traces are pushed to Langfuse
        from spider.observability import flush_observability

        flush_observability()

        # Show findings summary
        divider("FINDINGS")
        info("Scan results:")
        print(f"\n{BOLD}Session Results:{RESET}")
        if isinstance(result, dict):
            for key, val in result.items():
                if key in ("session_id", "target", "goal", "topology", "mode"):
                    continue
                print(f"  {CYAN}{key}{RESET}: {str(val)[:200]}")
        elif hasattr(result, "results"):
            for key, val in result.results.items():
                print(f"  {CYAN}{key}{RESET}: {str(val)[:200]}")

    except Exception as e:
        error(f"Scan failed: {e}")
        session_db.update_status(session_id, "failed")

    divider()


def new_scan(session_db, orchestrator):
    """Run a new pentest scan against a target (interactive)."""
    divider("NEW SCAN")

    def target_validator(text):
        if validate_target_syntax(text):
            return True
        return (
            "Invalid format: Enter a valid IP address or domain name "
            "(e.g., 127.0.0.1 or target.com)."
        )

    target = questionary.text("Enter target IP or domain:", validate=target_validator).ask()

    if not target:
        # User cancelled (e.g. Ctrl-C)
        return

    # Check scope early for interactive authorization
    if orchestrator.scope_guard:
        authorized, reason = orchestrator.scope_guard.authorize(target, "cli_new_scan")
        if not authorized:
            warn(f"Target {target!r} is not in your configured scope.")
            warn(f"Reason: {reason}")
            if not confirm("Authorize this scan interactively for this session?"):
                info("Scan cancelled.")
                return
            orchestrator.scope_guard.add_temp_authorization(target)
            success(f"Target {target!r} authorized interactively.")

    # Create session
    session_id = session_db.create_session(target)
    success(f"Session created — ID {session_id}")

    # Set scan mode
    divider("SCAN MODE")
    print(f"  {GREEN}[1]{RESET} Recon only (safe, autonomous)")
    print(f"  {GREEN}[2]{RESET} Full pentest (includes HITL-gated exploitation)")
    print(f"  {GREEN}[3]{RESET} Custom goal (natural language)")
    divider()
    mode_choice = prompt("Mode: ")

    if mode_choice == "3":
        mode = ScanMode.CUSTOM
        goal = prompt("Your goal: ")
        if not goal:
            warn("No goal provided. Cancelling.")
            return
    elif mode_choice == "2":
        mode = ScanMode.FULL
        goal = _build_goal(mode, target)
    else:
        mode = ScanMode.RECON
        goal = _build_goal(mode, target)

    divider("SCANNING")
    info(f"Target: {target}")
    info(f"Mode: {mode.value}")
    info(f"Goal: {goal[:80]}...")

    try:
        result = orchestrator.run(goal=goal, target=target, mode=mode)

        # Check for orchestrator-level errors (e.g. scope)
        err = result.get("error") if isinstance(result, dict) else None
        if err and "OUT_OF_SCOPE" in str(err):
            error(f"Scan aborted: {err}")
            session_db.update_status(session_id, "failed")
            return

        success(f"Scan complete. Session ID: {session_id}")

        # Save results
        session_db.save_results(session_id, result)
        success(f"Results saved to session {session_id}")

        # Ensure traces are pushed to Langfuse
        from spider.observability import flush_observability

        flush_observability()

        # Show findings
        show_findings(result)

    except Exception as e:
        error(f"Scan failed: {e}")
        session_db.update_status(session_id, "failed")

    divider()
    input(f"\n{DIM}Press Enter to continue...{RESET}")


# ── Show Findings ───────────────────────────────────────────────────────


def show_findings(result):
    """Display pentest findings in a nice format."""
    divider("FINDINGS")

    info("Scan results:")
    print(f"\n{BOLD}Session Results:{RESET}")
    if hasattr(result, "results"):
        for key, val in result.results.items():
            print(f"  {CYAN}{key}{RESET}: {str(val)[:200]}")
    elif isinstance(result, dict):
        for key, val in result.items():
            print(f"  {CYAN}{key}{RESET}: {str(val)[:200]}")


# ── View History ────────────────────────────────────────────────────────


def view_history(session_db):
    """View all past scan sessions."""
    divider("SCAN HISTORY")
    rows = session_db.get_all_sessions()

    if not rows:
        warn("No scans in database yet.")
        return

    print(f"\n{BOLD}{'ID':<6} {'Target':<20} {'Date':<20} {'Status':<12} {'Risk':<10}{RESET}")
    print(f"{DIM}{'─' * 68}{RESET}")
    for row in rows:
        sid = row.get("id", "N/A")
        target = row.get("target", "unknown")[:20]
        date = row.get("created_at", "unknown")[:19]
        status = row.get("status", "unknown")
        risk = row.get("risk_level", "—")

        status_color = GREEN if status == "completed" else RED
        row = f"  {sid:<6} {target:<20} {date:<20} {status_color}{status:<12}{RESET} "
        row += f"{YELLOW}{risk:<10}{RESET}"
        print(row)

    divider()
    sid_str = prompt("Enter Session ID to view details (or press Enter to go back): ")
    if not sid_str:
        return

    try:
        session = session_db.get_session(int(sid_str))
        if session:
            print(f"\n{BOLD}Session {sid_str}:{RESET}")
            print(f"  Target:     {session.get('target')}")
            print(f"  Status:     {session.get('status')}")
            print(f"  Risk Level: {session.get('risk_level', '—')}")
            findings = session.get("findings", {})
            print(f"  Findings:   {len(findings)} entries")
            if confirm("Export this session to JSON?"):
                export_path = Path(f"session_{sid_str}.json")
                with open(export_path, "w") as f:
                    json.dump(session, f, indent=2, default=str)
                success(f"Exported to {export_path}")
    except ValueError:
        error("Invalid session ID.")


# ── Pull Models ─────────────────────────────────────────────────────────


def pull_models(config):
    """Pull required Qwen3.5 abliterated models from Ollama."""
    divider("PULL MODELS")
    info("Checking and pulling Qwen3.5 abliterated models...")

    models = [
        config.primary_model,
        config.eval_model,
    ]

    for model in models:
        info(f"Checking: {model}")
        # We'll use the models module to check and pull
        from spider.models import _is_model_pulled, pull_model

        if _is_model_pulled(model, config.ollama_base_url):
            success(f"  Already downloaded: {model}")
        else:
            warn(f"  Pulling: {model} (this may take a while)")
            if pull_model(model, config.ollama_base_url):
                success(f"  Downloaded: {model}")
            else:
                error(f"  Failed to pull: {model}")

    input(f"\n{DIM}Press Enter to continue...{RESET}")


# ── Session Database (SQLite) ───────────────────────────────────────────


class SessionDB:
    """SQLite session store for pentest results."""

    def __init__(self, db_path: str | Path | None = None):
        self._db_path = Path(db_path) if db_path else Path.home() / ".spider" / "spider.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        c = conn.cursor()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                risk_level TEXT DEFAULT '',
                findings TEXT DEFAULT '{}',
                goal TEXT DEFAULT ''
            );
        """)
        conn.close()

    def create_session(self, target: str) -> int:
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        c = conn.cursor()
        c.execute("INSERT INTO sessions (target, status) VALUES (?, 'active')", (target,))
        conn.commit()
        sid = c.lastrowid
        conn.close()
        return sid

    def save_results(self, session_id: int, result):
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        c = conn.cursor()
        results_json = json.dumps(result, default=str)
        c.execute(
            "UPDATE sessions SET status='completed', findings=? WHERE id=?",
            (results_json, session_id),
        )
        conn.commit()
        conn.close()

    def update_status(self, session_id: int, status: str):
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        c = conn.cursor()
        c.execute("UPDATE sessions SET status=? WHERE id=?", (status, session_id))
        conn.commit()
        conn.close()

    def get_all_sessions(self) -> list[dict]:
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM sessions ORDER BY id DESC")
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def find_by_target(self, target: str) -> list[dict]:
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM sessions WHERE target=?", (target,))
        rows = [dict(r) for r in c.fetchall()]
        conn.close()
        return rows

    def get_session(self, session_id: int) -> dict | None:
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
        row = c.fetchone()
        result = dict(row) if row else None
        if result and result.get("findings"):
            try:
                result["findings"] = json.loads(result["findings"])
            except json.JSONDecodeError:
                result["findings"] = {}
        conn.close()
        return result


# ── Main Menu ───────────────────────────────────────────────────────────


def main_menu(session_db, config, orchestrator):
    while True:
        banner()
        print(f"  {GREEN}[1]{RESET}  New Scan")
        print(f"  {GREEN}[2]{RESET}  View History")
        print(f"  {GREEN}[3]{RESET}  Pull Models (Ollama)")
        print(f"  {GREEN}[4]{RESET}  Configuration")
        print(f"  {GREEN}[5]{RESET}  Exit")
        divider()

        choice = prompt("spider> ")

        if choice == "1":
            new_scan(session_db, orchestrator)
        elif choice == "2":
            view_history(session_db)
        elif choice == "3":
            pull_models(config)
        elif choice == "4":
            divider("CONFIGURATION")
            print(f"  Primary model:  {CYAN}{config.primary_model}{RESET}")
            print(f"  Eval model:     {CYAN}{config.eval_model}{RESET}")
            print(f"  Ollama URL:     {CYAN}{config.ollama_base_url}{RESET}")
            targets_str = ", ".join(config.allowed_targets) or "None (unrestricted)"
            print(f"  Allowed targets: {CYAN}{targets_str}{RESET}")
            print(f"  Excluded targets: {CYAN}{', '.join(config.excluded_targets)}{RESET}")
            input(f"\n{DIM}Press Enter to continue...{RESET}")
        elif choice == "5":
            print(f"\n{RED}[*] Shutting down SPIDER. Stay legal.{RESET}\n")
            sys.exit(0)
        else:
            warn("Invalid choice.")


# ── Entry Point ─────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="spider",
        description="SPIDER -- Symbiotic Pentesting Investigation & DSPy Exploitation Runtime",
    )
    parser.add_argument(
        "--scan",
        metavar="TARGET",
        help="Run a single scan against TARGET",
    )
    parser.add_argument(
        "--mode",
        choices=["recon", "full", "custom"],
        default="recon",
        help="Scan mode: recon (default), full, or custom",
    )
    parser.add_argument(
        "--goal",
        metavar="GOAL",
        default="",
        help="Natural language goal (required when --mode=custom)",
    )
    args = parser.parse_args()

    session_db = SessionDB()

    if args.scan:
        mode = ScanMode(args.mode)

        if mode == ScanMode.CUSTOM and not args.goal:
            print(f"{RED}[✗] --goal is required when --mode=custom{RESET}")
            sys.exit(1)

        # Single-scan mode (non-interactive)
        banner()
        print(f"  {DIM}Initializing...{RESET}")
        try:
            config, orchestrator = init_spider()
        except Exception as e:
            error(f"Failed to initialize: {e}")
            sys.exit(1)
        run_scan_noninteractive(
            session_db, orchestrator, target=args.scan, mode=mode, custom_goal=args.goal
        )
        return

    banner()
    print(f"  {DIM}Initializing...{RESET}")

    try:
        config, orchestrator = init_spider()
    except Exception as e:
        error(f"Failed to initialize: {e}")
        sys.exit(1)

    success("Ready")
    main_menu(session_db, config, orchestrator)


if __name__ == "__main__":
    main()
