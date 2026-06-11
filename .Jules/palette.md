## 2026-06-11 - Preserve scan interface while improving terminal rendering

**Learning:** SPIDER operators rely on the `spider --scan TARGET --mode ...` non-interactive interface, while the project already depends on Rich for terminal UI components.

**Action:** Preserve existing flags and exit behavior while using Rich for human-facing help or summaries instead of adding new CLI presentation dependencies.
