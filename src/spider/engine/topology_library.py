"""Named topology selection for prebuilt and user-saved graph topologies."""

import json
from pathlib import Path

from spider.schemas import GraphTopology, ScanMode

_AUTO_TOPOLOGY = "auto"
_WEAVE_TOPOLOGY = "weave"
_PREBUILT_TOPOLOGIES = frozenset({ScanMode.RECON.value, ScanMode.FULL.value})


class TopologySelectionError(ValueError):
    """Raised when a requested topology name cannot be resolved."""


def normalize_topology_name(topology_name: str | None) -> str:
    """Return the canonical topology selector name."""
    if topology_name is None:
        return _AUTO_TOPOLOGY
    normalized = topology_name.strip().lower()
    return normalized or _AUTO_TOPOLOGY


def is_weaver_topology(topology_name: str | None) -> bool:
    """Return True when the user explicitly requested DSPy topology weaving."""
    return normalize_topology_name(topology_name) in {_WEAVE_TOPOLOGY, ScanMode.CUSTOM.value}


def selected_prebuilt_mode(topology_name: str | None) -> ScanMode | None:
    """Return the prebuilt scan mode requested by topology name, if any."""
    normalized = normalize_topology_name(topology_name)
    if normalized not in _PREBUILT_TOPOLOGIES:
        return None
    return ScanMode(normalized)


def load_saved_topology(topology_name: str, topology_dir: str) -> GraphTopology:
    """Load a user-saved topology from an explicit JSON path or configured topology directory."""
    for candidate in _candidate_topology_paths(topology_name, topology_dir):
        if candidate.is_file():
            try:
                return GraphTopology(**json.loads(candidate.read_text()))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise TopologySelectionError(
                    f"Topology '{topology_name}' exists at '{candidate}' but is invalid: {exc}"
                ) from exc

    searched = ", ".join(
        str(path) for path in _candidate_topology_paths(topology_name, topology_dir)
    )
    raise TopologySelectionError(
        f"Unknown topology '{topology_name}'. Use 'auto', 'recon', 'full', 'weave', "
        f"or place a saved topology JSON at one of: {searched}."
    )


def list_saved_topologies(topology_dir: str) -> list[str]:
    """List saved topology names in the configured topology directory."""
    directory = Path(topology_dir).expanduser()
    if not directory.is_dir():
        return []
    return sorted(path.stem for path in directory.glob("*.json") if path.is_file())


def topology_selector_help(topology_dir: str) -> str:
    """Return a compact user-facing description of selectable topology names."""
    saved = list_saved_topologies(topology_dir)
    saved_text = f" Saved: {', '.join(saved)}." if saved else ""
    return f"Built-in: auto, recon, full, weave.{saved_text}"


def _candidate_topology_paths(topology_name: str, topology_dir: str) -> list[Path]:
    """Return ordered candidate JSON paths for a saved topology selector."""
    raw = Path(topology_name).expanduser()
    candidates: list[Path] = []
    if raw.suffix == ".json" or raw.is_absolute() or raw.parent != Path("."):
        candidates.append(raw)

    directory = Path(topology_dir).expanduser()
    filename = topology_name if topology_name.endswith(".json") else f"{topology_name}.json"
    candidates.append(directory / filename)
    return candidates
