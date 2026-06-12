"""Tests for orchestrator topology selection behavior."""

from typing import Any

import dspy
import pytest

from spider.config import SpiderConfig
from spider.engine.orchestrator import SpiderOrchestrator
from spider.engine.weaver import build_default_topology, validate_topology_contract
from spider.schemas import GraphTopology, ScanMode


@pytest.fixture
def config() -> SpiderConfig:
    """Minimal config that avoids refinement during orchestrator tests."""
    return SpiderConfig(
        ollama_base_url="http://localhost:11434",
        primary_model="test-model",
        eval_model="test-model",
        use_refine=False,
    )


class _FakeRunner:
    """GraphRunner stand-in that records the topology and avoids DSPy calls."""

    instances: list["_FakeRunner"] = []

    def __init__(self, topology: GraphTopology, **kwargs: Any) -> None:
        self.topology = topology
        self.kwargs = kwargs
        _FakeRunner.instances.append(self)

    def __call__(self, **kwargs: Any) -> dspy.Prediction:
        return dspy.Prediction(
            results={"node_ids": [node.id for node in self.topology.nodes]},
            completed=True,
        )


class _ForbiddenWeaver:
    """Weaver stand-in that fails if standard modes try to use it."""

    def __call__(self, **kwargs: Any) -> dspy.Prediction:
        raise AssertionError("standard scan modes must not call the DSPy weaver")


class _RecordingWeaver:
    """Weaver stand-in for custom mode assertions."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> dspy.Prediction:
        self.calls.append(kwargs)
        topology = build_default_topology(ScanMode.FULL)
        assert topology is not None
        return dspy.Prediction(topology=topology)


def _prepare_orchestrator(
    monkeypatch: pytest.MonkeyPatch,
    config: SpiderConfig,
) -> SpiderOrchestrator:
    """Create an orchestrator with tool building and graph execution stubbed."""
    import spider.engine.orchestrator as orchestrator_module

    _FakeRunner.instances = []
    monkeypatch.setattr(orchestrator_module, "GraphRunner", _FakeRunner)

    orchestrator = SpiderOrchestrator(config=config)
    monkeypatch.setattr(orchestrator, "_build_tools", lambda **_kwargs: {})
    monkeypatch.setattr(orchestrator, "_build_node_modules", lambda *_args, **_kwargs: {})
    return orchestrator


@pytest.mark.parametrize("mode", [ScanMode.RECON, ScanMode.FULL])
def test_standard_modes_do_not_call_weaver(
    monkeypatch: pytest.MonkeyPatch,
    config: SpiderConfig,
    mode: ScanMode,
) -> None:
    """RECON and FULL use deterministic topology instead of LLM weaving."""
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    orchestrator.weaver = _ForbiddenWeaver()

    result = orchestrator.run(goal="Assess authorized lab target", target="example.com", mode=mode)

    assert result["mode"] == mode.value
    assert len(_FakeRunner.instances) == 1
    selected = _FakeRunner.instances[0].topology
    assert selected.metadata["scan_mode"] == mode.value
    assert validate_topology_contract(selected, mode) == []


def test_custom_mode_calls_weaver(
    monkeypatch: pytest.MonkeyPatch,
    config: SpiderConfig,
) -> None:
    """CUSTOM mode still delegates topology generation to the DSPy weaver."""
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    weaver = _RecordingWeaver()
    orchestrator.weaver = weaver

    result = orchestrator.run(
        goal="Build a custom authorized assessment plan",
        target="example.com",
        mode=ScanMode.CUSTOM,
    )

    assert result["mode"] == ScanMode.CUSTOM.value
    assert len(weaver.calls) == 1
    assert weaver.calls[0]["goal"].objective == "Build a custom authorized assessment plan"
    assert len(_FakeRunner.instances) == 1


def test_recon_run_filters_selected_topology(
    monkeypatch: pytest.MonkeyPatch,
    config: SpiderConfig,
) -> None:
    """Selected topologies are still filtered by scan mode before validation/execution."""
    orchestrator = _prepare_orchestrator(monkeypatch, config)

    def select_full_topology_for_recon(**_kwargs: Any) -> GraphTopology:
        topology = build_default_topology(ScanMode.FULL)
        assert topology is not None
        assert any(node.id == "exploit_planner" for node in topology.nodes)
        return topology

    monkeypatch.setattr(orchestrator, "_select_topology", select_full_topology_for_recon)

    orchestrator.run(goal="Assess authorized lab target", target="example.com", mode=ScanMode.RECON)

    assert len(_FakeRunner.instances) == 1
    selected_node_ids = {node.id for node in _FakeRunner.instances[0].topology.nodes}
    assert "exploit_planner" not in selected_node_ids
    assert "reporter" in selected_node_ids


def test_configured_prebuilt_topology_overrides_scan_mode(
    monkeypatch: pytest.MonkeyPatch,
    config: SpiderConfig,
) -> None:
    """Users can explicitly select a prebuilt topology instead of auto mode defaults."""
    config.topology_name = "full"
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    orchestrator.weaver = _ForbiddenWeaver()

    result = orchestrator.run(
        goal="Assess authorized lab target", target="example.com", mode=ScanMode.FULL
    )

    assert result["mode"] == ScanMode.FULL.value
    selected_node_ids = {node.id for node in _FakeRunner.instances[0].topology.nodes}
    assert "exploit_execution" in selected_node_ids
    assert "post_exploitation" in selected_node_ids


def test_saved_topology_selection_loads_from_configured_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    config: SpiderConfig,
) -> None:
    """Users can reuse a saved topology JSON by name without invoking the weaver."""
    saved_topology = build_default_topology(ScanMode.RECON)
    assert saved_topology is not None
    saved_topology.name = "saved_recon"
    (tmp_path / "saved_recon.json").write_text(saved_topology.model_dump_json())

    config.topology_name = "saved_recon"
    config.topology_dir = str(tmp_path)
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    orchestrator.weaver = _ForbiddenWeaver()

    result = orchestrator.run(
        goal="Assess authorized lab target", target="example.com", mode=ScanMode.RECON
    )

    assert result["mode"] == ScanMode.RECON.value
    selected = _FakeRunner.instances[0].topology
    assert selected.name == "saved_recon"
    assert validate_topology_contract(selected, ScanMode.RECON) == []


def test_topology_name_kwarg_overrides_configured_topology(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    config: SpiderConfig,
) -> None:
    """Callers can select a saved topology for one run without mutating config."""
    saved_topology = build_default_topology(ScanMode.RECON)
    assert saved_topology is not None
    saved_topology.name = "one_off_recon"
    topology_path = tmp_path / "one_off_recon.json"
    topology_path.write_text(saved_topology.model_dump_json())

    config.topology_name = "weave"
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    orchestrator.weaver = _ForbiddenWeaver()

    result = orchestrator.run(
        goal="Assess authorized lab target",
        target="example.com",
        mode=ScanMode.RECON,
        topology_name=str(topology_path),
    )

    assert result["mode"] == ScanMode.RECON.value
    assert _FakeRunner.instances[0].topology.name == "one_off_recon"


def test_unknown_saved_topology_returns_selection_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    config: SpiderConfig,
) -> None:
    """Unknown topology names fail clearly before graph execution."""
    config.topology_name = "missing_topology"
    config.topology_dir = str(tmp_path)
    orchestrator = _prepare_orchestrator(monkeypatch, config)
    orchestrator.weaver = _ForbiddenWeaver()

    result = orchestrator.run(
        goal="Assess authorized lab target", target="example.com", mode=ScanMode.RECON
    )

    assert result["success"] is False
    assert str(result["error"]).startswith("TOPOLOGY_SELECTION_ERROR:")
    assert _FakeRunner.instances == []
