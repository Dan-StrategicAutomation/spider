"""Tests for GraphRunner input sourcing and wave failures."""

import dspy

from spider.engine.runner import GraphRunner
from spider.schemas import GraphTopology, NodeDef, NodeRole, ReconResults, TargetSpec, WebFindings


class RequiresReconSignature(dspy.Signature):
    """Test signature that requires structured upstream recon data."""

    recon_results: ReconResults = dspy.InputField()
    web_findings: WebFindings = dspy.OutputField()


class RecordingModule(dspy.Module):
    """Test module that records whether the runner executed it."""

    def __init__(self):
        super().__init__()
        self.signature = RequiresReconSignature
        self.called = False

    def forward(self, recon_results: ReconResults) -> dspy.Prediction:
        self.called = True
        return dspy.Prediction(web_findings=WebFindings(raw_output=recon_results.raw_output))


def test_runner_fails_wave_when_declared_upstream_output_is_missing():
    """Missing upstream outputs must fail the wave instead of using an empty model."""
    node = NodeDef(
        id="web_enum",
        role=NodeRole.CHAIN_OF_THOUGHT,
        name="Web Enumeration",
        description="Enumerate web findings from recon data.",
        inputs=["recon_results"],
        output="web_findings",
        depends_on=[],
    )
    topology = GraphTopology(
        name="missing_upstream_output",
        objective="exercise missing runner input handling",
        nodes=[node],
        edges=[],
        runtime_inputs=["target"],
    )
    module = RecordingModule()
    runner = GraphRunner(
        topology=topology,
        node_modules={"web_enum": module},
        target="example.test",
        recon_results=ReconResults(raw_output="undeclared runtime value must not be used"),
    )

    result = runner()

    assert result.error.startswith("Wave failed: web_enum:")
    assert "Node 'web_enum' missing required signature input 'recon_results'" in result.error
    assert "Declared topology inputs for node 'web_enum': ['recon_results']" in result.error
    assert "Declared runtime inputs: ['target']" in result.error
    assert not module.called


class RequiresTargetSpecSignature(dspy.Signature):
    """Test signature that requires a structured target descriptor."""

    target_spec: TargetSpec = dspy.InputField()
    recon_results: ReconResults = dspy.OutputField()


class TargetRecordingModule(dspy.Module):
    """Test module that records the normalized runtime target."""

    def __init__(self):
        super().__init__()
        self.signature = RequiresTargetSpecSignature
        self.received_target: TargetSpec | None = None

    def forward(self, target_spec: TargetSpec) -> dspy.Prediction:
        self.received_target = target_spec
        return dspy.Prediction(recon_results=ReconResults(hosts=[target_spec.target]))


def test_runner_normalizes_legacy_target_runtime_input_to_target_spec():
    """Legacy runtime target strings should be supplied to modules as TargetSpec."""
    node = NodeDef(
        id="recon",
        role=NodeRole.REACT,
        name="Recon",
        description="Run recon from a structured target spec.",
        inputs=["target"],
        output="recon_results",
        depends_on=[],
    )
    topology = GraphTopology(
        name="target_spec_runtime",
        objective="exercise target normalization",
        nodes=[node],
        edges=[],
        runtime_inputs=["target"],
    )
    module = TargetRecordingModule()
    runner = GraphRunner(
        topology=topology,
        node_modules={"recon": module},
        target="example.test",
    )

    result = runner()

    assert result.completed is True
    assert module.received_target == TargetSpec.from_raw("example.test")
    assert result.results["recon_results"].hosts == ["example.test"]
