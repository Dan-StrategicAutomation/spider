"""Tests for DSPy module selection when no tools are available."""

import dspy

from spider.config import SpiderConfig
from spider.nodes.enum import ServiceEnumerationModule, WebEnumerationModule
from spider.nodes.vuln_analysis import VulnerabilityAnalysisModule


def _config() -> SpiderConfig:
    return SpiderConfig(_env_file=None, use_refine=False)


def test_web_enumeration_uses_predict_without_tools():
    """No-tool web enumeration should not create a ReAct tool loop."""
    module = WebEnumerationModule(tools=[], config=_config())

    assert isinstance(module.analyzer, dspy.Predict)


def test_service_enumeration_uses_predict_without_tools():
    """No-tool service enumeration should not create a ReAct tool loop."""
    module = ServiceEnumerationModule(tools=[], config=_config())

    assert isinstance(module.analyzer, dspy.Predict)


def test_vulnerability_analysis_uses_predict_without_tools():
    """No-tool vulnerability analysis should not expose only the finish tool."""
    module = VulnerabilityAnalysisModule(tools=[], config=_config())

    assert isinstance(module.analyzer, dspy.Predict)
