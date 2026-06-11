import dspy
from spider.nodes.enum import WebEnumerationModule, ServiceEnumerationModule
from spider.nodes.vuln_analysis import VulnerabilityAnalysisModule
from spider.nodes.exploit_planner import ExploitPlanningModule
from spider.nodes.reporter import ReporterModule
from spider.config import SpiderConfig

def test_instantiation():
    config = SpiderConfig(use_refine=False)
    # Mock tools
    tools = [] 

    print("Testing WebEnumerationModule...")
    web_enum = WebEnumerationModule(tools=tools, config=config)
    assert isinstance(web_enum.analyzer, dspy.ReAct)
    
    print("Testing VulnerabilityAnalysisModule...")
    vuln_anal = VulnerabilityAnalysisModule(tools=tools, config=config)
    assert isinstance(vuln_anal.analyzer, dspy.ReAct)
    
    print("Testing ExploitPlanningModule...")
    planner = ExploitPlanningModule(tools=tools, config=config)
    assert isinstance(planner.planner, dspy.Predict)
    
    print("Testing ReporterModule...")
    reporter = ReporterModule(tools=tools, config=config)
    assert isinstance(reporter.generator, dspy.Predict)
    
    # Test with refine:
    config_refine = SpiderConfig(use_refine=True)
    print("Testing WebEnumerationModule with Refine...")
    web_enum_refine = WebEnumerationModule(tools=tools, config=config_refine)
    assert isinstance(web_enum_refine.analyzer, dspy.Refine)
    
    print("All instantiation tests passed!")

if __name__ == "__main__":
    test_instantiation()
