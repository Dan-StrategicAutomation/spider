"""Vulnerability analysis node -- CVE matching and exploit availability.

Cross-references discovered services with NVD, CISA KEV, EPSS, and
Exploit-DB to identify known vulnerabilities.
"""

import dspy

from spider.schemas import VulnerabilityList


class VulnAnalysisSignature(dspy.Signature):
    """Analyze discovered services and web findings for known vulnerabilities.
    Match to CVEs, check exploit availability, prioritize by CVSS and EPSS.
    Include service versions and web application details in analysis."""
    web_findings: str = dspy.InputField()
    service_details: str = dspy.InputField()
    vulnerabilities: VulnerabilityList = dspy.OutputField()


class VulnerabilityAnalysisModule(dspy.Module):
    """Vulnerability analysis module with dspy.Refine."""
    def __init__(self, tools: list[dspy.Tool]):
        super().__init__()
        analyzer = dspy.ChainOfThought(VulnAnalysisSignature)

        def vuln_reward(args: dict, pred: dspy.Prediction) -> float:
            vulns = pred.vulnerabilities
            if not vulns.vulnerabilities:
                return 0.3  # Absence of vulns isn't necessarily bad
            vulns_list = vulns.vulnerabilities
            score = min(0.6, len(vulns_list) * 0.1)
            if any(v.cve.cvss_score > 7.0 for v in vulns_list):
                score += 0.2
            if any(v.cve.has_public_exploit for v in vulns_list):
                score += 0.1
            if any(v.cve.in_kev for v in vulns_list):
                score += 0.1
            return min(1.0, score)

        self.analyzer = dspy.Refine(
            module=analyzer,
            N=3,
            reward_fn=vuln_reward,
            threshold=0.7,
        )

    def forward(self, web_findings: str, service_details: str) -> dspy.Prediction:
        with dspy.settings.context(temperature=0.1):
            return self.analyzer(
                web_findings=web_findings,
                service_details=service_details,
            )
