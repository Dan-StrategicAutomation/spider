"""Tests for DSPy-native node reward functions."""

import dspy

from spider.engine.self_eval import VulnAnalysisReward, WebEnumerationReward
from spider.schemas import (
    CVEFinding,
    DirectoryEntry,
    ReconResults,
    RewardEvaluation,
    ServiceDetails,
    TechInfo,
    VulnerabilityInfo,
    VulnerabilityList,
    VulnerabilityRewardContext,
    WebEnumerationRewardContext,
    WebFindings,
    WebParamInfo,
)


class RecordingJudge(dspy.Module):
    """Mock DSPy judge returning a fixed structured reward evaluation."""

    def __init__(self, evaluation: RewardEvaluation):
        super().__init__()
        self.evaluation = evaluation
        self.context = None

    def forward(self, context):
        self.context = context
        return dspy.Prediction(evaluation=self.evaluation)


def test_vulnerability_reward_accepts_empty_result_when_tools_support_no_findings():
    """An empty VulnerabilityList can pass when DSPy judge validates no-finding evidence."""
    judge = RecordingJudge(
        RewardEvaluation(
            score=0.86,
            evidence_present=True,
            no_findings_supported=True,
            unsupported_cves_absent=True,
            rationale="Scanner and CVE intelligence output support no findings.",
        )
    )
    service_details = ServiceDetails(
        service_name="nginx",
        version="1.24.0",
        raw_output="nmap service detection found nginx 1.24.0; no known vulnerabilities found",
    )
    web_findings = WebFindings(raw_output="nikto completed: no vulnerabilities discovered")
    pred = dspy.Prediction(
        vulnerabilities=VulnerabilityList(
            vulnerabilities=[],
            raw_output="CVE intelligence lookup: no matching CVEs and no public exploits",
        )
    )

    score = VulnAnalysisReward(judge=judge)(
        {"web_findings": web_findings, "service_details": service_details}, pred
    )

    assert score == 0.86
    assert isinstance(judge.context, VulnerabilityRewardContext)
    assert judge.context.vulnerabilities.vulnerabilities == []
    assert judge.context.service_details.service_name == "nginx"


def test_vulnerability_reward_accepts_grounded_non_empty_result():
    """A non-empty finding can pass when DSPy judge validates grounding and consistency."""
    judge = RecordingJudge(
        RewardEvaluation(
            score=0.94,
            evidence_present=True,
            cve_or_source_references_present=True,
            service_details_consistent=True,
            unsupported_cves_absent=True,
            rationale="CVE and NVD source match Apache 2.4.49 service evidence.",
        )
    )
    service_details = ServiceDetails(
        service_name="apache",
        version="2.4.49",
        raw_output="Apache httpd 2.4.49 detected. CVE-2021-41773 path traversal applies.",
    )
    web_findings = WebFindings(raw_output="GET /cgi-bin returned Apache 2.4.49 evidence")
    finding = VulnerabilityInfo(
        cve=CVEFinding(
            cve_id="CVE-2021-41773",
            cvss_score=7.5,
            severity="HIGH",
            has_public_exploit=True,
            summary="Apache httpd 2.4.49 path traversal applies",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        ),
        affected_service="apache",
        affected_version="2.4.49",
        remediation_hint="Upgrade Apache httpd to a fixed version.",
    )
    pred = dspy.Prediction(
        vulnerabilities=VulnerabilityList(
            vulnerabilities=[finding],
            total_high=1,
            raw_output="NVD returned CVE-2021-41773 for Apache httpd 2.4.49.",
        )
    )

    score = VulnAnalysisReward(judge=judge)(
        {"web_findings": web_findings, "service_details": service_details}, pred
    )

    assert score == 0.94
    assert isinstance(judge.context, VulnerabilityRewardContext)
    assert judge.context.vulnerabilities.vulnerabilities[0].cve.cve_id == "CVE-2021-41773"
    assert judge.context.service_details.version == "2.4.49"


def test_vulnerability_reward_uses_judge_to_penalize_unsupported_cve():
    """Unsupported CVEs should not pass purely because the list is non-empty."""
    judge = RecordingJudge(
        RewardEvaluation(
            score=0.18,
            evidence_present=True,
            cve_or_source_references_present=False,
            service_details_consistent=False,
            unsupported_cves_absent=False,
            rationale="The reported CVE is not supported by tool evidence.",
        )
    )
    service_details = ServiceDetails(
        service_name="nginx",
        version="1.24.0",
        raw_output="nginx 1.24.0 detected; no known vulnerabilities found",
    )
    finding = VulnerabilityInfo(
        cve=CVEFinding(
            cve_id="CVE-2099-99999",
            cvss_score=9.8,
            severity="CRITICAL",
            references=["https://example.invalid/untrusted"],
        ),
        affected_service="tomcat",
        affected_version="9.0",
    )
    pred = dspy.Prediction(vulnerabilities=VulnerabilityList(vulnerabilities=[finding]))

    score = VulnAnalysisReward(judge=judge)(
        {"web_findings": WebFindings(), "service_details": service_details}, pred
    )

    assert score == 0.18
    assert isinstance(judge.context, VulnerabilityRewardContext)


def test_web_enumeration_reward_accepts_empty_result_when_evidence_supports_absence():
    """Empty web findings can pass when DSPy judge validates absence of web findings."""
    judge = RecordingJudge(
        RewardEvaluation(
            score=0.82,
            evidence_present=True,
            no_findings_supported=True,
            rationale="Recon found no web service and HTTP probe found no web content.",
        )
    )
    recon_results = ReconResults(raw_output="tcp/22 OpenSSH only; no web service detected")
    pred = dspy.Prediction(
        web_findings=WebFindings(raw_output="http probe completed: no web content found")
    )

    score = WebEnumerationReward(judge=judge)({"recon_results": recon_results}, pred)

    assert score == 0.82
    assert isinstance(judge.context, WebEnumerationRewardContext)
    assert judge.context.web_findings.directories == []


def test_web_enumeration_reward_accepts_grounded_non_empty_result():
    """Structured web findings can pass when DSPy judge validates field grounding."""
    judge = RecordingJudge(
        RewardEvaluation(
            score=0.91,
            evidence_present=True,
            cve_or_source_references_present=True,
            rationale="Directory, parameter, technology, and vulnerability notes are grounded.",
        )
    )
    recon_results = ReconResults(raw_output="port 80 http open")
    pred = dspy.Prediction(
        web_findings=WebFindings(
            directories=[DirectoryEntry(path="/admin", status_code=200)],
            params=[WebParamInfo(url="http://example.test/item?id=1", param_name="id")],
            technologies=[TechInfo(name="PHP", version="8.2", category="language")],
            potential_vulns=["SQL injection"],
            raw_output=(
                "ffuf found /admin status 200. PHP 8.2 detected. "
                "Parameter id appears in URL and SQL injection was flagged."
            ),
        )
    )

    score = WebEnumerationReward(judge=judge)({"recon_results": recon_results}, pred)

    assert score == 0.91
    assert isinstance(judge.context, WebEnumerationRewardContext)
    assert judge.context.web_findings.directories[0].path == "/admin"
