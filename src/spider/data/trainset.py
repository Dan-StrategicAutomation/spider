"""Training datasets for SPIDER nodes.
Contains 'Gold' examples used for DSPy BootstrapFewShot optimization.
"""

import dspy

from spider.schemas import PortInfo, ReconResults, ServiceInfo, VulnerabilityInfo, VulnerabilityList

# --- ReconModule Examples ---
RECON_TRAINSET = [
    dspy.Example(
        target="127.0.0.1",
        recon_results=ReconResults(
            hosts=["127.0.0.1"],
            ports=[PortInfo(port=80, protocol="tcp", state="open")],
            services=[ServiceInfo(port=80, name="http", product="nginx", version="1.18.0")],
            raw_output="Nmap scan report for 127.0.0.1\nPORT   STATE SERVICE\n80/tcp open  http",
        ),
    ).with_inputs("target"),
    dspy.Example(
        target="example.com",
        recon_results=ReconResults(
            hosts=["93.184.216.34"],
            ports=[
                PortInfo(port=80, protocol="tcp", state="open"),
                PortInfo(port=443, protocol="tcp", state="open"),
            ],
            services=[
                ServiceInfo(port=80, name="http", product="Apache", version="2.4.41"),
                ServiceInfo(port=443, name="https", product="Apache", version="2.4.41"),
            ],
            raw_output="Scanning example.com...\n80/tcp open http\n443/tcp open https",
        ),
    ).with_inputs("target"),
]

# --- ExploitPlanningModule Examples ---
PLANNING_TRAINSET = [
    dspy.Example(
        vulnerabilities=VulnerabilityList(
            vulnerabilities=[
                VulnerabilityInfo(
                    cve_id="CVE-2021-41773",
                    severity="CRITICAL",
                    description="Path traversal in Apache 2.4.49",
                    exploit_available=True,
                )
            ]
        ),
        attack_plan=(
            "Attempt path traversal on Apache 2.4.49 using CVE-2021-41773. "
            "Target /cgi-bin/.%%32%65/."
        ),
    ).with_inputs("vulnerabilities"),
]

# More datasets can be added here as we expand optimization coverage.
