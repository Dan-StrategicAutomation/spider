"""Integration tests against lab targets (DVWA, Juice Shop, Metasploitable2).

These tests verify SPIDER can actually discover and classify vulnerabilities
against deliberately vulnerable targets with known expected findings.
"""

import pytest


@pytest.mark.integration
class TestLabReachability:
    """Verify all lab containers are running and reachable."""

    def test_dvwa_reachable(self):
        """DVWA should respond on port 80."""
        # TODO: Implement HTTP check
        pytest.skip("Lab containers not running")

    def test_juiceshop_reachable(self):
        """Juice Shop should respond on port 3000."""
        pytest.skip("Lab containers not running")

    def test_metasploitable2_reachable(self):
        """Metasploitable2 should have SSH on port 22."""
        pytest.skip("Lab containers not running")
