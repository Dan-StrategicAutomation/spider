"""Scope guard tests -- MUST PASS before any pentesting is allowed."""

from spider.sandbox.scope_guard import ScopeGuard


class TestScopeGuard:
    """Test scope validation for authorized targets."""

    def setup_method(self):
        self.guard = ScopeGuard(
            allowed=["192.168.1.0/24", "10.0.0.0/8"],
            excluded=["0.0.0.0", "127.0.0.1", "localhost"],
            lab_network="172.20.0.0/24",
        )

    def test_allowed_target(self):
        authorized, reason = self.guard.authorize("192.168.1.100", "nmap_scan")
        assert authorized is True
        assert "Within allowed network" in reason

    def test_excluded_target(self):
        authorized, reason = self.guard.authorize("127.0.0.1", "nmap_scan")
        assert authorized is False
        assert "excluded" in reason.lower()

    def test_out_of_scope_target(self):
        authorized, reason = self.guard.authorize("8.8.8.8", "nmap_scan")
        assert authorized is False
        assert "not within" in reason.lower()

    def test_lab_network_allowed(self):
        authorized, reason = self.guard.authorize("172.20.0.10", "nmap_scan")
        assert authorized is True
        assert "Lab network" in reason

    def test_is_lab_target(self):
        assert self.guard.is_lab_target("172.20.0.10") is True
        assert self.guard.is_lab_target("192.168.1.100") is False
        assert self.guard.is_lab_target("8.8.8.8") is False

    def test_wildcard_pattern(self):
        guard = ScopeGuard(allowed=["*.example.com"], excluded=["127.0.0.1"])
        authorized, _ = guard.authorize("www.example.com", "dns_enum")
        assert authorized is True

    def test_empty_scope_rejects_all(self):
        guard = ScopeGuard(allowed=[], excluded=[])
        authorized, _ = guard.authorize("192.168.1.1", "nmap_scan")
        assert authorized is False  # No allowed targets = nothing passes
