"""Unit tests for recon_tools -- Python-native implementations.

All network I/O is mocked.  Tests verify JSON structure, port parsing,
and graceful handling of missing libraries / connection errors.
"""

import json
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# dns_enum
# ---------------------------------------------------------------------------


class TestDnsEnum:
    def _make_resolver(self, record_map: dict):
        """Return a mock dns.resolver.Resolver whose resolve() uses record_map."""
        import dns.exception
        import dns.resolver

        mock_resolver = MagicMock()

        def fake_resolve(domain, rtype):
            if rtype in record_map:
                answers = [MagicMock() for _ in record_map[rtype]]
                for ans, text in zip(answers, record_map[rtype], strict=False):
                    ans.to_text.return_value = text
                return answers
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = fake_resolve
        return mock_resolver

    def test_returns_populated_records(self):
        from spider.tools.recon_tools import dns_enum

        record_map = {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com."],
            "TXT": ["v=spf1 include:_spf.example.com ~all"],
        }
        mock_resolver = self._make_resolver(record_map)

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            result = json.loads(dns_enum("example.com"))

        assert result["success"] is True
        assert result["domain"] == "example.com"
        assert result["records"]["A"] == ["93.184.216.34"]
        assert result["records"]["MX"] == ["10 mail.example.com."]

    def test_empty_answer_returns_empty_list(self):
        import dns.resolver

        from spider.tools.recon_tools import dns_enum

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            result = json.loads(dns_enum("nonexistent.internal"))

        assert result["success"] is True
        for records in result["records"].values():
            assert records == []

    def test_nxdomain_returns_empty_list(self):
        import dns.resolver

        from spider.tools.recon_tools import dns_enum

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            result = json.loads(dns_enum("definitely.not.real"))

        assert result["success"] is True


# ---------------------------------------------------------------------------
# subdomain_enum
# ---------------------------------------------------------------------------


class TestSubdomainEnum:
    def test_found_subdomains_appear_in_output(self):
        import dns.resolver

        from spider.tools.recon_tools import subdomain_enum

        mock_resolver = MagicMock()

        def fake_resolve(fqdn, rtype):
            if fqdn == "www.example.com" and rtype == "A":
                ans = MagicMock()
                ans.to_text.return_value = "93.184.216.34"
                return [ans]
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = fake_resolve

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            result = json.loads(subdomain_enum("example.com"))

        assert result["success"] is True
        assert result["count"] >= 1
        found_names = [s["subdomain"] for s in result["subdomains_found"]]
        assert "www.example.com" in found_names

    def test_no_subdomains_returns_empty(self):
        import dns.resolver

        from spider.tools.recon_tools import subdomain_enum

        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        with patch("dns.resolver.Resolver", return_value=mock_resolver):
            result = json.loads(subdomain_enum("empty.example.com"))

        assert result["success"] is True
        assert result["count"] == 0
        assert result["subdomains_found"] == []


# ---------------------------------------------------------------------------
# whois_lookup
# ---------------------------------------------------------------------------


class TestWhoisLookup:
    def test_successful_lookup(self):
        from spider.tools.recon_tools import whois_lookup

        mock_data = {
            "domain_name": "EXAMPLE.COM",
            "registrar": "ICANN",
            "creation_date": "1992-01-01",
            "name_servers": ["NS1.IANA.ORG", "NS2.IANA.ORG"],
        }

        with patch("whois.whois", return_value=mock_data):
            result = json.loads(whois_lookup("example.com"))

        assert result["success"] is True
        assert result["domain"] == "example.com"
        assert "EXAMPLE.COM" in result["whois"]["domain_name"]

    def test_lookup_error_returns_failure(self):
        from spider.tools.recon_tools import whois_lookup

        with patch("whois.whois", side_effect=Exception("network error")):
            result = json.loads(whois_lookup("broken.example"))

        assert result["success"] is False
        assert "network error" in result["error"]


# ---------------------------------------------------------------------------
# tcp_port_scan
# ---------------------------------------------------------------------------


class TestTcpPortScan:
    def test_open_ports_detected(self):
        from spider.tools.recon_tools import tcp_port_scan

        def fake_create_connection(addr, timeout):
            host, port = addr
            if port in (22, 80):
                return MagicMock().__enter__.return_value  # context manager succeeds
            raise ConnectionRefusedError()

        with patch("socket.create_connection") as mock_conn:
            mock_conn.side_effect = fake_create_connection
            # Patch to make context manager work
            mock_conn.return_value.__enter__ = MagicMock(return_value=None)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            result = json.loads(tcp_port_scan("127.0.0.1", ports="22,80,443", timeout=0.1))

        assert result["success"] is True
        assert result["target"] == "127.0.0.1"
        assert result["scanned"] == 3

    def test_port_range_parsing(self):
        from spider.tools.recon_tools import tcp_port_scan

        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = json.loads(tcp_port_scan("127.0.0.1", ports="80-83", timeout=0.1))

        assert result["scanned"] == 4  # 80, 81, 82, 83

    def test_mixed_port_spec(self):
        from spider.tools.recon_tools import tcp_port_scan

        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = json.loads(tcp_port_scan("127.0.0.1", ports="22,80-82,443", timeout=0.1))

        assert result["scanned"] == 5  # 22, 80, 81, 82, 443

    def test_all_closed_returns_empty_open(self):
        from spider.tools.recon_tools import tcp_port_scan

        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = json.loads(tcp_port_scan("127.0.0.1", ports="9999", timeout=0.1))

        assert result["open"] == []
        assert 9999 in result["closed"]

    def test_os_error_treated_as_closed(self):
        from spider.tools.recon_tools import tcp_port_scan

        with patch("socket.create_connection", side_effect=OSError("timeout")):
            result = json.loads(tcp_port_scan("127.0.0.1", ports="22", timeout=0.1))

        assert result["success"] is True
        assert result["open"] == []

    def test_note_field_present(self):
        from spider.tools.recon_tools import tcp_port_scan

        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = json.loads(tcp_port_scan("127.0.0.1", ports="80", timeout=0.1))

        assert "note" in result
