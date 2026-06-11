"""ScopeGuard -- hard enforcement of target scope.

Never attacks out of scope. Checked at the tool adapter level before every invocation.
"""

import fnmatch
import ipaddress


class ScopeGuard:
    """Validates all tool invocations against allowed and excluded targets."""

    def __init__(
        self,
        allowed: list[str],
        excluded: list[str],
        lab_network: str | None = None,
    ):
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network | str] = []
        self._excluded: set[str] = set(excluded)
        self._lab_network: ipaddress.IPv4Network | None = None
        self._temp_authorized: set[str] = set()  # Interactive authorization for CLI

        for cidr in allowed:
            try:
                self._allowed_networks.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                # Treat as hostname -- allowed literally
                self._allowed_networks.append(cidr)  # type: ignore[arg-type]

        if lab_network:
            import contextlib

            with contextlib.suppress(ValueError):
                self._lab_network = ipaddress.IPv4Network(lab_network, strict=False)

    def authorize(self, target: str, action: str) -> tuple[bool, str]:
        """Check if target is authorized for the given action.

        Returns (authorized, reason).
        """
        # Check temporary authorizations first
        if target in self._temp_authorized:
            return True, "Temporarily authorized"

        # 1. Check excluded list
        if any(fnmatch.fnmatch(target, exc) for exc in self._excluded):
            return False, f"Target {target!r} is in the excluded list"

        # 2. Lab network always passes (for testing)
        if self._lab_network:
            try:
                if ipaddress.IPv4Address(target) in self._lab_network:
                    return True, "Lab network target"
            except ValueError:
                pass

        # 3. If allowed list is empty, reject all targets (fail-safe)
        if not self._allowed_networks:
            return False, "No allowed targets specified - access denied"

        # 4. Check allowed networks
        for allowed in self._allowed_networks:
            if isinstance(allowed, str):
                if fnmatch.fnmatch(target, allowed):
                    return True, f"Matching allowed pattern {allowed!r}"
            else:
                try:
                    # Try as IP address first
                    target_ip = ipaddress.IPv4Address(target)
                    if target_ip in allowed:
                        return True, f"Within allowed network {allowed!r}"
                except ValueError:
                    # Target is a hostname (like 'localhost' or 'target.com')
                    # If the 'allowed' entry was also a hostname (handled in __init__),
                    # literal match or fnmatch already covered it above.
                    pass

        return False, f"Target {target!r} is not within any allowed scope"

    def add_temp_authorization(self, target: str) -> None:
        """Add a target to temporary authorization (for interactive CLI use)."""
        self._temp_authorized.add(target)

    def is_lab_target(self, target: str) -> bool:
        """Check if target is in the safe test lab network."""
        if self._lab_network:
            try:
                return ipaddress.IPv4Address(target) in self._lab_network
            except ValueError:
                pass
        return False
