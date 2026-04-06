"""ScopeGuard -- hard enforcement of target scope.

Never attacks out of scope. Checked at the tool adapter level before every invocation.
"""

import ipaddress
import fnmatch


class ScopeGuard:
    """Validates all tool invocations against allowed and excluded targets."""

    def __init__(
        self,
        allowed: list[str],
        excluded: list[str],
        lab_network: str | None = None,
    ):
        self._allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._excluded: set[str] = set(excluded)
        self._lab_network: ipaddress.IPv4Network | None = None

        for cidr in allowed:
            try:
                self._allowed_networks.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError:
                # Treat as hostname -- allowed literally
                self._allowed_networks.append(cidr)  # type: ignore[arg-type]

        if lab_network:
            try:
                self._lab_network = ipaddress.IPv4Network(lab_network, strict=False)
            except ValueError:
                pass

    def authorize(self, target: str, action: str) -> tuple[bool, str]:
        """Check if target is authorized for the given action.

        Returns (authorized, reason).
        """
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

        # 3. Check allowed networks
        for allowed in self._allowed_networks:
            if isinstance(allowed, str):
                if fnmatch.fnmatch(target, allowed):
                    return True, f"Matching allowed pattern {allowed!r}"
            else:
                try:
                    if ipaddress.IPv4Address(target) in allowed:
                        return True, f"Within allowed network {allowed!r}"
                except ValueError:
                    # Hostname -- check domain match
                    if fnmatch.fnmatch(target, str(allowed)):
                        return True, f"Matching allowed hostname {allowed!r}"

        return False, f"Target {target!r} is not within any allowed scope"

    def is_lab_target(self, target: str) -> bool:
        """Check if target is in the safe test lab network."""
        if self._lab_network:
            try:
                return ipaddress.IPv4Address(target) in self._lab_network
            except ValueError:
                pass
        return False
