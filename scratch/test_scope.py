import ipaddress
import fnmatch
from spider.sandbox.scope_guard import ScopeGuard

# Mock config
allowed = ["192.168.1.0/24", "target.com"]
excluded = ["192.168.1.1"]
lab = "172.20.0.0/24"

guard = ScopeGuard(allowed, excluded, lab)

def test(target):
    auth, reason = guard.authorize(target, "test")
    print(f"Target: {target} -> Auth: {auth}, Reason: {reason}")

test("192.168.1.10")  # Should be True
test("192.168.1.1")   # Should be False (excluded)
test("192.168.2.1")   # Should be False (not allowed)
test("target.com")    # Should be True
test("sub.target.com") # Should be False (currently literal match in ScopeGuard)
test("172.20.0.5")    # Should be True (lab)
test("127.0.0.1")     # Should be False
