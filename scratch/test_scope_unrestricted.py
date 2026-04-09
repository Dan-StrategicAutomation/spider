import ipaddress
import fnmatch
from spider.sandbox.scope_guard import ScopeGuard

# Unrestricted config (no allowed targets)
allowed = []
excluded = ["127.0.0.1", "localhost"]
lab = "172.20.0.0/24"

guard = ScopeGuard(allowed, excluded, lab)

def test(target):
    auth, reason = guard.authorize(target, "test")
    print(f"Target: {target} -> Auth: {auth}, Reason: {reason}")

print("Testing Unrestricted Scope (allowed=[]):")
test("1.2.3.4")       # Should be True (unrestricted)
test("127.0.0.1")     # Should be False (excluded)
test("localhost")     # Should be False (excluded)
test("172.20.0.5")    # Should be True (lab)

print("\nTesting Restricted Scope (allowed=['1.2.3.0/24']):")
guard_restricted = ScopeGuard(["1.2.3.0/24"], excluded, lab)
def test_res(target):
    auth, reason = guard_restricted.authorize(target, "test")
    print(f"Target: {target} -> Auth: {auth}, Reason: {reason}")

test_res("1.2.3.4")   # Should be True
test_res("8.8.8.8")   # Should be False
