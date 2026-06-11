from spider.schemas import WebFindings

def test_truncation():
    large_str = "A" * 20000
    findings = WebFindings(raw_output=large_str)
    print(f"Length before: {len(large_str)}")
    print(f"Length after: {len(findings.raw_output)}")
    print(f"Content: {findings.raw_output[-50:]}")
    assert len(findings.raw_output) <= 10020
    assert findings.raw_output.endswith("[TRUNCATED]")
    print("Truncation test passed!")

if __name__ == "__main__":
    test_truncation()
