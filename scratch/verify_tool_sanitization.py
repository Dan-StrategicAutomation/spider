from spider.tools.adapter import _sanitize_args

def test_sanitization():
    # Case 1: Simple nested hallucination
    input1 = {"target": {"target": "127.0.0.1"}}
    output1 = _sanitize_args(input1)
    print(f"Case 1: {input1} -> {output1}")
    assert output1["target"] == "127.0.0.1"

    # Case 2: Hallucination with extra fields
    input2 = {"target": {"target": "127.0.0.1", "kwargs": {}}}
    output2 = _sanitize_args(input2)
    print(f"Case 2: {input2} -> {output2}")
    assert output2["target"] == "127.0.0.1"

    # Case 3: Mixed valid and invalid args
    input3 = {"target": {"target": "google.com"}, "port": 80}
    output3 = _sanitize_args(input3)
    print(f"Case 3: {input3} -> {output3}")
    assert output3["target"] == "google.com"
    assert output3["port"] == 80

    # Case 4: No hallucination (don't break valid stuff)
    input4 = {"target": "10.0.0.1"}
    output4 = _sanitize_args(input4)
    print(f"Case 4: {input4} -> {output4}")
    assert output4["target"] == "10.0.0.1"

    print("\nAll sanitization tests passed!")

if __name__ == "__main__":
    test_sanitization()
