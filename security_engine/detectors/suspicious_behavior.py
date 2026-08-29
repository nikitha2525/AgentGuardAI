"""
Suspicious Behavior Detector for AgentGuard AI.
Detects mass data exfiltration patterns, unauthorized network egress / webhooks,
evasion techniques (obfuscation, base64 payload delivery), and anomalous parameter structures.
"""

import re
from typing import Dict, List, Any


class SuspiciousBehaviorDetector:
    """
    Evaluates requests for anomaly markers, mass exfiltration, and unauthorized egress.
    """

    PATTERNS: List[Dict[str, Any]] = [
        # External Egress / Suspicious Webhooks
        {
            "id": "SUSP_UNTRUSTED_EGRESS",
            "name": "Untrusted External Network Destination",
            "category": "suspicious_behavior",
            "severity": "HIGH",
            "risk_weight": 25,
            "patterns": [
                r"(?i)https?:\/\/(?:www\.)?(?:webhook\.site|requestbin\.com|pipedream\.net|pastebin\.com|tempfile\.org|anonfiles\.com|transfer\.sh|ngrok\.io|serveo\.net)",
                r"(?i)https?:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[a-zA-Z0-9_-]+",
                r"(?i)https?:\/\/api\.telegram\.org\/bot[0-9]+:[a-zA-Z0-9_-]+",
                r"(?i)https?:\/\/(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?(?:\/|\b)",
            ],
            "description": "Outbound network destination pointing to known data exfiltration sinks or direct IP endpoints."
        },
        # Mass Data Exfiltration
        {
            "id": "SUSP_MASS_EXFILTRATION",
            "name": "Mass Exfiltration / Bulk Data Access",
            "category": "suspicious_behavior",
            "severity": "HIGH",
            "risk_weight": 25,
            "patterns": [
                r"(?i)\bLIMIT\s+(?:[1-9][0-9]{4,}|100000|all)\b",
                r"(?i)\bexport\s+(?:all\s+)?(?:users|customers|accounts|records|database)\b",
                r"(?i)\bdump\s+(?:all\s+)?(?:tables|database|credentials)\b",
                r"(?i)\bSELECT\s+\*\s+FROM\s+(?:users|passwords|accounts|credentials|credit_cards|tokens)\b",
            ],
            "description": "High-volume data querying or bulk database dump request."
        },
        # Obfuscation / Evasion
        {
            "id": "SUSP_PAYLOAD_OBFUSCATION",
            "name": "Payload Obfuscation / Evasion Technique",
            "category": "suspicious_behavior",
            "severity": "MEDIUM",
            "risk_weight": 20,
            "patterns": [
                r"(?:\\x[0-9a-fA-F]{2}){4,}",
                r"(?i)\bbase64\s+(?:-d|--decode|decode)\b",
                r"(?i)\b(?:eval|exec)\s*\(\s*(?:atob|base64_decode|decode)\s*\(",
                r"(?i)\bchar\s*\(\s*(?:[0-9]+\s*,\s*){3,}[0-9]+\s*\)",
            ],
            "description": "Hexadecimal, character-code, or base64 decoding evasion attempt."
        }
    ]

    def __init__(self):
        self._compiled_rules = []
        for rule in self.PATTERNS:
            compiled = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in rule["patterns"]]
            self._compiled_rules.append({
                "id": rule["id"],
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "risk_weight": rule["risk_weight"],
                "description": rule["description"],
                "regexes": compiled
            })

    def analyze(self, text: str, tool: str = None, action: str = None, params: Any = None) -> List[Dict[str, Any]]:
        """
        Analyzes prompt and params for suspicious behavior and anomaly indicators.
        """
        combined = f"{text or ''} {tool or ''} {action or ''}"
        if params:
            import json
            try:
                if isinstance(params, (dict, list)):
                    combined += " " + json.dumps(params)
                else:
                    combined += " " + str(params)
            except Exception:
                combined += " " + str(params)

        if not combined.strip():
            return []

        threats = []

        for rule in self._compiled_rules:
            matched_items = []
            for regex in rule["regexes"]:
                for match in regex.finditer(combined):
                    matched_items.append({
                        "matched_pattern": match.group(0),
                        "span": match.span()
                    })

            if matched_items:
                threats.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "risk_weight": rule["risk_weight"],
                    "description": rule["description"],
                    "matches_count": len(matched_items),
                    "evidence": matched_items[0]["matched_pattern"],
                    "all_matches": matched_items[:5]
                })

        # Check for mass numerical count in params if dict
        if isinstance(params, dict):
            limit = params.get("limit") or params.get("count") or params.get("size")
            if isinstance(limit, (int, float)) and limit > 10000:
                threats.append({
                    "rule_id": "SUSP_HIGH_LIMIT",
                    "rule_name": "Excessive Parameter Limit",
                    "category": "suspicious_behavior",
                    "severity": "HIGH",
                    "risk_weight": 20,
                    "description": f"Query requested {limit} records, exceeding safe operational threshold (10,000).",
                    "matches_count": 1,
                    "evidence": f"limit={limit}",
                    "all_matches": [{"matched_pattern": f"limit={limit}", "span": (0, 0)}]
                })

        return threats
