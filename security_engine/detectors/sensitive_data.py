"""
Sensitive Data Detector for AgentGuard AI.
Detects API keys, secrets, tokens, PII (SSN, emails, credit cards with Luhn check),
private keys, and connection strings. Provides zero-leakage redaction masking.
"""

import re
from typing import Dict, List, Any, Tuple, Union


def luhn_check(card_number: str) -> bool:
    """Validates credit card number using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


class SensitiveDataDetector:
    """
    Regex and algorithmic sensitive data detector with payload redaction.
    """

    PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "SENSITIVE_AWS_KEY",
            "name": "AWS Access Key",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "pattern": r"(?i)\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            "description": "AWS IAM Access Key ID detected."
        },
        {
            "id": "SENSITIVE_OPENAI_KEY",
            "name": "OpenAI API Key",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "pattern": r"\bsk-(?:proj-|admin-)?[a-zA-Z0-9_\-]{20,}\b",
            "description": "OpenAI / LLM API Key detected."
        },
        {
            "id": "SENSITIVE_ANTHROPIC_KEY",
            "name": "Anthropic API Key",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "pattern": r"\bsk-ant-[a-zA-Z0-9_\-]{20,}\b",
            "description": "Anthropic Claude API Key detected."
        },
        {
            "id": "SENSITIVE_HUGGINGFACE_TOKEN",
            "name": "HuggingFace Access Token",
            "category": "sensitive_data",
            "severity": "HIGH",
            "risk_weight": 25,
            "pattern": r"\bhf_[a-zA-Z0-9]{30,}\b",
            "description": "Hugging Face User Access Token detected."
        },
        {
            "id": "SENSITIVE_JWT_TOKEN",
            "name": "JSON Web Token (JWT)",
            "category": "sensitive_data",
            "severity": "HIGH",
            "risk_weight": 25,
            "pattern": r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]+\b",
            "description": "JWT authentication token detected."
        },
        {
            "id": "SENSITIVE_PRIVATE_KEY",
            "name": "Private Cryptographic Key",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 40,
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
            "description": "Unencrypted Private Key block detected."
        },
        {
            "id": "SENSITIVE_DB_PASSWORD_URI",
            "name": "Database URI with Credentials",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "pattern": r"(?i)\b(?:postgres|postgresql|mysql|mongodb|redis|amqp|couchdb):\/\/[^:\s\n]+:([^@\s\n]+)@[a-zA-Z0-9.-]+",
            "description": "Database connection string containing plaintext credentials."
        },
        {
            "id": "SENSITIVE_US_SSN",
            "name": "US Social Security Number (SSN)",
            "category": "sensitive_data",
            "severity": "HIGH",
            "risk_weight": 30,
            "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
            "description": "US Social Security Number (PII) detected."
        },
        {
            "id": "SENSITIVE_CREDIT_CARD",
            "name": "Credit Card Number",
            "category": "sensitive_data",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
            "luhn_validate": True,
            "description": "Payment card number detected with valid Luhn checksum."
        },
        {
            "id": "SENSITIVE_EMAIL_ADDRESS",
            "name": "Email Address (PII)",
            "category": "sensitive_data",
            "severity": "MEDIUM",
            "risk_weight": 15,
            "pattern": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            "description": "Email address (PII) identified."
        },
        {
            "id": "SENSITIVE_GENERIC_SECRET",
            "name": "Generic Password/Token Parameter",
            "category": "sensitive_data",
            "severity": "HIGH",
            "risk_weight": 25,
            "pattern": r"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|bearer_token|password|passwd|db_password)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?",
            "description": "Explicit secret or password assignment detected."
        }
    ]

    def __init__(self):
        self._compiled_rules = []
        for rule in self.PATTERNS:
            self._compiled_rules.append({
                "id": rule["id"],
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "risk_weight": rule["risk_weight"],
                "description": rule["description"],
                "regex": re.compile(rule["pattern"], re.IGNORECASE if "PRIVATE KEY" not in rule["pattern"] else 0),
                "luhn_validate": rule.get("luhn_validate", False)
            })

    def mask_text(self, text: str) -> str:
        """
        Replaces detected secrets in a string with [REDACTED:<TYPE>].
        """
        if not isinstance(text, str):
            return text

        masked = text
        for rule in self._compiled_rules:
            if rule["luhn_validate"]:
                def replace_card(m):
                    raw = m.group(0)
                    if luhn_check(raw):
                        return f"[REDACTED:{rule['name'].upper().replace(' ', '_')}]"
                    return raw
                masked = rule["regex"].sub(replace_card, masked)
            else:
                masked = rule["regex"].sub(f"[REDACTED:{rule['name'].upper().replace(' ', '_')}]", masked)

        return masked

    def mask_payload(self, data: Any) -> Any:
        """
        Recursively redacts sensitive values inside dicts, lists, or strings.
        """
        if isinstance(data, dict):
            masked_dict = {}
            for k, v in data.items():
                # Check if key itself indicates password/secret
                if any(sec in k.lower() for sec in ["password", "secret", "token", "api_key", "apikey", "private_key"]):
                    masked_dict[k] = "[REDACTED_SECRET]"
                else:
                    masked_dict[k] = self.mask_payload(v)
            return masked_dict
        elif isinstance(data, list):
            return [self.mask_payload(item) for item in data]
        elif isinstance(data, str):
            return self.mask_text(data)
        else:
            return data

    def analyze(self, text: str, params: Any = None) -> List[Dict[str, Any]]:
        """
        Scans text and tool parameters for sensitive information.
        """
        combined_text = text if isinstance(text, str) else ""
        if params:
            import json
            try:
                if isinstance(params, (dict, list)):
                    combined_text += " " + json.dumps(params)
                else:
                    combined_text += " " + str(params)
            except Exception:
                combined_text += " " + str(params)

        if not combined_text:
            return []

        threats = []

        for rule in self._compiled_rules:
            matches = []
            for match in rule["regex"].finditer(combined_text):
                val = match.group(0)
                if rule["luhn_validate"] and not luhn_check(val):
                    continue
                # Mask matched value for safe logging
                masked_val = val[:4] + "..." + val[-4:] if len(val) > 10 else "***"
                matches.append({
                    "masked_pattern": masked_val,
                    "span": match.span()
                })

            if matches:
                threats.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "risk_weight": rule["risk_weight"],
                    "description": rule["description"],
                    "matches_count": len(matches),
                    "evidence": matches[0]["masked_pattern"],
                    "all_matches": matches[:5]
                })

        return threats
