"""
Prompt Injection Detector for AgentGuard AI.
Deterministic pattern and heuristic analyzer for prompt injection, jailbreak attempts,
system prompt overrides, delimiter attacks, and role hijacking.
"""

import re
from typing import Dict, List, Any


class PromptInjectionDetector:
    """
    Analyzes input text and tool parameters for prompt injection attempts.
    """

    PATTERNS: List[Dict[str, Any]] = [
        {
            "id": "PI_DIRECT_OVERRIDE",
            "name": "Direct Instruction Override",
            "category": "prompt_injection",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "patterns": [
                r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|prompts|rules|commands)",
                r"(?i)\bdisregard\s+(all\s+)?(previous|prior|safety|system)\s+(instructions|directives|rules|guidelines)",
                r"(?i)\bforget\s+(all\s+)?(previous|prior|safety|guardrail)\s+(instructions|rules|context)",
                r"(?i)\boverride\s+(system\s+)?(prompt|directive|guardrails|instructions)",
                r"(?i)\bbypass\s+(all\s+)?(safety|security|policy|restrictions|filters|guardrails)",
                r"(?i)\bdo\s+not\s+follow\s+(the\s+)?(original|system|developer)\s+(instructions|prompts)",
            ],
            "description": "Attempt to override or disregard prior system instructions."
        },
        {
            "id": "PI_ROLE_HIJACK",
            "name": "Role Hijack / Jailbreak (DAN / Developer Mode)",
            "category": "prompt_injection",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "patterns": [
                r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer\s+mode|god\s+mode|dan\s+mode|unrestricted\s+mode|jailbroken)",
                r"(?i)\bact\s+as\s+(dan|an\s+unfiltered|an\s+evil|an\s+unrestricted|a\s+rogue)\s+(ai|agent|model|assistant)",
                r"(?i)\bdo\s+anything\s+now\b",
                r"(?i)\byou\s+have\s+no\s+(rules|restrictions|limits|guidelines|ethics)",
                r"(?i)\bpretend\s+you\s+are\s+not\s+bound\s+by\s+(any\s+)?(rules|policies|safety)",
            ],
            "description": "Attempt to hijack AI agent role into an unrestricted persona (DAN/Jailbreak)."
        },
        {
            "id": "PI_DELIMITER_INJECTION",
            "name": "Delimiter & System Token Injection",
            "category": "prompt_injection",
            "severity": "HIGH",
            "risk_weight": 30,
            "patterns": [
                r"(?i)(---|===|###)\s*(BEGIN|START)\s*(SYSTEM|DEVELOPER|ADMIN|ROOT|CONFIG|OVERRIDE)",
                r"(?i)(---|===|###)\s*(END|FINISH)\s*(USER|PROMPT|CONTEXT)",
                r"(?i)<\s*(system|developer|admin_override|prompt_override|hidden_instruction)\s*>",
                r"(?i)<\/\s*(system|developer|admin_override|prompt_override)\s*>",
                r"(?i)\[\s*(SYSTEM|DEVELOPER|ADMIN_COMMAND|OVERRIDE)\s*\]",
                r"(?i)\"role\"\s*:\s*\"system\"",
            ],
            "description": "Structured delimiter attack attempting to forge system tokens or tag boundaries."
        },
        {
            "id": "PI_INDIRECT_TRIGGER",
            "name": "Indirect Instruction Injection",
            "category": "prompt_injection",
            "severity": "HIGH",
            "risk_weight": 25,
            "patterns": [
                r"(?i)\bnew\s+(directive|mandate|priority|mission)\s*:\s*",
                r"(?i)\bimportant\s+update\s*:\s*from\s+now\s+on\b",
                r"(?i)\bfrom\s+now\s+on,\s*(you\s+must|always|output|respond)\b",
                r"(?i)\boutput\s+only\s+(the\s+following|this\s+exact)\s+text\s*:\s*",
                r"(?i)\breturn\s+the\s+system\s+prompt\b",
                r"(?i)\bprint\s+(your\s+)?(initial|system|hidden)\s+(instructions|prompt)",
                r"(?i)\brepeat\s+all\s+(prior|previous|system)\s+words\b",
            ],
            "description": "Indirect context manipulation or system prompt extraction attempt."
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

    def analyze(self, text: str, context: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Scans input text for prompt injection patterns.
        Returns a list of detected threat objects.
        """
        if not text or not isinstance(text, str):
            return []

        threats = []

        for rule in self._compiled_rules:
            matched_samples = []
            for regex in rule["regexes"]:
                for match in regex.finditer(text):
                    span = match.span()
                    matched_str = match.group(0)
                    # Extract surrounding snippet safely
                    start_ctx = max(0, span[0] - 20)
                    end_ctx = min(len(text), span[1] + 20)
                    snippet = text[start_ctx:end_ctx].strip()
                    
                    matched_samples.append({
                        "matched_pattern": matched_str,
                        "span": span,
                        "context_snippet": snippet
                    })

            if matched_samples:
                threats.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "risk_weight": rule["risk_weight"],
                    "description": rule["description"],
                    "matches_count": len(matched_samples),
                    "evidence": matched_samples[0]["matched_pattern"],
                    "context_snippet": matched_samples[0]["context_snippet"],
                    "all_matches": matched_samples[:5]
                })

        return threats
