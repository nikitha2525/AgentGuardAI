"""
Malicious Intent Detector for AgentGuard AI.
Detects dangerous system commands, destructive SQL queries, reverse shells,
unauthorized directory traversal, and privilege escalation attempts.
"""

import re
from typing import Dict, List, Any


class MaliciousIntentDetector:
    """
    Scans prompts, tool names, and parameter payloads for malicious system actions.
    """

    PATTERNS: List[Dict[str, Any]] = [
        # Destructive Shell / OS Commands
        {
            "id": "MAL_DESTRUCTIVE_CMD",
            "name": "Destructive File/System Command",
            "category": "malicious_intent",
            "severity": "CRITICAL",
            "risk_weight": 40,
            "patterns": [
                r"(?i)\brm\s+-(?:r[fF]|f[rR]|rf|fr)\s+[\/\*~]",
                r"(?i)\brmdir\s+\/s\s+\/q\b",
                r"(?i)\bmkfs(?:\.[a-z0-9]+)?\s+",
                r"(?i)\bdd\s+if=\/dev\/(?:zero|urandom|null)\s+of=",
                r"(?i)\bformat\s+[c-z]:\s+\/q\b",
                r"(?i)\bdel\s+\/f\s+\/s\s+\/q\b",
                r"(?i)\bchmod\s+(?:-R\s+)?777\s+[\/\*]",
                r"(?i)\bchown\s+(?:-R\s+)?root\b",
            ],
            "description": "Destructive file system deletion or drive wiping command."
        },
        # Reverse Shells and Code Execution
        {
            "id": "MAL_REVERSE_SHELL",
            "name": "Reverse Shell / Remote Code Execution",
            "category": "malicious_intent",
            "severity": "CRITICAL",
            "risk_weight": 45,
            "patterns": [
                r"(?i)\bbash\s+-i\s+>&?\s*\/dev\/tcp\/",
                r"(?i)\bnc(?:at)?\s+(?:-[a-z]*e|-[a-z]*c)\s+(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)",
                r"(?i)\b(?:curl|wget)\s+[^|\n]+(?:\|\s*(?:bash|sh|zsh|python|perl|ruby))",
                r"(?i)powershell(?:\.exe)?\s+(?:-[eE]n?c?o?d?e?d?C?o?m?m?a?n?d?|-[cCdD][a-zA-Z]*)\s+[A-Za-z0-9+\/=]{10,}",
                r"(?i)\bIEX\s*\(\s*(?:New-Object|iwr|Invoke-WebRequest|DownloadString)",
                r"(?i)\bpython(?:\d)?\s+-c\s*['\"][^'\"]*socket[^'\"]*dup2",
                r"(?i)\bcertutil(?:\.exe)?\s+-urlcache\s+-split\s+-f\b",
            ],
            "description": "Remote shell execution or external script piping detected."
        },
        # Destructive & Injection SQL
        {
            "id": "MAL_DESTRUCTIVE_SQL",
            "name": "Destructive / Injected SQL Query",
            "category": "malicious_intent",
            "severity": "CRITICAL",
            "risk_weight": 35,
            "patterns": [
                r"(?i)\bDROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW|PROCEDURE|INDEX)\b",
                r"(?i)\bTRUNCATE\s+(?:TABLE)?\b",
                r"(?i)\bDELETE\s+FROM\s+[a-zA-Z0-9_`\"\[\]]+(?:\s*;|\s*$|\s+(?:WHERE\s+1\s*=\s*1|WHERE\s+'1'\s*=\s*'1'))",
                r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\s+.*(?:password|hash|token|secret|admin|users|information_schema)",
                r"(?i)('|\")\s*(?:OR|AND)\s*('1'='1'|1=1|true)\s*(--|#|\/\*)",
                r"(?i)\bEXEC(?:UTE)?\s*\(\s*(?:sp_executesql|xp_cmdshell)",
                r"(?i)\bxp_cmdshell\b",
            ],
            "description": "Destructive SQL operation (DROP/TRUNCATE/unconditional DELETE) or SQLi dump."
        },
        # Directory Traversal & Sensitive File Access
        {
            "id": "MAL_PATH_TRAVERSAL",
            "name": "Path Traversal / Unauthorized File Access",
            "category": "malicious_intent",
            "severity": "HIGH",
            "risk_weight": 30,
            "patterns": [
                r"(?:\.\.[\/\\]){2,}(?:etc[\/\\]passwd|etc[\/\\]shadow|windows[\/\\]system32|boot\.ini)",
                r"(?i)(?:\/|\\)(?:etc\/passwd|etc\/shadow|etc\/sudoers|\.ssh\/id_rsa|\.aws\/credentials)",
                r"(?i)\b(?:C:\\Windows\\System32\\config\\SAM|C:\\Windows\\System32\\drivers\\etc\\hosts)\b",
                r"(?i)\breg(?:\.exe)?\s+(?:query|add|delete)\s+HKLM\b",
                r"(?i)\bwhoami\s*\/priv\b",
            ],
            "description": "Attempt to traverse directories to access sensitive OS credentials or config files."
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
        Analyzes prompt, tool, action, and payload for malicious intent patterns.
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

        return threats
