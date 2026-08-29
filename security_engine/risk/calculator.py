"""
Risk Calculator for AgentGuard AI.
Computes deterministic, weighted risk scores [0 - 100] with category breakdown
and level classification (LOW, MEDIUM, HIGH, CRITICAL).
"""

from typing import Dict, List, Any, Tuple


class RiskCalculator:
    """
    Transparent weighted risk calculation engine.
    """

    THRESHOLDS = {
        "LOW": (0, 29),
        "MEDIUM": (30, 59),
        "HIGH": (60, 79),
        "CRITICAL": (80, 100)
    }

    def __init__(self, weight_overrides: Dict[str, int] = None):
        self.weights = {
            "prompt_injection": 30,
            "sensitive_data": 25,
            "policy_violation": 30,
            "malicious_intent": 35,
            "suspicious_behavior": 15,
            "untrusted_egress": 20
        }
        if weight_overrides:
            self.weights.update(weight_overrides)

    def classify_level(self, score: int) -> str:
        """Categorizes numerical risk score into risk level."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        else:
            return "LOW"

    def calculate_risk(
        self,
        threats: List[Dict[str, Any]],
        permission_eval: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculates cumulative clamped risk score and categorical breakdown.
        """
        breakdown: Dict[str, int] = {
            "prompt_injection": 0,
            "sensitive_data": 0,
            "policy_violation": 0,
            "malicious_intent": 0,
            "suspicious_behavior": 0
        }

        # Sum risk weights per threat category
        for threat in threats:
            cat = threat.get("category", "suspicious_behavior")
            weight = threat.get("risk_weight", 15)
            # Add up to category limit to prevent a single category from overwhelming everything
            current = breakdown.get(cat, 0)
            breakdown[cat] = min(60, current + weight)

        # Policy risk
        policy_decision = permission_eval.get("decision", "ALLOW")
        policy_weight = permission_eval.get("policy_risk_weight", 0)
        if policy_decision == "BLOCK":
            breakdown["policy_violation"] = max(35, policy_weight)
        elif policy_decision == "REVIEW":
            breakdown["policy_violation"] = max(20, policy_weight)

        raw_score = sum(breakdown.values())
        final_score = min(100, max(0, raw_score))
        level = self.classify_level(final_score)

        return {
            "risk_score": final_score,
            "risk_level": level,
            "breakdown": breakdown,
            "max_score": 100,
            "thresholds": self.THRESHOLDS
        }
