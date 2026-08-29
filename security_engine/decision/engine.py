"""
Deterministic Decision Engine for AgentGuard AI.
Guarantees that final security decisions (ALLOW / REVIEW / BLOCK) are rendered strictly
by deterministic rules and risk boundaries, without non-deterministic LLM variance.
"""

from typing import Dict, List, Any


class DecisionEngine:
    """
    Renders deterministic ALLOW, REVIEW, or BLOCK decisions based on risk and policy rules.
    """

    def decide(
        self,
        risk_evaluation: Dict[str, Any],
        permission_eval: Dict[str, Any],
        threats: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Renders deterministic decision, detailed reasons, and guardrail flags.
        """
        score = risk_evaluation.get("risk_score", 0)
        risk_level = risk_evaluation.get("risk_level", "LOW")
        policy_decision = permission_eval.get("decision", "ALLOW")
        is_authorized = permission_eval.get("is_authorized", True)

        reasons: List[str] = []
        is_blocked = False
        requires_review = False

        # 1. Policy check enforcement
        if not is_authorized or policy_decision == "BLOCK":
            is_blocked = True
            reasons.append(permission_eval.get("reason", "Operation blocked by agent permission policy."))
        elif policy_decision == "REVIEW":
            requires_review = True
            reasons.append(permission_eval.get("reason", "Operation requires human authorization per agent policy."))

        # 2. Critical threat checks
        has_critical_threat = any(t.get("severity") == "CRITICAL" for t in threats)
        if has_critical_threat:
            is_blocked = True
            for t in threats:
                if t.get("severity") == "CRITICAL":
                    reasons.append(f"Critical Security Alert: {t.get('rule_name')} detected ({t.get('description')}).")

        # 3. High threat items
        for t in threats:
            if t.get("severity") == "HIGH" and not is_blocked:
                requires_review = True
                reasons.append(f"High Security Alert: {t.get('rule_name')} ({t.get('description')}).")
            elif t.get("severity") == "MEDIUM":
                reasons.append(f"Security Warning: {t.get('rule_name')} detected.")

        # 4. Score-based deterministic gates
        if score >= 60:
            final_decision = "BLOCK"
            if not reasons:
                reasons.append(f"Composite risk score ({score}/100) exceeded maximum allowable threshold (60).")
        elif score >= 30 or requires_review or policy_decision == "REVIEW":
            final_decision = "REVIEW" if not is_blocked else "BLOCK"
            if final_decision == "REVIEW" and not reasons:
                reasons.append(f"Elevated risk score ({score}/100) requires human supervisor review before tool dispatch.")
        else:
            final_decision = "ALLOW" if not is_blocked else "BLOCK"
            if final_decision == "ALLOW":
                reasons.append("All security detectors passed and agent permissions verified. Request authorized.")

        return {
            "decision": final_decision,
            "risk_score": score,
            "risk_level": risk_level,
            "reasons": reasons,
            "is_blocked": final_decision == "BLOCK",
            "requires_review": final_decision == "REVIEW",
            "is_allowed": final_decision == "ALLOW",
            "threats_count": len(threats),
            "guarantee": "DETERMINISTIC_ENFORCEMENT"
        }
