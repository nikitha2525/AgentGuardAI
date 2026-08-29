"""
Unit tests for Risk Calculator and Deterministic Decision Engine.
"""

import pytest
from security_engine.risk.calculator import RiskCalculator
from security_engine.decision.engine import DecisionEngine


class TestRiskAndDecisionEngine:
    def setup_method(self):
        self.risk_calc = RiskCalculator()
        self.decision_engine = DecisionEngine()

    def test_clean_request_allow(self):
        threats = []
        perm_eval = {"decision": "ALLOW", "is_authorized": True, "policy_risk_weight": 0, "role": "researcher"}
        risk_res = self.risk_calc.calculate_risk(threats, perm_eval)
        
        assert risk_res["risk_score"] == 0
        assert risk_res["risk_level"] == "LOW"

        dec_res = self.decision_engine.decide(risk_res, perm_eval, threats)
        assert dec_res["decision"] == "ALLOW"
        assert dec_res["is_allowed"] is True
        assert dec_res["is_blocked"] is False

    def test_critical_threat_forces_block(self):
        threats = [
            {"category": "malicious_intent", "severity": "CRITICAL", "risk_weight": 40, "rule_name": "Destructive Shell"}
        ]
        perm_eval = {"decision": "ALLOW", "is_authorized": True, "policy_risk_weight": 0}
        risk_res = self.risk_calc.calculate_risk(threats, perm_eval)
        dec_res = self.decision_engine.decide(risk_res, perm_eval, threats)

        assert dec_res["decision"] == "BLOCK"
        assert dec_res["is_blocked"] is True

    def test_unauthorized_policy_forces_block(self):
        threats = []
        perm_eval = {"decision": "BLOCK", "is_authorized": False, "policy_risk_weight": 35, "reason": "Forbidden tool"}
        risk_res = self.risk_calc.calculate_risk(threats, perm_eval)
        dec_res = self.decision_engine.decide(risk_res, perm_eval, threats)

        assert dec_res["decision"] == "BLOCK"
        assert dec_res["is_blocked"] is True

    def test_medium_risk_or_review_policy_yields_review(self):
        threats = [
            {"category": "sensitive_data", "severity": "MEDIUM", "risk_weight": 15, "rule_name": "Email Address"}
        ]
        perm_eval = {"decision": "REVIEW", "is_authorized": True, "policy_risk_weight": 20, "reason": "Review needed"}
        risk_res = self.risk_calc.calculate_risk(threats, perm_eval)
        dec_res = self.decision_engine.decide(risk_res, perm_eval, threats)

        assert dec_res["decision"] == "REVIEW"
        assert dec_res["requires_review"] is True
        assert dec_res["is_blocked"] is False

    def test_clamped_score_max_100(self):
        threats = [
            {"category": "prompt_injection", "severity": "CRITICAL", "risk_weight": 50},
            {"category": "malicious_intent", "severity": "CRITICAL", "risk_weight": 50},
            {"category": "sensitive_data", "severity": "CRITICAL", "risk_weight": 50}
        ]
        perm_eval = {"decision": "BLOCK", "is_authorized": False, "policy_risk_weight": 40}
        risk_res = self.risk_calc.calculate_risk(threats, perm_eval)

        assert risk_res["risk_score"] == 100
        assert risk_res["risk_level"] == "CRITICAL"
