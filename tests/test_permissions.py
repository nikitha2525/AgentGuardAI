"""
Unit tests for AgentGuard AI Permission and Policy Engine.
"""

import pytest
from security_engine.permissions.policy_engine import PolicyEngine


class TestPolicyEngine:
    def setup_method(self):
        self.engine = PolicyEngine()

    def test_research_agent_allowed_websearch(self):
        res = self.engine.evaluate_permission("ResearchAgent", "WebSearch", "query")
        assert res["decision"] == "ALLOW"
        assert res["is_authorized"] is True

    def test_research_agent_blocked_shell(self):
        res = self.engine.evaluate_permission("ResearchAgent", "Shell", "exec")
        assert res["decision"] == "BLOCK"
        assert res["is_authorized"] is False

    def test_customer_support_allowed_ticket_read(self):
        res = self.engine.evaluate_permission("CustomerSupportAgent", "TicketDB", "read")
        assert res["decision"] == "ALLOW"
        assert res["is_authorized"] is True

    def test_customer_support_blocked_ticket_delete(self):
        res = self.engine.evaluate_permission("CustomerSupportAgent", "TicketDB", "delete")
        assert res["decision"] == "BLOCK"
        assert res["is_authorized"] is False

    def test_customer_support_review_refund_issue(self):
        res = self.engine.evaluate_permission("CustomerSupportAgent", "RefundAPI", "issue")
        assert res["decision"] == "REVIEW"
        assert res["is_authorized"] is True

    def test_unknown_agent_default_deny(self):
        res = self.engine.evaluate_permission("RogueAgent999", "WebSearch", "query")
        assert res["decision"] == "BLOCK"
        assert res["is_authorized"] is False
        assert "default-deny" in res["reason"]
