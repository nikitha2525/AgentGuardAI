"""
Policy & Permission Engine for AgentGuard AI.
Evaluates agent permissions against deterministic server-side role matrices.
"""

import json
import os
from typing import Dict, Any, Tuple


class PolicyEngine:
    """
    Evaluates whether an agent has authorization to execute a tool action.
    """

    def __init__(self, policy_file_path: str = None):
        if not policy_file_path:
            base_dir = os.path.dirname(__file__)
            policy_file_path = os.path.join(base_dir, "policies.json")
        self.policy_file_path = policy_file_path
        self._load_policies()

    def _load_policies(self):
        try:
            with open(self.policy_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.agents = data.get("agents", {})
                self.tools = data.get("tools", {})
        except Exception as e:
            self.agents = {}
            self.tools = {}

    def get_agents(self) -> Dict[str, Any]:
        return self.agents

    def get_tools(self) -> Dict[str, Any]:
        return self.tools

    def evaluate_permission(self, agent_id: str, tool: str, action: str) -> Dict[str, Any]:
        """
        Deterministically evaluates whether the requested tool and action is ALLOWED, REQUIRES_REVIEW, or BLOCKED.
        Returns evaluation dict with decision, reason, and risk weight.
        """
        tool_clean = (tool or "").strip()
        action_clean = (action or "").strip().lower()
        agent_clean = (agent_id or "").strip()

        # Check if agent exists
        agent_conf = self.agents.get(agent_clean)
        if not agent_conf:
            return {
                "decision": "BLOCK",
                "is_authorized": False,
                "reason": f"Unknown or unregistered agent '{agent_clean}'. Access denied by default-deny security policy.",
                "policy_risk_weight": 30,
                "role": "untrusted"
            }

        role = agent_conf.get("role", "general")
        perms = agent_conf.get("permissions", {})

        # Check if tool is defined in agent permissions
        tool_perms = perms.get(tool_clean)
        if not tool_perms:
            # Check case-insensitive tool match
            for t_name, t_val in perms.items():
                if t_name.lower() == tool_clean.lower():
                    tool_perms = t_val
                    break

        if not tool_perms:
            return {
                "decision": "BLOCK",
                "is_authorized": False,
                "reason": f"Agent '{agent_clean}' ({role}) is not granted access to tool '{tool_clean}'.",
                "policy_risk_weight": 30,
                "role": role
            }

        # Check action within tool
        actions = tool_perms.get("actions", {})
        action_decision = None

        if action_clean in actions:
            action_decision = actions[action_clean]
        else:
            for act_name, act_val in actions.items():
                if act_name.lower() == action_clean:
                    action_decision = act_val
                    break

        if not action_decision:
            action_decision = tool_perms.get("default", "BLOCK")

        action_decision = action_decision.upper()

        if action_decision == "ALLOW":
            return {
                "decision": "ALLOW",
                "is_authorized": True,
                "reason": f"Agent '{agent_clean}' is authorized to execute '{action_clean}' on '{tool_clean}'.",
                "policy_risk_weight": 0,
                "role": role
            }
        elif action_decision == "REVIEW":
            return {
                "decision": "REVIEW",
                "is_authorized": True,
                "reason": f"Action '{action_clean}' on '{tool_clean}' is flagged as sensitive and requires human review/approval.",
                "policy_risk_weight": 20,
                "role": role
            }
        else:
            return {
                "decision": "BLOCK",
                "is_authorized": False,
                "reason": f"Action '{action_clean}' on tool '{tool_clean}' is strictly prohibited for agent '{agent_clean}'.",
                "policy_risk_weight": 35,
                "role": role
            }
