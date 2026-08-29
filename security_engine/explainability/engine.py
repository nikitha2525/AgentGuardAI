"""
Explainability & Attack Chain Generator for AgentGuard AI.
Produces structured attack chains, step-by-step evidence nodes, and SOC forensic summaries.
"""

from typing import Dict, List, Any


class ExplainabilityEngine:
    """
    Builds transparent attack chains and actionable forensic summaries for security analysts.
    """

    def generate_attack_chain(
        self,
        agent_id: str,
        user_input: str,
        tool: str,
        action: str,
        masked_params: Any,
        threats: List[Dict[str, Any]],
        permission_eval: Dict[str, Any],
        risk_eval: Dict[str, Any],
        decision_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Creates a sequential graph of forensic nodes for interactive UI inspection.
        """
        nodes = []

        # 1. Ingress Node (User Prompt)
        nodes.append({
            "step": 1,
            "id": "node_ingress",
            "title": "Ingress & Prompt Analysis",
            "type": "ingress",
            "status": "warning" if threats else "clean",
            "summary": f"Intercepted request for Agent '{agent_id}' targeting tool '{tool}:{action}'.",
            "details": {
                "user_prompt_snippet": (user_input[:120] + "...") if user_input and len(user_input) > 120 else user_input or "N/A",
                "prompt_length": len(user_input or "")
            }
        })

        # 2. Threat Detection Node
        has_critical = any(t.get("severity") == "CRITICAL" for t in threats)
        threat_status = "blocked" if has_critical else ("warning" if threats else "clean")
        nodes.append({
            "step": 2,
            "id": "node_detectors",
            "title": "Multi-Detector Heuristics",
            "type": "detection",
            "status": threat_status,
            "summary": f"Identified {len(threats)} threat signature(s) across heuristic pipelines." if threats else "Zero malicious signatures or prompt injection patterns detected.",
            "details": {
                "detected_threats": [
                    {
                        "rule_name": t.get("rule_name"),
                        "category": t.get("category"),
                        "severity": t.get("severity"),
                        "evidence": t.get("evidence")
                    } for t in threats
                ]
            }
        })

        # 3. Agent Tool Action Node
        nodes.append({
            "step": 3,
            "id": "node_agent_action",
            "title": "Tool & Parameter Sanitation",
            "type": "sanitization",
            "status": "clean",
            "summary": f"Payload verified and sensitive credentials redacted for dispatch.",
            "details": {
                "agent_id": agent_id,
                "tool": tool,
                "action": action,
                "sanitized_params": masked_params
            }
        })

        # 4. Permission & Policy Matrix Node
        is_auth = permission_eval.get("is_authorized", True)
        policy_decision = permission_eval.get("decision", "ALLOW")
        nodes.append({
            "step": 4,
            "id": "node_permission",
            "title": "Server-Side Policy Check",
            "type": "permission",
            "status": "clean" if policy_decision == "ALLOW" else ("warning" if policy_decision == "REVIEW" else "blocked"),
            "summary": permission_eval.get("reason", "Policy checked."),
            "details": {
                "agent_role": permission_eval.get("role", "general"),
                "policy_decision": policy_decision,
                "authorized": is_auth
            }
        })

        # 5. Risk Assessment Node
        risk_score = risk_eval.get("risk_score", 0)
        risk_level = risk_eval.get("risk_level", "LOW")
        nodes.append({
            "step": 5,
            "id": "node_risk",
            "title": "Weighted Risk Calculation",
            "type": "risk",
            "status": "blocked" if risk_score >= 60 else ("warning" if risk_score >= 30 else "clean"),
            "summary": f"Calculated composite risk score: {risk_score}/100 ({risk_level}).",
            "details": {
                "risk_score": risk_score,
                "risk_level": risk_level,
                "category_breakdown": risk_eval.get("breakdown", {})
            }
        })

        # 6. Final Deterministic Decision Node
        final_dec = decision_result.get("decision", "ALLOW")
        nodes.append({
            "step": 6,
            "id": "node_decision",
            "title": "Deterministic Enforcement",
            "type": "enforcement",
            "status": "clean" if final_dec == "ALLOW" else ("warning" if final_dec == "REVIEW" else "blocked"),
            "summary": f"Gateway rendered strict decision: {final_dec}.",
            "details": {
                "decision": final_dec,
                "reasons": decision_result.get("reasons", []),
                "recommendation": self._generate_recommendation(final_dec, threats, permission_eval)
            }
        })

        return {
            "attack_chain_nodes": nodes,
            "forensic_summary": self._generate_summary(final_dec, agent_id, tool, action, threats, risk_score),
            "recommendations": self._generate_recommendation(final_dec, threats, permission_eval)
        }

    def _generate_summary(
        self,
        decision: str,
        agent_id: str,
        tool: str,
        action: str,
        threats: List[Dict[str, Any]],
        risk_score: int
    ) -> str:
        if decision == "ALLOW":
            return f"Request by {agent_id} to execute {tool}:{action} was safely authorized with low risk ({risk_score}/100)."
        elif decision == "REVIEW":
            threat_names = ", ".join([t.get("rule_name") for t in threats]) if threats else "policy review requirement"
            return f"Request by {agent_id} flagged for human review due to {threat_names} (Risk score: {risk_score}/100)."
        else:
            threat_names = ", ".join([t.get("rule_name") for t in threats]) if threats else "strict policy violation"
            return f"Security Gateway intercepted and BLOCKED hostile or unauthorized action '{action}' on '{tool}' by '{agent_id}'. Triggered: {threat_names} (Risk score: {risk_score}/100)."

    def _generate_recommendation(
        self,
        decision: str,
        threats: List[Dict[str, Any]],
        permission_eval: Dict[str, Any]
    ) -> List[str]:
        recs = []
        if decision == "ALLOW":
            recs.append("No immediate action required. Tool invocation safe to forward.")
            return recs

        if not permission_eval.get("is_authorized"):
            recs.append(f"Review agent permission matrix. Agent is currently forbidden from executing this tool action.")

        for t in threats:
            cat = t.get("category")
            if cat == "prompt_injection":
                recs.append("Sanitize upstream user prompts and strip delimiter overrides before passing to LLM context.")
            elif cat == "sensitive_data":
                recs.append("Rotate any exposed API keys/credentials immediately and enforce client-side environment variable injection.")
            elif cat == "malicious_intent":
                recs.append("Block agent session and isolate tool endpoint. Prevent direct shell/raw SQL query execution.")
            elif cat == "suspicious_behavior":
                recs.append("Enforce strict parameter pagination limits and whitelist allowable network egress destinations.")

        if not recs:
            recs.append("Inspect tool parameters and verify agent identity before manual approval.")

        return recs
