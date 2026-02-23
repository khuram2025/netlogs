"""
AI-powered alert summarization service.
"""

import logging
import json
from typing import Dict, Any, Optional
from datetime import datetime

from .client import ai_client

logger = logging.getLogger(__name__)


async def summarize_alert(
    alert_data: Dict[str, Any],
    enrichment_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate an AI-powered summary of a security alert.

    Args:
        alert_data: Alert information (title, severity, rule details, etc.)
        enrichment_data: Optional enrichment data (top sources, destinations, ports, etc.)

    Returns:
        Dict with:
            - summary: Executive summary (2-3 sentences)
            - risk_assessment: Risk level and reasoning
            - recommended_actions: List of suggested response actions
            - confidence: AI confidence score (0.0-1.0)
            - mitre_context: Explanation of MITRE technique
    """
    # Check if AI is configured
    if not await ai_client.is_configured():
        return {
            "summary": "AI not configured. Please configure an LLM provider in Admin > AI Settings.",
            "risk_assessment": "N/A",
            "recommended_actions": [],
            "confidence": 0.0,
            "mitre_context": "",
        }

    try:
        # Build comprehensive prompt
        prompt = _build_alert_prompt(alert_data, enrichment_data)

        system_prompt = """You are a cybersecurity analyst assistant for NetLogs SOAR/SIEM platform.
Analyze security alerts and provide actionable insights in JSON format.

You MUST respond with ONLY valid JSON (no markdown, no code blocks, no explanation).

Required JSON structure:
{
    "summary": "2-3 sentence executive summary of the incident",
    "risk_assessment": "Low/Medium/High/Critical with brief reasoning",
    "recommended_actions": ["action 1", "action 2", "action 3"],
    "confidence": 0.85,
    "mitre_context": "Brief explanation of the MITRE ATT&CK technique"
}"""

        # Call AI
        response_text = await ai_client.complete(prompt, system_prompt)

        # Parse JSON response
        try:
            # Clean up response (remove markdown code blocks if present)
            cleaned = response_text.strip()
            if cleaned.startswith("```"):
                # Remove ```json and ``` wrappers
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]) if len(lines) > 2 else cleaned

            result = json.loads(cleaned)

            # Validate required fields
            required_fields = ["summary", "risk_assessment", "recommended_actions", "confidence", "mitre_context"]
            for field in required_fields:
                if field not in result:
                    result[field] = "" if field != "recommended_actions" else []

            # Ensure confidence is float
            if isinstance(result.get("confidence"), (int, float)):
                result["confidence"] = float(result["confidence"])
            else:
                result["confidence"] = 0.7  # Default

            # Ensure recommended_actions is list
            if not isinstance(result.get("recommended_actions"), list):
                result["recommended_actions"] = []

            return result

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}\nResponse: {response_text}")
            # Return fallback summary
            return {
                "summary": response_text[:500],  # Use raw response as summary
                "risk_assessment": alert_data.get("severity", "unknown").capitalize(),
                "recommended_actions": ["Review alert details", "Investigate source IPs", "Check for related events"],
                "confidence": 0.5,
                "mitre_context": "",
            }

    except Exception as e:
        logger.error(f"Alert summarization failed: {e}", exc_info=True)
        return {
            "summary": f"AI summarization error: {str(e)}",
            "risk_assessment": "Unknown",
            "recommended_actions": [],
            "confidence": 0.0,
            "mitre_context": "",
        }


def _build_alert_prompt(alert_data: Dict[str, Any], enrichment_data: Optional[Dict[str, Any]]) -> str:
    """Build the prompt for alert summarization."""

    # Extract key alert fields
    alert_title = alert_data.get("title", "Unknown Alert")
    rule_name = alert_data.get("rule_name", "Unknown Rule")
    severity = alert_data.get("severity", "unknown")
    category = alert_data.get("category", "unknown")
    description = alert_data.get("description", "")
    mitre_tactic = alert_data.get("mitre_tactic", "")
    mitre_technique = alert_data.get("mitre_technique", "")

    prompt = f"""Analyze this security alert:

**Alert Title:** {alert_title}
**Rule Name:** {rule_name}
**Severity:** {severity}
**Category:** {category}
**Description:** {description}
**MITRE Tactic:** {mitre_tactic}
**MITRE Technique:** {mitre_technique}
"""

    # Add enrichment data if available
    if enrichment_data:
        prompt += "\n**Enrichment Data:**\n"

        if enrichment_data.get("total_events"):
            prompt += f"- Total Events: {enrichment_data['total_events']}\n"

        if enrichment_data.get("time_range"):
            tr = enrichment_data["time_range"]
            prompt += f"- Time Range: {tr.get('start', 'unknown')} to {tr.get('end', 'unknown')}\n"

        if enrichment_data.get("top_sources"):
            sources = enrichment_data["top_sources"][:5]  # Top 5
            prompt += f"- Top Source IPs: {', '.join([f'{s[0]} ({s[1]} events)' for s in sources])}\n"

        if enrichment_data.get("top_destinations"):
            dests = enrichment_data["top_destinations"][:5]
            prompt += f"- Top Destination IPs: {', '.join([f'{d[0]} ({d[1]} events)' for d in dests])}\n"

        if enrichment_data.get("top_ports"):
            ports = enrichment_data["top_ports"][:5]
            prompt += f"- Top Destination Ports: {', '.join([f'{p[0]} ({p[1]} events)' for p in ports])}\n"

        if enrichment_data.get("devices"):
            devices = enrichment_data["devices"]
            prompt += f"- Affected Devices: {', '.join(devices)}\n"

    prompt += """

Based on this security alert, provide:
1. **Summary**: 2-3 sentence executive summary explaining what happened
2. **Risk Assessment**: Rate as Low/Medium/High/Critical with brief reasoning
3. **Recommended Actions**: 3-5 specific actions the SOC team should take (prioritized list)
4. **Confidence**: Your confidence in this assessment (0.0 to 1.0)
5. **MITRE Context**: Brief explanation of the MITRE ATT&CK technique and why it's relevant

Respond with ONLY valid JSON."""

    return prompt
