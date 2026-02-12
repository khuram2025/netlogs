"""
Notification service - sends alert notifications via email, Telegram, webhook.
"""

import json
import logging
import smtplib
import ssl
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Optional

import httpx

logger = logging.getLogger(__name__)

# Rate limiting: track recent sends per channel
_recent_sends: Dict[int, list] = {}  # channel_id -> [timestamps]
MAX_PER_MINUTE = 10


def _rate_limited(channel_id: int) -> bool:
    """Check if channel has exceeded rate limit (10/minute)."""
    now = datetime.now(timezone.utc)
    if channel_id not in _recent_sends:
        _recent_sends[channel_id] = []

    # Remove sends older than 60 seconds
    _recent_sends[channel_id] = [
        t for t in _recent_sends[channel_id]
        if (now - t).total_seconds() < 60
    ]

    if len(_recent_sends[channel_id]) >= MAX_PER_MINUTE:
        return True

    _recent_sends[channel_id].append(now)
    return False


def _severity_emoji(severity: str) -> str:
    """Get emoji for alert severity."""
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get(severity.lower(), "⚪")


async def send_notification(channel, alert, rule=None) -> bool:
    """Send a notification through the specified channel.

    Args:
        channel: NotificationChannel model instance
        alert: Alert model instance
        rule: Optional AlertRule model instance

    Returns:
        True if sent successfully, False otherwise
    """
    if _rate_limited(channel.id):
        logger.warning(f"Rate limit exceeded for channel '{channel.name}' (id={channel.id})")
        return False

    try:
        if channel.channel_type == "email":
            return await _send_email(channel, alert, rule)
        elif channel.channel_type == "telegram":
            return await _send_telegram(channel, alert, rule)
        elif channel.channel_type == "webhook":
            return await _send_webhook(channel, alert, rule)
        else:
            logger.error(f"Unknown channel type: {channel.channel_type}")
            return False
    except Exception as e:
        logger.error(f"Notification failed for channel '{channel.name}': {e}")
        return False


async def _send_email(channel, alert, rule=None) -> bool:
    """Send alert notification via email."""
    config = channel.config
    smtp_host = config.get("smtp_host", "localhost")
    smtp_port = config.get("smtp_port", 587)
    username = config.get("username", "")
    password = config.get("password", "")
    from_addr = config.get("from_addr", "netlogs@localhost")
    to_addrs = config.get("to_addrs", [])
    use_tls = config.get("use_tls", True)

    if not to_addrs:
        logger.error("No recipient addresses configured for email channel")
        return False

    severity = alert.severity.upper()
    subject = f"[NetLogs {severity}] {alert.title}"

    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 24px;">
            <h2 style="color: white; margin-top: 0;">
                {_severity_emoji(alert.severity)} Alert: {alert.title}
            </h2>
            <table style="width: 100%; border-collapse: collapse; margin: 16px 0;">
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: #94a3b8;">Severity</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: white; font-weight: bold;">{severity}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: #94a3b8;">Rule</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;">{rule.name if rule else 'N/A'}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border-bottom: 1px solid #334155; color: #94a3b8;">Time</td>
                    <td style="padding: 8px; border-bottom: 1px solid #334155;">{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S UTC') if alert.triggered_at else 'N/A'}</td>
                </tr>
            </table>
            {f'<p style="color: #94a3b8;">{alert.description}</p>' if alert.description else ''}
            <hr style="border-color: #334155;">
            <p style="font-size: 12px; color: #64748b;">
                This is an automated alert from NetLogs SIEM Platform.
            </p>
        </div>
    </body>
    </html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg.attach(MIMEText(html_body, "html"))

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls(context=context)
                if username and password:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if username and password:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())

        logger.info(f"Email sent to {to_addrs} for alert '{alert.title}'")
        return True
    except Exception as e:
        logger.error(f"Email send failed: {e}")
        return False


async def _send_telegram(channel, alert, rule=None) -> bool:
    """Send alert notification via Telegram bot."""
    config = channel.config
    bot_token = config.get("bot_token", "")
    chat_id = config.get("chat_id", "")

    if not bot_token or not chat_id:
        logger.error("Telegram bot_token or chat_id not configured")
        return False

    emoji = _severity_emoji(alert.severity)
    text = (
        f"{emoji} *NetLogs Alert: {alert.severity.upper()}*\n\n"
        f"*{alert.title}*\n"
    )
    if alert.description:
        text += f"\n{alert.description}\n"
    if rule:
        text += f"\n📋 Rule: {rule.name}"
    if alert.triggered_at:
        text += f"\n🕐 {alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}"

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            })
            if resp.status_code == 200:
                logger.info(f"Telegram message sent to chat {chat_id} for alert '{alert.title}'")
                return True
            else:
                logger.error(f"Telegram API error: {resp.status_code} - {resp.text}")
                return False
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False


async def _send_webhook(channel, alert, rule=None) -> bool:
    """Send alert notification via webhook."""
    config = channel.config
    url = config.get("url", "")
    method = config.get("method", "POST").upper()
    headers = config.get("headers", {})
    max_retries = 3

    if not url:
        logger.error("Webhook URL not configured")
        return False

    payload = {
        "alert_id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "description": alert.description,
        "status": alert.status,
        "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
        "details": alert.details,
        "rule": {
            "id": rule.id,
            "name": rule.name,
            "category": rule.category,
        } if rule else None,
        "source": "netlogs",
    }

    headers.setdefault("Content-Type", "application/json")

    for attempt in range(1, max_retries + 1):
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                if method == "POST":
                    resp = await client.post(url, json=payload, headers=headers)
                elif method == "PUT":
                    resp = await client.put(url, json=payload, headers=headers)
                else:
                    resp = await client.post(url, json=payload, headers=headers)

                if 200 <= resp.status_code < 300:
                    logger.info(f"Webhook sent to {url} for alert '{alert.title}'")
                    return True
                else:
                    logger.warning(f"Webhook {url} returned {resp.status_code} (attempt {attempt}/{max_retries})")

        except Exception as e:
            logger.warning(f"Webhook {url} failed (attempt {attempt}/{max_retries}): {e}")

    logger.error(f"Webhook {url} failed after {max_retries} attempts")
    return False


async def send_test_notification(channel) -> Dict:
    """Send a test notification through the specified channel.

    Returns dict with 'success' and 'message' keys.
    """

    class FakeAlert:
        id = 0
        title = "Test Alert - NetLogs Notification Test"
        severity = "info"
        description = "This is a test notification from NetLogs SIEM Platform. If you received this, your notification channel is configured correctly."
        status = "new"
        triggered_at = datetime.now(timezone.utc)
        details = {"test": True}

    class FakeRule:
        id = 0
        name = "Test Rule"
        category = "test"

    try:
        result = await send_notification(channel, FakeAlert(), FakeRule())
        if result:
            return {"success": True, "message": "Test notification sent successfully"}
        else:
            return {"success": False, "message": "Failed to send test notification"}
    except Exception as e:
        return {"success": False, "message": str(e)}
