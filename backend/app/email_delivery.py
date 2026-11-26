"""SMTP delivery for account verification, password recovery and invitations."""
from __future__ import annotations

import html
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import parseaddr
from urllib.parse import urlsplit

from .config import settings


class EmailDeliveryError(RuntimeError):
    """Raised when an action email cannot be safely configured or delivered."""


def email_configuration_error() -> str | None:
    # Development links are permitted only in explicitly local development.
    if settings.email_dev_mode and settings.app_environment == "development":
        return None
    if settings.app_environment == "production" and settings.email_dev_mode:
        return "Development email mode is not allowed in production"

    missing = []
    if not settings.smtp_host:
        missing.append("DATALINEAGE_SMTP_HOST")
    if not settings.smtp_from_email:
        missing.append("DATALINEAGE_SMTP_FROM_EMAIL")
    if bool(settings.smtp_username) != bool(settings.smtp_password):
        return "Configure both DATALINEAGE_SMTP_USERNAME and DATALINEAGE_SMTP_PASSWORD, or leave both empty"
    if settings.smtp_ssl and settings.smtp_starttls:
        return "Configure only one of DATALINEAGE_SMTP_SSL or DATALINEAGE_SMTP_STARTTLS"
    if not 1 <= settings.smtp_port <= 65535:
        return "DATALINEAGE_SMTP_PORT must be between 1 and 65535"
    if missing:
        return "Email delivery is not configured: set " + ", ".join(missing)

    parsed_name, parsed_address = parseaddr(settings.smtp_from_email)
    if not parsed_address or parsed_address.count("@") != 1 or any(ch.isspace() for ch in parsed_address):
        return "DATALINEAGE_SMTP_FROM_EMAIL must be a valid email address"
    if not settings.smtp_host or any(ch.isspace() for ch in settings.smtp_host):
        return "DATALINEAGE_SMTP_HOST must be a valid host name"

    base = urlsplit(settings.public_base_url)
    if base.scheme not in {"http", "https"} or not base.netloc or base.username or base.password:
        return "DATALINEAGE_PUBLIC_BASE_URL must be a valid HTTP or HTTPS URL"
    if settings.app_environment == "production" and base.scheme != "https":
        return "DATALINEAGE_PUBLIC_BASE_URL must use HTTPS in production"
    return None


def _email_html(action_url: str, action: str) -> str:
    safe_app = html.escape(settings.app_name)
    safe_action = html.escape(action)
    safe_url = html.escape(action_url, quote=True)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:28px 12px;background:#f4f6fb;font-family:Arial,Helvetica,sans-serif;color:#172033">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e5e9f2;border-radius:14px;overflow:hidden">
    <tr><td style="padding:26px 30px;background:#111827;color:#ffffff"><div style="font-size:20px;font-weight:700">{safe_app}</div><div style="font-size:12px;color:#cbd5e1;margin-top:5px">Understand your data. Protect what depends on it.</div></td></tr>
    <tr><td style="padding:30px"><h1 style="font-size:21px;margin:0 0 14px;color:#111827">Complete your account action</h1>
      <p style="font-size:15px;line-height:1.6;color:#475569">Use the button below to {safe_action}. This link is time-limited and can only be used once.</p>
      <p style="margin:26px 0"><a href="{safe_url}" style="display:inline-block;padding:13px 20px;background:#4f46e5;color:#ffffff;text-decoration:none;border-radius:9px;font-weight:700">Continue to {safe_app}</a></p>
      <p style="font-size:12px;line-height:1.6;color:#64748b">If the button does not work, copy this link into your browser:<br><a href="{safe_url}" style="color:#4338ca;overflow-wrap:anywhere">{safe_url}</a></p>
      <p style="font-size:12px;color:#64748b;margin-top:24px">If you did not request this, you can safely ignore this email.</p>
    </td></tr>
  </table>
</body></html>"""


def send_action_email(to_email: str, subject: str, action_url: str, action: str) -> None:
    error = email_configuration_error()
    if error:
        raise EmailDeliveryError(error)
    if settings.email_dev_mode and settings.app_environment == "development":
        # The local development flow exposes a one-time URL in the HTTP response, never logs it.
        return

    recipient = parseaddr(to_email)[1]
    parsed_url = urlsplit(action_url)
    if not recipient or recipient.count("@") != 1:
        raise EmailDeliveryError("The recipient email address is invalid.")
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc or parsed_url.username or parsed_url.password:
        raise EmailDeliveryError("The action link is invalid; email was not sent.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        f"Use the link below to {action}. The link expires soon and can only be used once.\n\n"
        f"{action_url}\n\nIf you did not request this, you can ignore this email."
    )
    message.add_alternative(_email_html(action_url, action), subtype="html")

    try:
        context = ssl.create_default_context()
        if settings.smtp_ssl:
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, context=context, timeout=15) as server:
                if settings.smtp_username:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
        else:
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                if settings.smtp_starttls:
                    server.starttls(context=context)
                    server.ehlo()
                if settings.smtp_username:
                    server.login(settings.smtp_username, settings.smtp_password)
                server.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError("Email could not be sent. Check SMTP configuration and try again.") from exc
