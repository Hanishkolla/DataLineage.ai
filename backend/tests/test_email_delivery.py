from email.message import EmailMessage

import pytest

from app.config import settings
from app.email_delivery import EmailDeliveryError, email_configuration_error, send_action_email


@pytest.fixture
def smtp_settings(monkeypatch):
    monkeypatch.setattr(settings, "app_environment", "test")
    monkeypatch.setattr(settings, "email_dev_mode", False)
    monkeypatch.setattr(settings, "app_name", "DataLineage AI")
    monkeypatch.setattr(settings, "public_base_url", "https://app.example.test")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_username", "mailer@example.test")
    monkeypatch.setattr(settings, "smtp_password", "test-password")
    monkeypatch.setattr(settings, "smtp_from_email", "DataLineage AI <noreply@example.test>")
    monkeypatch.setattr(settings, "smtp_starttls", True)
    monkeypatch.setattr(settings, "smtp_ssl", False)


def test_email_configuration_rejects_incomplete_auth_pair(smtp_settings, monkeypatch):
    monkeypatch.setattr(settings, "smtp_password", "")
    assert "Configure both" in email_configuration_error()


def test_email_configuration_rejects_conflicting_tls(smtp_settings, monkeypatch):
    monkeypatch.setattr(settings, "smtp_ssl", True)
    assert "only one" in email_configuration_error()


def test_email_configuration_rejects_invalid_sender(smtp_settings, monkeypatch):
    monkeypatch.setattr(settings, "smtp_from_email", "not-an-email")
    assert "valid email" in email_configuration_error()


def test_send_action_email_builds_plain_text_and_html_and_uses_starttls(smtp_settings, monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("smtp.example.test", 587, 15)
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def ehlo(self): sent["ehlo"] = sent.get("ehlo", 0) + 1
        def starttls(self, context): sent["tls"] = context
        def login(self, username, password): sent["login"] = (username, password)
        def send_message(self, message): sent["message"] = message

    monkeypatch.setattr("app.email_delivery.smtplib.SMTP", FakeSMTP)
    send_action_email("person@example.test", "Verify your account", "https://app.example.test/#verify_token=abc", "verify your email")

    message = sent["message"]
    assert isinstance(message, EmailMessage)
    assert message["To"] == "person@example.test"
    assert message.get_content_type() == "multipart/alternative"
    parts = list(message.iter_parts())
    assert [part.get_content_type() for part in parts] == ["text/plain", "text/html"]
    assert "verify your email" in parts[0].get_content()
    assert "DataLineage AI" in parts[1].get_content()
    assert "https://app.example.test/#verify_token=abc" in parts[1].get_content()
    assert sent["ehlo"] == 2
    assert sent["login"] == ("mailer@example.test", "test-password")


def test_send_action_email_escapes_html_in_action_and_url(smtp_settings, monkeypatch):
    captured = {}

    class FakeSMTP:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def ehlo(self): pass
        def starttls(self, context): pass
        def login(self, *args): pass
        def send_message(self, message): captured["message"] = message

    monkeypatch.setattr("app.email_delivery.smtplib.SMTP", FakeSMTP)
    send_action_email("person@example.test", "Subject", "https://app.example.test/action?x=1&y=2", "<verify>")
    html_part = list(captured["message"].iter_parts())[1].get_content()
    assert "&amp;" in html_part
    assert "&lt;verify&gt;" in html_part


def test_send_action_email_rejects_unsafe_action_url(smtp_settings):
    with pytest.raises(EmailDeliveryError, match="action link is invalid"):
        send_action_email("person@example.test", "Subject", "javascript:alert(1)", "verify")


def test_dev_mode_does_not_open_smtp(monkeypatch):
    monkeypatch.setattr(settings, "app_environment", "development")
    monkeypatch.setattr(settings, "email_dev_mode", True)
    def unexpected(*args, **kwargs):
        raise AssertionError("SMTP must not be used in local development-link mode")
    monkeypatch.setattr("app.email_delivery.smtplib.SMTP", unexpected)
    send_action_email("person@example.test", "Subject", "http://127.0.0.1:8000/#verify_token=abc", "verify")
