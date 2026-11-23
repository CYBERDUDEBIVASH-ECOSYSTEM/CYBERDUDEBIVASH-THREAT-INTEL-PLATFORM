"""Offline P0: Telegram transport never leaks bot secrets or follows redirects."""
from __future__ import annotations

from io import BytesIO
import json
import logging

from scripts import alert_engine


TOKEN = "123456789:TEST_SECRET_TOKEN_DO_NOT_LOG"
CHAT_ID = "-100987654321"


def _messages(caplog):
    return "\n".join(record.getMessage() for record in caplog.records)


def _install_no_network_opener(monkeypatch, fake_open):
    """Stub the HTTPS opener and assert the no-redirect policy is installed."""
    class FakeOpener:
        def open(self, request, *, timeout):
            return fake_open(request, timeout=timeout)

    def fake_build_opener(*handlers):
        assert alert_engine._NoTelegramRedirect in handlers
        return FakeOpener()

    monkeypatch.setattr(alert_engine.urllib.request, "build_opener", fake_build_opener)


def test_transport_exception_never_logs_token_bearing_url_or_chat(monkeypatch, caplog):
    """An upstream error can echo its full request URL, including the bot token."""
    def failed_open(request, *, timeout):
        assert request.get_method() == "POST"
        assert timeout == 15
        assert request.full_url.startswith("https://api.telegram.org/bot")
        raise RuntimeError(f"upstream: {request.full_url} chat_id={CHAT_ID}")

    _install_no_network_opener(monkeypatch, failed_open)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False

    emitted = _messages(caplog)
    assert "RuntimeError" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
    assert "api.telegram.org/bot" not in emitted


def test_untrusted_telegram_error_description_is_not_logged(monkeypatch, caplog):
    """A Telegram error JSON body may echo the token URL and chat ID."""
    def fake_open(request, *, timeout):
        description = f"bad request to {request.full_url}: chat_id={CHAT_ID}"
        return BytesIO(json.dumps({"ok": False, "description": description}).encode())

    _install_no_network_opener(monkeypatch, fake_open)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False

    emitted = _messages(caplog)
    assert "rejected alert" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
    assert "api.telegram.org/bot" not in emitted


def test_successful_delivery_does_not_log_customer_chat(monkeypatch, caplog):
    def fake_open(request, *, timeout):
        return BytesIO(b'{"ok":true}')

    _install_no_network_opener(monkeypatch, fake_open)
    with caplog.at_level(logging.INFO, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is True

    emitted = _messages(caplog)
    assert "Telegram alert accepted" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted


def test_redirect_policy_refuses_cross_origin_and_https_downgrade():
    """Redirect responses can never forward a credential-bearing URL."""
    guard = alert_engine._NoTelegramRedirect()
    for location in (
        "http://api.telegram.org/unsafe",
        "https://different-host.example/collect",
        "https://api.telegram.org/moved",
    ):
        assert guard.redirect_request(None, None, 302, "redirect", {}, location) is None


def test_non_https_telegram_origin_fails_closed_without_transport(monkeypatch, caplog):
    def must_not_build_opener(*_handlers):
        raise AssertionError("invalid origin must never initialize a network opener")

    monkeypatch.setattr(alert_engine, "TG_API_BASE", "http://not-telegram.example/bot{token}/{method}")
    monkeypatch.setattr(alert_engine.urllib.request, "build_opener", must_not_build_opener)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False
    emitted = _messages(caplog)
    assert "origin policy rejected" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted


def test_transport_setup_failure_never_raises_or_leaks_credentials(monkeypatch, caplog):
    """An opener/proxy setup failure must be fail-closed and safe to log."""
    def fail_build(*handlers):
        assert alert_engine._NoTelegramRedirect in handlers
        raise RuntimeError(f"secret={TOKEN} chat={CHAT_ID}")

    monkeypatch.setattr(alert_engine.urllib.request, "build_opener", fail_build)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False
    emitted = _messages(caplog)
    assert "transport initialization failed: RuntimeError" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
