"""Offline P0: Telegram transport diagnostics never expose bot secrets or chat IDs."""
from __future__ import annotations

from io import BytesIO
import json
import logging

from scripts import alert_engine


TOKEN = "123456789:TEST_SECRET_TOKEN_DO_NOT_LOG"
CHAT_ID = "-100987654321"


def _messages(caplog):
    return "\\n".join(record.getMessage() for record in caplog.records)


def test_transport_exception_never_logs_token_bearing_url_or_chat(monkeypatch, caplog):
    """An urllib error may include its full Telegram URL; never log str(error)."""
    def failed_open(request, *, timeout):
        assert request.get_method() == "POST"
        assert timeout == 15
        raise RuntimeError(f"upstream: {request.full_url} chat_id={CHAT_ID}")

    monkeypatch.setattr(alert_engine.urllib.request, "urlopen", failed_open)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False

    emitted = _messages(caplog)
    assert "RuntimeError" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
    assert "api.telegram.org/bot" not in emitted


def test_untrusted_telegram_error_description_is_not_logged(monkeypatch, caplog):
    """A Telegram JSON error may echo the token URL and other private inputs."""
    def fake_open(request, *, timeout):
        description = f"bad request to {request.full_url}: chat_id={CHAT_ID}"
        return BytesIO(json.dumps({"ok": False, "description": description}).encode())

    monkeypatch.setattr(alert_engine.urllib.request, "urlopen", fake_open)
    with caplog.at_level(logging.DEBUG, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is False

    emitted = _messages(caplog)
    assert "rejected alert" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
    assert "api.telegram.org/bot" not in emitted


def test_successful_telegram_delivery_does_not_log_customer_chat(monkeypatch, caplog):
    def fake_open(request, *, timeout):
        return BytesIO(b'{"ok":true}')

    monkeypatch.setattr(alert_engine.urllib.request, "urlopen", fake_open)
    with caplog.at_level(logging.INFO, logger=alert_engine.logger.name):
        assert alert_engine._tg_send(TOKEN, CHAT_ID, "synthetic", max_retries=1) is True

    emitted = _messages(caplog)
    assert "Telegram alert accepted" in emitted
    assert TOKEN not in emitted
    assert CHAT_ID not in emitted
