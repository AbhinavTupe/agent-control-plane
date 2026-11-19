import logging

import pytest

from server.main import PollingAccessLogFilter


@pytest.mark.parametrize(
    ("method", "path", "status_code", "should_keep"),
    [
        ("GET", "/auth/status", 200, False),
        ("GET", "/healthz", 200, False),
        ("GET", "/auth/status", 401, True),
        ("GET", "/healthz", 401, True),
        ("POST", "/hook/copilot", 401, True),
        ("GET", "/approvals", 200, True),
    ],
)
def test_polling_access_log_filter(method, path, status_code, should_keep):
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:123", method, path, "1.1", status_code),
        None,
    )

    assert PollingAccessLogFilter().filter(record) is should_keep
