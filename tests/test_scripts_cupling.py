import pytest
from importlib import reload

from typing import TYPE_CHECKING

if not TYPE_CHECKING:
    from _import_utils import allow_imports

    allow_imports()


def test_same_listen_port(monkeypatch: pytest.MonkeyPatch):
    import activity
    import activity_monitor

    assert activity_monitor.LISTEN_PORT == activity.LISTEN_PORT

    mocked_port = 314
    monkeypatch.setenv("ACTIVITY_MONITOR_LISTEN_PORT", f"{mocked_port}")

    reload(activity)
    reload(activity_monitor)

    assert activity_monitor.LISTEN_PORT == mocked_port
    assert activity.LISTEN_PORT == mocked_port
