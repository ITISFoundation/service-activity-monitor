import pytest
import json
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from ..docker import activity
else:
    from _import_utils import allow_imports

    allow_imports()
    import activity


@pytest.fixture
def are_kernels_busy() -> bool:
    return True


def test_activity(http_server: None, capfd: pytest.CaptureFixture):
    activity.main()
    capture_result = capfd.readouterr()
    assert json.loads(capture_result.out) == {"seconds_inactive": 0}
