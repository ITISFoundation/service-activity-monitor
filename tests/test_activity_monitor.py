import asyncio
import json
import psutil
import pytest
import pytest_asyncio
import requests
import requests_mock
import threading
import time

from typing import Callable, Final, Iterable, TYPE_CHECKING
from pytest_mock import MockFixture
from tenacity import AsyncRetrying
from tenacity.stop import stop_after_delay
from tenacity.wait import wait_fixed
from conftest import _ActivityGenerator


if TYPE_CHECKING:
    from ..docker import activity_monitor
else:
    from _import_utils import allow_imports

    allow_imports()
    import activity_monitor

pytestmark = pytest.mark.asyncio


@pytest.fixture
def mock__get_sibling_processes(
    mocker: MockFixture,
) -> Callable[[list[int]], list[psutil.Process]]:
    def _get_processes(pids: list[int]) -> list[psutil.Process]:
        results = []
        for pid in pids:
            proc = psutil.Process(pid)
            assert proc.status()
            results.append(proc)
        return results

    def _(pids: list[int]) -> None:
        mocker.patch(
            "activity_monitor._get_sibling_processes", return_value=_get_processes(pids)
        )

    return _


async def test_cpu_usage_monitor_not_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.CPUUsageMonitor(1, busy_threshold=5) as cpu_usage_monitor:
        async for attempt in AsyncRetrying(
            stop=stop_after_delay(5), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                assert cpu_usage_monitor.total_cpu_usage == 0
                assert cpu_usage_monitor.is_busy is False


async def test_cpu_usage_monitor_still_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=False, cpu=True, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.CPUUsageMonitor(0.5, busy_threshold=5) as cpu_usage_monitor:
        # wait for monitor to trigger
        await asyncio.sleep(1)

        # must still result busy
        assert cpu_usage_monitor.total_cpu_usage > 0
        assert cpu_usage_monitor.is_busy is True


async def test_disk_usage_monitor_not_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.DiskUsageMonitor(
        0.5, read_usage_threshold=0, write_usage_threshold=0
    ) as disk_usage_monitor:
        async for attempt in AsyncRetrying(
            stop=stop_after_delay(5), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                read_bytes = disk_usage_monitor.total_bytes_read
                write_bytes = disk_usage_monitor.total_bytes_write
                assert read_bytes == 0
                assert write_bytes == 0
                assert disk_usage_monitor.is_busy is False


async def test_disk_usage_monitor_still_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=True)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.DiskUsageMonitor(
        0.5, read_usage_threshold=0, write_usage_threshold=0
    ) as disk_usage_monitor:
        # wait for monitor to trigger
        await asyncio.sleep(1)
        write_bytes = disk_usage_monitor.total_bytes_write
        # NOTE: due to os disk cache reading is not reliable not testing it
        assert write_bytes > 0

        # must still result busy
        assert disk_usage_monitor.is_busy is True


@pytest.fixture
def mock_no_network_activity(mocker: MockFixture) -> None:
    mocker.patch(
        "activity_monitor.NetworkUsageMonitor._sample_total_network_usage",
        side_effect=lambda: (time.time(), 0, 0),
    )


async def test_network_usage_monitor_not_busy(
    mock_no_network_activity: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.NetworkUsageMonitor(
        0.5, received_usage_threshold=0, sent_usage_threshold=0
    ) as network_usage_monitor:
        async for attempt in AsyncRetrying(
            stop=stop_after_delay(5), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                assert network_usage_monitor.bytes_received == 0
                assert network_usage_monitor.bytes_sent == 0
                assert network_usage_monitor.is_busy is False


@pytest.fixture
def mock_network_monitor_exclude_interfaces(mocker: MockFixture) -> None:
    mocker.patch("activity_monitor.NetworkUsageMonitor._EXCLUDE_INTERFACES", new=set())
    assert activity_monitor.NetworkUsageMonitor._EXCLUDE_INTERFACES == set()


async def test_network_usage_monitor_still_busy(
    mock_network_monitor_exclude_interfaces: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
):
    activity_generator = create_activity_generator(network=True, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.NetworkUsageMonitor(
        0.5, received_usage_threshold=0, sent_usage_threshold=0
    ) as network_usage_monitor:
        # wait for monitor to trigger
        await asyncio.sleep(1)

        assert network_usage_monitor.bytes_received > 0
        assert network_usage_monitor.bytes_sent > 0
        assert network_usage_monitor.is_busy is True


@pytest.fixture
def mock_jupyter_kernel_monitor(are_kernels_busy: bool) -> Iterable[None]:
    with requests_mock.Mocker(real_http=True) as m:
        m.get("http://localhost:8888/api/kernels", text=json.dumps([{"id": "atest1"}]))
        m.get(
            "http://localhost:8888/api/kernels/atest1",
            text=json.dumps(
                {"execution_state": "running" if are_kernels_busy else "idle"}
            ),
        )
        yield


@pytest.mark.parametrize("are_kernels_busy", [True, False])
async def test_jupyter_kernel_monitor(
    mock_jupyter_kernel_monitor: None, are_kernels_busy: bool
):
    kernel_monitor = activity_monitor.JupyterKernelMonitor(1)
    kernel_monitor._update_kernels_activity()
    assert kernel_monitor.are_kernels_busy is are_kernels_busy


@pytest_asyncio.fixture
async def server_url() -> str:
    return f"http://localhost:{activity_monitor.LISTEN_PORT}"


@pytest_asyncio.fixture
async def http_server(mock_jupyter_kernel_monitor: None, server_url: str) -> None:
    server = activity_monitor.make_server(activity_monitor.LISTEN_PORT)

    def _run_server_worker() -> None:
        server.serve_forever()

    thread = threading.Thread(target=_run_server_worker, daemon=True)
    thread.start()

    # ensure server is running
    async for attempt in AsyncRetrying(
        stop=stop_after_delay(3), wait=wait_fixed(0.1), reraise=True
    ):
        with attempt:
            result = requests.get(f"{server_url}/activity", timeout=1)
            assert result.status_code == 200, result.text

    yield None

    server.shutdown()
    server.server_close()

    with pytest.raises(requests.exceptions.RequestException):
        requests.get(f"{server_url}/activity", timeout=1)


@pytest.mark.parametrize("are_kernels_busy", [False])
async def test_http_server_ok(http_server: None, server_url: str):
    result = requests.get(f"{server_url}/activity", timeout=1)
    assert result.status_code == 200


_BIG_THRESHOLD: Final[int] = int(1e10)


@pytest.fixture
def mock_activity_manager_config(mocker: MockFixture) -> None:
    mocker.patch("activity_monitor.CHECK_INTERVAL_S", 1)
    mocker.patch("activity_monitor.KERNEL_CHECK_INTERVAL_S", 1)

    mocker.patch(
        "activity_monitor.BUSY_USAGE_THRESHOLD_NETWORK_RECEIVED", _BIG_THRESHOLD
    )
    mocker.patch("activity_monitor.BUSY_USAGE_THRESHOLD_NETWORK_SENT", _BIG_THRESHOLD)


@pytest.mark.parametrize("are_kernels_busy", [False])
async def test_activity_monitor_becomes_not_busy(
    mock_activity_manager_config: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[list[int]], list[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    http_server: None,
    server_url: str,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    async for attempt in AsyncRetrying(
        stop=stop_after_delay(10), wait=wait_fixed(0.1), reraise=True
    ):
        with attempt:
            # check that all become not busy
            result = requests.get(f"{server_url}/debug", timeout=1)
            assert result.status_code == 200
            debug_response = result.json()
            assert debug_response["cpu_usage"]["is_busy"] is False
            assert debug_response["disk_usage"]["is_busy"] is False
            assert debug_response["kernel_monitor"]["is_busy"] is False
            assert debug_response["network_usage"]["is_busy"] is False

            result = requests.get(f"{server_url}/activity", timeout=1)
            assert result.status_code == 200
            response = result.json()
            assert response["seconds_inactive"] > 0
