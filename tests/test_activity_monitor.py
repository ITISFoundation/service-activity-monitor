import psutil
import pytest
import requests
import time

from typing import Callable, List, Dict, TYPE_CHECKING
from pytest_mock import MockFixture
from tenacity import Retrying
from tenacity.stop import stop_after_delay
from tenacity.wait import wait_fixed
from conftest import _ActivityGenerator
from unittest.mock import Mock


if TYPE_CHECKING:
    from ..docker import activity_monitor
else:
    from _import_utils import allow_imports

    allow_imports()
    import activity_monitor


@pytest.fixture
def mock__get_sibling_processes(
    mocker: MockFixture,
) -> Callable[[List[int]], List[psutil.Process]]:
    def _get_processes(pids: List[int]) -> List[psutil.Process]:
        no_access_pid = psutil.Process(1)   # ensure it does not error out
        results = [no_access_pid]
        for pid in pids:
            proc = psutil.Process(pid)
            assert proc.status()
            results.append(proc)
        return results

    def _(pids: List[int]) -> None:
        mocker.patch(
            "activity_monitor._get_sibling_processes", return_value=_get_processes(pids)
        )

    return _


@pytest.fixture
def metrics_manager() -> activity_monitor.MetricsManager:
    return activity_monitor.MetricsManager()


def test_cpu_usage_monitor_not_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.CPUUsageMonitor(
        1, metrics_manager, busy_threshold=5
    ) as cpu_usage_monitor:
        for attempt in Retrying(
            stop=stop_after_delay(5), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                assert cpu_usage_monitor.total_cpu_usage == 0
                assert cpu_usage_monitor.is_busy is False


def test_cpu_usage_monitor_still_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=False, cpu=True, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.CPUUsageMonitor(
        0.5, metrics_manager, busy_threshold=5
    ) as cpu_usage_monitor:
        # wait for monitor to trigger
        time.sleep(1)

        # must still result busy
        assert cpu_usage_monitor.total_cpu_usage > 0
        assert cpu_usage_monitor.is_busy is True


def test_disk_usage_monitor_not_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.DiskUsageMonitor(
        0.5, metrics_manager, read_usage_threshold=0, write_usage_threshold=0
    ) as disk_usage_monitor:
        for attempt in Retrying(
            stop=stop_after_delay(5), wait=wait_fixed(0.1), reraise=True
        ):
            with attempt:
                read_bytes = disk_usage_monitor.total_bytes_read
                write_bytes = disk_usage_monitor.total_bytes_write
                assert read_bytes == 0
                assert write_bytes == 0
                assert disk_usage_monitor.is_busy is False


def test_disk_usage_monitor_still_busy(
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=True)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.DiskUsageMonitor(
        0.5, metrics_manager, read_usage_threshold=0, write_usage_threshold=0
    ) as disk_usage_monitor:
        # wait for monitor to trigger
        time.sleep(1)
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


def test_network_usage_monitor_not_busy(
    mock_no_network_activity: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.NetworkUsageMonitor(
        0.5, metrics_manager, received_usage_threshold=0, sent_usage_threshold=0
    ) as network_usage_monitor:
        for attempt in Retrying(
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


def test_network_usage_monitor_still_busy(
    mock_network_monitor_exclude_interfaces: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    metrics_manager: activity_monitor.MetricsManager,
):
    activity_generator = create_activity_generator(network=True, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    with activity_monitor.NetworkUsageMonitor(
        0.5, metrics_manager, received_usage_threshold=0, sent_usage_threshold=0
    ) as network_usage_monitor:
        # wait for monitor to trigger
        time.sleep(1)

        assert network_usage_monitor.bytes_received > 0
        assert network_usage_monitor.bytes_sent > 0
        assert network_usage_monitor.is_busy is True


@pytest.mark.parametrize("are_kernels_busy", [True, False])
def test_jupyter_kernel_monitor(
    mock_jupyter_kernel_monitor: None,
    are_kernels_busy: bool,
    metrics_manager: activity_monitor.MetricsManager,
):
    kernel_monitor = activity_monitor.JupyterKernelMonitor(1, metrics_manager)
    kernel_monitor._update_kernels_activity()
    assert kernel_monitor.are_kernels_busy is are_kernels_busy


@pytest.mark.parametrize("are_kernels_busy", [False])
def test_http_server_ok(http_server: None, server_url: str):
    result = requests.get(f"{server_url}/activity", timeout=1)
    assert result.status_code == 200


@pytest.fixture
def mock_activity_manager_config(mocker: MockFixture) -> None:
    mocker.patch("activity_monitor.MONITOR_INTERVAL_S", 1)
    mocker.patch("activity_monitor.JUPYTER_NOTEBOOK_KERNEL_CHECK_INTERVAL_S", 1)


@pytest.mark.parametrize("are_kernels_busy", [False])
def test_activity_monitor_becomes_not_busy(
    mock_activity_manager_config: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    http_server: None,
    server_url: str,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    for attempt in Retrying(
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


@pytest.mark.parametrize("are_kernels_busy", [False])
def test_metrics_endpoint(
    mock_activity_manager_config: None,
    socket_server: None,
    mock__get_sibling_processes: Callable[[List[int]], List[psutil.Process]],
    create_activity_generator: Callable[[bool, bool, bool], _ActivityGenerator],
    http_server: None,
    server_url: str,
):
    activity_generator = create_activity_generator(network=False, cpu=False, disk=False)
    mock__get_sibling_processes([activity_generator.get_pid()])

    result = requests.get(f"{server_url}/metrics", timeout=1)
    assert result.status_code == 200
    assert result.text.count("network_bytes_received_total") == 3
    assert result.text.count("network_bytes_sent_total") == 3


def test_metric_manager(metrics_manager: activity_monitor.MetricsManager):
    metrics_manager.register_metric("metric_name", help="metric_help", initial_value=0)

    total_count = 0
    for i in range(10):
        total_count += i

        metrics_manager.inc_metric("metric_name", i)
        formatted_metrics = metrics_manager.format_metrics()
        assert "# HELP metric_name metric_help" in formatted_metrics
        assert "# TYPE metric_name counter" in formatted_metrics
        assert f"metric_name {total_count}" in formatted_metrics


def test_regression_jypyter_not_running():
    monitor = activity_monitor.JupyterKernelMonitor(10, Mock())

    monitor._update_kernels_activity()
    assert monitor.are_kernels_busy is False
