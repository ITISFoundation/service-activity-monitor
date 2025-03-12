import json
import logging
import psutil
import requests
import time
import os

from abc import abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple, Set, Union


_TB: int = 1024 * 1024 * 1024 * 1024
_ENV_VAR_PREFIX: str = "ACTIVITY_MONITOR"


def _read_env(var_name: str, default: Any, base_type: type) -> Any:
    return base_type(os.environ.get(var_name, default))


# NOTE: using high thresholds to make service by default
# considered inactive.
# If the service owner does not change these, by lowering
# them to an adequate value the service will always be shut
# down as soon as the inactivity period is detected.
_THRESHOLD_PREFIX: str = f"{_ENV_VAR_PREFIX}_BUSY_THRESHOLD"
BUSY_USAGE_THRESHOLD_CPU: float = _read_env(
    f"{_THRESHOLD_PREFIX}_CPU_PERCENT", 1000, float
)
BUSY_USAGE_THRESHOLD_DISK_READ: int = _read_env(
    f"{_THRESHOLD_PREFIX}_DISK_READ_BPS", 1 * _TB, int
)
BUSY_USAGE_THRESHOLD_DISK_WRITE: int = _read_env(
    f"{_THRESHOLD_PREFIX}_DISK_WRITE_BPS", 1 * _TB, int
)
BUSY_USAGE_THRESHOLD_NETWORK_RECEIVED: int = _read_env(
    f"{_THRESHOLD_PREFIX}_NETWORK_RECEIVE_BPS", 1 * _TB, int
)
BUSY_USAGE_THRESHOLD_NETWORK_SENT: int = _read_env(
    f"{_THRESHOLD_PREFIX}_NETWORK_SENT_BPS", 1 * _TB, int
)

# NOTE: set the following flags to disable a specific monitor
DISABLE_JUPYTER_KERNEL_MONITOR: bool = (
    os.environ.get(f"{_ENV_VAR_PREFIX}_DISABLE_JUPYTER_KERNEL_MONITOR", None)
    is not None
)
DISABLE_CPU_USAGE_MONITOR: bool = (
    os.environ.get(f"{_ENV_VAR_PREFIX}_DISABLE_CPU_USAGE_MONITOR", None) is not None
)
DISABLE_DISK_USAGE_MONITOR: bool = (
    os.environ.get(f"{_ENV_VAR_PREFIX}_DISABLE_DISK_USAGE_MONITOR", None) is not None
)
DISABLE_NETWORK_USAGE_MONITOR: bool = (
    os.environ.get(f"{_ENV_VAR_PREFIX}_DISABLE_NETWORK_USAGE_MONITOR", None) is not None
)

# NOTE: Other configuration options
JUPYTER_NOTEBOOK_BASE_URL: str = os.environ.get(
    f"{_ENV_VAR_PREFIX}_JUPYTER_NOTEBOOK_BASE_URL", "http://localhost:8888"
)
JUPYTER_NOTEBOOK_KERNEL_CHECK_INTERVAL_S: float = float(
    os.environ.get(f"{_ENV_VAR_PREFIX}_JUPYTER_NOTEBOOK_KERNEL_CHECK_INTERVAL_S", 5)
)
MONITOR_INTERVAL_S: float = float(
    os.environ.get(f"{_ENV_VAR_PREFIX}_MONITOR_INTERVAL_S", 1)
)
LISTEN_PORT: int = int(os.environ.get(f"{_ENV_VAR_PREFIX}_LISTEN_PORT", 19597))

# Internals
_THREAD_EXECUTOR_WORKERS: int = 10

_logger = logging.getLogger(__name__)


############### Utils


_METRICS_COUNTER_TEMPLATE: str = """
# HELP {name} {help}
# TYPE {name} counter
{name} {value}
"""


MetricEntry = Dict[str, Union[str, int]]


class MetricsManager:
    def __init__(self) -> None:
        self._metrics: Dict[str, MetricEntry] = {}

    def register_metric(
        self, name: str, *, help: str, initial_value: Union[int, float]
    ) -> None:
        self._metrics[name] = {"help": help, "value": initial_value}

    def inc_metric(self, name: str, value: Union[int, float]) -> None:
        self._metrics[name]["value"] += value

    def format_metrics(self) -> str:
        result = ""

        for name, metric_entry in self._metrics.items():
            entry = _METRICS_COUNTER_TEMPLATE.format(
                name=name, help=metric_entry["help"], value=metric_entry["value"]
            )
            result += f"{entry}"

        return result


class AbstractIsBusyMonitor:
    def __init__(self, poll_interval: float, metrics: MetricsManager) -> None:
        self._poll_interval: float = poll_interval
        self._keep_running: bool = True
        self._thread: Thread | None = None

        self.metrics = metrics
        self.is_busy: bool = True
        self.thread_executor = ThreadPoolExecutor(max_workers=_THREAD_EXECUTOR_WORKERS)

    @abstractmethod
    def _check_if_busy(self) -> bool:
        """Must be user defined and returns if current
        metric is to be considered busy

        Returns:
            bool: True if considered busy
        """

    @abstractmethod
    def get_debug_entry(self) -> Dict[str, Any]:
        """Information about the current internal state to be exported

        Returns:
            dict[str, Any]: json serializable data
        """

    def _worker(self) -> None:
        while self._keep_running:
            try:
                self.is_busy = self._check_if_busy()
            except Exception as e:
                _logger.exception("Failed to check if busy")
            time.sleep(self._poll_interval)

    def start(self) -> None:
        self._thread = Thread(
            target=self._worker,
            daemon=True,
            name=f"{self.__class__.__name__}_check_busy",
        )
        self._thread.start()

    def stop(self) -> None:
        self._keep_running = False
        if self._thread:
            self._thread.join()
        self.thread_executor.shutdown(wait=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()


def __get_children_processes_recursive(pid) -> List[psutil.Process]:
    try:
        return psutil.Process(pid).children(recursive=True)
    except psutil.NoSuchProcess:
        return []


def _get_sibling_processes() -> List[psutil.Process]:
    # Returns the CPU usage of all processes except this one.
    # ASSUMPTIONS:
    # - `CURRENT_PROC` is a child of root process
    # - `CURRENT_PROC` does not create any child processes
    #
    # It looks for its brothers (and their children) p1 to pN in order
    # to compute real CPU usage.
    #   - CURRENT_PROC
    #   - p1
    #   ...
    #   - pN
    current_process = psutil.Process()
    parent_pid = current_process.ppid()
    all_children = __get_children_processes_recursive(parent_pid)
    return [c for c in all_children if c.pid != current_process.pid]


############### Monitors


class JupyterKernelMonitor(AbstractIsBusyMonitor):
    def __init__(self, poll_interval: float, metrics: MetricsManager) -> None:
        super().__init__(poll_interval=poll_interval, metrics=metrics)
        self.are_kernels_busy: bool = False

    def _get(self, path: str) -> dict:
        r = requests.get(
            f"{JUPYTER_NOTEBOOK_BASE_URL}{path}",
            headers={"accept": "application/json"},
            timeout=2,
        )
        return r.json()

    def _update_kernels_activity(self) -> None:
        try:
            json_response = self._get("/api/kernels")
        except Exception:  # pylint:disable=broad-exception-caught
            self.are_kernels_busy = False
            return

        are_kernels_busy = False

        for kernel_data in json_response:
            kernel_id = kernel_data["id"]

            kernel_info = self._get(f"/api/kernels/{kernel_id}")
            if kernel_info["execution_state"] != "idle":
                are_kernels_busy = True

        self.are_kernels_busy = are_kernels_busy

    def _check_if_busy(self) -> bool:
        self._update_kernels_activity()
        return self.are_kernels_busy

    def get_debug_entry(self) -> Dict[str, Any]:
        return {
            "kernel_monitor": {
                "is_busy": self.is_busy,
                "config": {"poll_interval": self._poll_interval},
            }
        }


ProcessID = int
TimeSeconds = float
PercentCPU = float


class CPUUsageMonitor(AbstractIsBusyMonitor):
    """At regular intervals computes the total CPU usage
    and averages over 1 second.
    """

    def __init__(
        self, poll_interval: float, metrics: MetricsManager, *, busy_threshold: float
    ):
        super().__init__(poll_interval=poll_interval, metrics=metrics)
        self.busy_threshold = busy_threshold

        # snapshot
        self._last_sample: dict[ProcessID, tuple[TimeSeconds, PercentCPU]] = (
            self._sample_total_cpu_usage()
        )
        self.total_cpu_usage: PercentCPU = 0

    @staticmethod
    def _sample_cpu_usage(
        process: psutil.Process,
    ) -> Tuple[ProcessID, Tuple[TimeSeconds, PercentCPU]]:
        """returns: tuple[pid, tuple[time, percent_cpu_usage]]"""
        return (process.pid, (time.time(), process.cpu_percent()))

    def _sample_total_cpu_usage(
        self,
    ) -> Dict[ProcessID, Tuple[TimeSeconds, PercentCPU]]:
        futures = [
            self.thread_executor.submit(self._sample_cpu_usage, p)
            for p in _get_sibling_processes()
        ]
        return dict([f.result() for f in as_completed(futures)])

    @staticmethod
    def _get_cpu_over_1_second(
        last: Tuple[TimeSeconds, PercentCPU], current: Tuple[TimeSeconds, PercentCPU]
    ) -> float:
        interval = current[0] - last[0]
        measured_cpu_in_interval = current[1]
        # cpu_over_1_second[%] = 1[s] * measured_cpu_in_interval[%] / interval[s]
        return measured_cpu_in_interval / interval

    def _update_total_cpu_usage(self) -> None:
        current_sample = self._sample_total_cpu_usage()

        total_cpu: float = 0
        for pid, time_and_cpu_usage in current_sample.items():
            if pid not in self._last_sample:
                continue  # skip if not found

            last_time_and_cpu_usage = self._last_sample[pid]
            total_cpu += self._get_cpu_over_1_second(
                last_time_and_cpu_usage, time_and_cpu_usage
            )

        self._last_sample = current_sample  # replace

        self.total_cpu_usage = total_cpu

    def _check_if_busy(self) -> bool:
        self._update_total_cpu_usage()
        return self.total_cpu_usage > self.busy_threshold

    def get_debug_entry(self) -> Dict[str, Any]:
        return {
            "cpu_usage": {
                "is_busy": self.is_busy,
                "total": self.total_cpu_usage,
                "config": {
                    "poll_interval": self._poll_interval,
                    "busy_threshold": self.busy_threshold,
                },
            },
        }


BytesRead = int
BytesWrite = int


class DiskUsageMonitor(AbstractIsBusyMonitor):
    def __init__(
        self,
        poll_interval: float,
        metrics: MetricsManager,
        *,
        read_usage_threshold: int,
        write_usage_threshold: int,
    ):
        super().__init__(poll_interval=poll_interval, metrics=metrics)
        self.read_usage_threshold = read_usage_threshold
        self.write_usage_threshold = write_usage_threshold

        self._last_sample: dict[
            ProcessID, tuple[TimeSeconds, BytesRead, BytesWrite]
        ] = self._sample_total_disk_usage()

        self.total_bytes_read: BytesRead = 0
        self.total_bytes_write: BytesWrite = 0

    @staticmethod
    def _sample_disk_usage(
        process: psutil.Process,
    ) -> Optional[Tuple[ProcessID, Tuple[TimeSeconds, BytesRead, BytesWrite]]]:
        try:
            counters = process.io_counters()
        except (psutil.AccessDenied):
            _logger.warning("cannot access process='%s'", process)
            return None
        except psutil.NoSuchProcess: 
            return None
        return (process.pid, (time.time(), counters.read_bytes, counters.write_bytes))

    def _sample_total_disk_usage(
        self,
    ) -> Dict[ProcessID, Tuple[TimeSeconds, BytesRead, BytesWrite]]:
        futures = [
            self.thread_executor.submit(self._sample_disk_usage, p)
            for p in _get_sibling_processes()
        ]
        results = [f.result() for f in as_completed(futures)]
        return dict(r for r in results if r is not None)

    @staticmethod
    def _get_bytes_over_one_second(
        last: Tuple[TimeSeconds, BytesRead, BytesWrite],
        current: Tuple[TimeSeconds, BytesRead, BytesWrite],
    ) -> Tuple[BytesRead, BytesWrite]:
        interval = current[0] - last[0]
        measured_bytes_read_in_interval = current[1] - last[1]
        measured_bytes_write_in_interval = current[2] - last[2]

        # bytes_*_1_second[%] = 1[s] * measured_bytes_*_in_interval[%] / interval[s]
        bytes_read_over_1_second = int(measured_bytes_read_in_interval / interval)
        bytes_write_over_1_second = int(measured_bytes_write_in_interval / interval)
        return bytes_read_over_1_second, bytes_write_over_1_second

    def _update_total_disk_usage(self) -> None:
        current_sample = self._sample_total_disk_usage()

        total_bytes_read: int = 0
        total_bytes_write: int = 0
        for pid, time_and_disk_usage in current_sample.items():
            if pid not in self._last_sample:
                continue  # skip if not found

            last_time_and_disk_usage = self._last_sample[pid]

            bytes_read, bytes_write = self._get_bytes_over_one_second(
                last_time_and_disk_usage, time_and_disk_usage
            )
            total_bytes_read += bytes_read
            total_bytes_write += bytes_write

        self._last_sample = current_sample  # replace

        self.total_bytes_read = total_bytes_read
        self.total_bytes_write = total_bytes_write

    def _check_if_busy(self) -> bool:
        self._update_total_disk_usage()
        return (
            self.total_bytes_read > self.read_usage_threshold
            or self.total_bytes_write > self.write_usage_threshold
        )

    def get_debug_entry(self) -> Dict[str, Any]:
        return {
            "disk_usage": {
                "is_busy": self.is_busy,
                "total": {
                    "bytes_read_per_second": self.total_bytes_read,
                    "bytes_write_per_second": self.total_bytes_write,
                },
                "config": {
                    "poll_interval": self._poll_interval,
                    "read_usage_threshold": self.read_usage_threshold,
                    "write_usage_threshold": self.write_usage_threshold,
                },
            }
        }


InterfaceName = str
BytesReceived = int
BytesSent = int


class NetworkUsageMonitor(AbstractIsBusyMonitor):
    _EXCLUDE_INTERFACES: Set[InterfaceName] = {
        "lo",
    }

    def __init__(
        self,
        poll_interval: float,
        metrics: MetricsManager,
        *,
        received_usage_threshold: int,
        sent_usage_threshold: int,
    ):
        super().__init__(poll_interval=poll_interval, metrics=metrics)
        self.received_usage_threshold = received_usage_threshold
        self.sent_usage_threshold = sent_usage_threshold

        self._last_sample: tuple[TimeSeconds, BytesReceived, BytesSent] = (
            self._sample_total_network_usage()
        )
        self.bytes_received: BytesReceived = 0
        self.bytes_sent: BytesSent = 0

        self.metrics.register_metric(
            "network_bytes_received_total",
            help="Total number of bytes received across all network interfaces.",
            initial_value=0,
        )
        self.metrics.register_metric(
            "network_bytes_sent_total",
            help="Total number of bytes sent across all network interfaces.",
            initial_value=0,
        )

    def _sample_total_network_usage(
        self,
    ) -> Tuple[TimeSeconds, BytesReceived, BytesSent]:
        net_io_counters = psutil.net_io_counters(pernic=True)

        total_bytes_received: int = 0
        total_bytes_sent: int = 0
        for nic, stats in net_io_counters.items():
            if nic in self._EXCLUDE_INTERFACES:
                continue

            total_bytes_received += stats.bytes_recv
            total_bytes_sent += stats.bytes_sent

        return time.time(), total_bytes_received, total_bytes_sent

    @staticmethod
    def _get_bytes_over_one_second(
        last: Tuple[TimeSeconds, BytesReceived, BytesSent],
        current: Tuple[TimeSeconds, BytesReceived, BytesSent],
    ) -> Tuple[BytesReceived, BytesSent]:
        interval = current[0] - last[0]
        measured_bytes_received_in_interval = current[1] - last[1]
        measured_bytes_sent_in_interval = current[2] - last[2]

        # bytes_*_1_second[%] = 1[s] * measured_bytes_*_in_interval[%] / interval[s]
        bytes_received_over_1_second = int(
            measured_bytes_received_in_interval / interval
        )
        bytes_sent_over_1_second = int(measured_bytes_sent_in_interval / interval)
        return bytes_received_over_1_second, bytes_sent_over_1_second

    def _update_total_network_usage(self) -> None:
        current_sample = self._sample_total_network_usage()

        bytes_received, bytes_sent = self._get_bytes_over_one_second(
            self._last_sample, current_sample
        )

        self._last_sample = current_sample  # replace

        self.bytes_received = bytes_received
        self.bytes_sent = bytes_sent

        self.metrics.inc_metric("network_bytes_received_total", bytes_received)
        self.metrics.inc_metric("network_bytes_sent_total", bytes_sent)

    def _check_if_busy(self) -> bool:
        self._update_total_network_usage()
        return (
            self.bytes_received > self.received_usage_threshold
            or self.bytes_sent > self.sent_usage_threshold
        )

    def get_debug_entry(self) -> Dict[str, Any]:
        return {
            "network_usage": {
                "is_busy": self.is_busy,
                "total": {
                    "bytes_received_per_second": self.bytes_received,
                    "bytes_sent_per_second": self.bytes_sent,
                },
                "config": {
                    "poll_interval": self._poll_interval,
                    "received_usage_threshold": self.received_usage_threshold,
                    "sent_usage_threshold": self.sent_usage_threshold,
                },
            }
        }


class ActivityManager:
    def __init__(self, interval: float) -> None:
        self._keep_running: bool = True
        self._thread: Thread | None = None

        self.interval = interval
        self.last_idle: datetime | None = None

        self._monitors: list[AbstractIsBusyMonitor] = []

        self.metrics = MetricsManager()

        if not DISABLE_JUPYTER_KERNEL_MONITOR:
            self._monitors.append(
                JupyterKernelMonitor(
                    JUPYTER_NOTEBOOK_KERNEL_CHECK_INTERVAL_S, self.metrics
                )
            )
        if not DISABLE_CPU_USAGE_MONITOR:
            self._monitors.append(
                CPUUsageMonitor(
                    MONITOR_INTERVAL_S,
                    self.metrics,
                    busy_threshold=BUSY_USAGE_THRESHOLD_CPU,
                )
            )
        if not DISABLE_DISK_USAGE_MONITOR:
            self._monitors.append(
                DiskUsageMonitor(
                    MONITOR_INTERVAL_S,
                    self.metrics,
                    read_usage_threshold=BUSY_USAGE_THRESHOLD_DISK_READ,
                    write_usage_threshold=BUSY_USAGE_THRESHOLD_DISK_WRITE,
                )
            )
        if not DISABLE_NETWORK_USAGE_MONITOR:
            self._monitors.append(
                NetworkUsageMonitor(
                    MONITOR_INTERVAL_S,
                    self.metrics,
                    received_usage_threshold=BUSY_USAGE_THRESHOLD_NETWORK_RECEIVED,
                    sent_usage_threshold=BUSY_USAGE_THRESHOLD_NETWORK_SENT,
                )
            )

    def check(self):
        is_busy = any(x.is_busy for x in self._monitors)

        if is_busy:
            self.last_idle = None

        if not is_busy and self.last_idle is None:
            self.last_idle = datetime.utcnow()

    def get_idle_seconds(self) -> float:
        if self.last_idle is None:
            return 0

        idle_seconds = (datetime.utcnow() - self.last_idle).total_seconds()
        return idle_seconds if idle_seconds > 0 else 0

    def get_debug(self) -> Dict[str, Any]:
        merged_dict: dict[str, Any] = {}
        for x in self._monitors:
            merged_dict.update(x.get_debug_entry())
        return merged_dict

    def get_metrics(self) -> str:
        return self.metrics.format_metrics()

    def _worker(self) -> None:
        while self._keep_running:
            with suppress(Exception):
                self.check()
            time.sleep(self.interval)

    def start(self) -> None:
        for monitor in self._monitors:
            monitor.start()

        self._thread = Thread(
            target=self._worker,
            daemon=True,
            name=f"{self.__class__.__name__}_check_busy",
        )
        self._thread.start()

    def stop(self) -> None:
        for monitor in self._monitors:
            monitor.stop()

        self._keep_running = False
        self._thread.join()


############### Http Server


class ServerState:
    pass


class HTTPServerWithState(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, state):
        self.state = state  # application's state
        super().__init__(server_address, RequestHandlerClass)


class MainRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, data: Any) -> None:
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _send_text(self, code: int, text: str) -> None:
        self.send_response(code)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

    @property
    def activity_manager(self) -> ActivityManager:
        return self.server.state.activity_manager

    def do_GET(self):
        if self.path == "/activity":
            self._send_json(
                200, {"seconds_inactive": self.activity_manager.get_idle_seconds()}
            )
        elif self.path == "/debug":
            self._send_json(200, self.activity_manager.get_debug())
        elif self.path == "/metrics":
            self._send_text(200, self.activity_manager.get_metrics())
        else:  # Handle case where the endpoint is not found
            self._send_json(404, {"error": "Resource not found"})


def make_server(port: int) -> HTTPServerWithState:
    state = ServerState()
    state.activity_manager = ActivityManager(MONITOR_INTERVAL_S)
    state.activity_manager.start()

    server_address = ("", port)  # Listen on all interfaces, port 8000
    return HTTPServerWithState(server_address, MainRequestHandler, state)


def main():
    http_server = make_server(LISTEN_PORT)
    http_server.serve_forever()


if __name__ == "__main__":
    main()
