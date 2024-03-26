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
from typing import Final, Any


_TB: Final[int] = 1024 * 1024 * 1024 * 1024
_ENV_VAR_PREFIX: Final[str] = "ACTIVITY_MONITOR_BUSY_THRESHOLD"

# NOTE: using high thresholds to make service by default
# considered inactive.
# If the service owner does not change these, by lowering
# them to an adequate value the service will always be shut
# down as soon as the inactivity period is detected.
BUSY_USAGE_THRESHOLD_CPU: Final[float] = os.environ.get(
    f"{_ENV_VAR_PREFIX}_CPU_PERCENT", 1000
)
BUSY_USAGE_THRESHOLD_DISK_READ: Final[int] = os.environ.get(
    f"{_ENV_VAR_PREFIX}_DISK_READ_BPS", 1 * _TB
)
BUSY_USAGE_THRESHOLD_DISK_WRITE: Final[int] = os.environ.get(
    f"{_ENV_VAR_PREFIX}_DISK_WRITE_BPS", 1 * _TB
)
BUSY_USAGE_THRESHOLD_NETWORK_RECEIVED: Final[int] = os.environ.get(
    f"{_ENV_VAR_PREFIX}_NETWORK_RECEIVE_BPS", 1 * _TB
)
BUSY_USAGE_THRESHOLD_NETWORK_SENT: Final[int] = os.environ.get(
    f"{_ENV_VAR_PREFIX}_NETWORK_SENT__BPS", 1 * _TB
)

# NOTE: set the following flags to disable a specific monitor
DISABLE_JUPYTER_KERNEL_MONITOR: Final[bool] = (
    os.environ.get("DISABLE_JUPYTER_KERNEL_MONITOR", None) is not None
)
DISABLE_CPU_USAGE_MONITOR: Final[bool] = (
    os.environ.get("DISABLE_CPU_USAGE_MONITOR", None) is not None
)
DISABLE_DISK_USAGE_MONITOR: Final[bool] = (
    os.environ.get("DISABLE_DISK_USAGE_MONITOR", None) is not None
)
DISABLE_NETWORK_USAGE_MONITOR: Final[bool] = (
    os.environ.get("DISABLE_NETWORK_USAGE_MONITOR", None) is not None
)

# Internals
LISTEN_PORT: Final[int] = 19597
KERNEL_CHECK_INTERVAL_S: Final[float] = 5
CHECK_INTERVAL_S: Final[float] = 1
_THREAD_EXECUTOR_WORKERS: Final[int] = 10

_logger = logging.getLogger(__name__)


############### Utils
class AbstractIsBusyMonitor:
    def __init__(self, poll_interval: float) -> None:
        self._poll_interval: float = poll_interval
        self._keep_running: bool = True
        self._thread: Thread | None = None

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
    def get_debug_entry(self) -> dict[str, Any]:
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


def __get_children_processes_recursive(pid) -> list[psutil.Process]:
    try:
        return psutil.Process(pid).children(recursive=True)
    except psutil.NoSuchProcess:
        return []


def _get_sibling_processes() -> list[psutil.Process]:
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
    BASE_URL = "http://localhost:8888"
    HEADERS = {"accept": "application/json"}

    def __init__(self, poll_interval: float) -> None:
        super().__init__(poll_interval=poll_interval)
        self.are_kernels_busy: bool = False

    def _get(self, path: str) -> dict:
        r = requests.get(f"{self.BASE_URL}{path}", headers=self.HEADERS)
        return r.json()

    def _update_kernels_activity(self) -> None:
        json_response = self._get("/api/kernels")

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

    def get_debug_entry(self) -> dict[str, Any]:
        return {"kernel_monitor": {"is_busy": self.is_busy}}


ProcessID = int
TimeSeconds = float
PercentCPU = float


class CPUUsageMonitor(AbstractIsBusyMonitor):
    """At regular intervals computes the total CPU usage
    and averages over 1 second.
    """

    def __init__(self, poll_interval: float, *, busy_threshold: float):
        super().__init__(poll_interval=poll_interval)
        self.busy_threshold = busy_threshold

        # snapshot
        self._last_sample: dict[ProcessID, tuple[TimeSeconds, PercentCPU]] = (
            self._sample_total_cpu_usage()
        )
        self.total_cpu_usage: PercentCPU = 0

    @staticmethod
    def _sample_cpu_usage(
        process: psutil.Process,
    ) -> tuple[ProcessID, tuple[TimeSeconds, PercentCPU]]:
        """returns: tuple[pid, tuple[time, percent_cpu_usage]]"""
        return (process.pid, (time.time(), process.cpu_percent()))

    def _sample_total_cpu_usage(
        self,
    ) -> dict[ProcessID, tuple[TimeSeconds, PercentCPU]]:
        futures = [
            self.thread_executor.submit(self._sample_cpu_usage, p)
            for p in _get_sibling_processes()
        ]
        return dict([f.result() for f in as_completed(futures)])

    @staticmethod
    def _get_cpu_over_1_second(
        last: tuple[TimeSeconds, PercentCPU], current: tuple[TimeSeconds, PercentCPU]
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

    def get_debug_entry(self) -> dict[str, Any]:
        return {
            "cpu_usage": {"is_busy": self.is_busy, "total": self.total_cpu_usage},
        }


BytesRead = int
BytesWrite = int


class DiskUsageMonitor(AbstractIsBusyMonitor):
    def __init__(
        self,
        poll_interval: float,
        *,
        read_usage_threshold: int,
        write_usage_threshold: int,
    ):
        super().__init__(poll_interval=poll_interval)
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
    ) -> tuple[ProcessID, tuple[TimeSeconds, BytesRead, BytesWrite]]:
        counters = process.io_counters()
        return (process.pid, (time.time(), counters.read_bytes, counters.write_bytes))

    def _sample_total_disk_usage(
        self,
    ) -> dict[ProcessID, tuple[TimeSeconds, BytesRead, BytesWrite]]:
        futures = [
            self.thread_executor.submit(self._sample_disk_usage, p)
            for p in _get_sibling_processes()
        ]
        return dict([f.result() for f in as_completed(futures)])

    @staticmethod
    def _get_bytes_over_one_second(
        last: tuple[TimeSeconds, BytesRead, BytesWrite],
        current: tuple[TimeSeconds, BytesRead, BytesWrite],
    ) -> tuple[BytesRead, BytesWrite]:
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

    def get_debug_entry(self) -> dict[str, Any]:
        return {
            "disk_usage": {
                "is_busy": self.is_busy,
                "total": {
                    "bytes_read_per_second": self.total_bytes_read,
                    "bytes_write_per_second": self.total_bytes_write,
                },
            }
        }


InterfaceName = str
BytesReceived = int
BytesSent = int


class NetworkUsageMonitor(AbstractIsBusyMonitor):
    _EXCLUDE_INTERFACES: set[InterfaceName] = {
        "lo",
    }

    def __init__(
        self,
        poll_interval: float,
        *,
        received_usage_threshold: int,
        sent_usage_threshold: int,
    ):
        super().__init__(poll_interval=poll_interval)
        self.received_usage_threshold = received_usage_threshold
        self.sent_usage_threshold = sent_usage_threshold

        self._last_sample: tuple[TimeSeconds, BytesReceived, BytesSent] = (
            self._sample_total_network_usage()
        )
        self.bytes_received: BytesReceived = 0
        self.bytes_sent: BytesSent = 0

    def _sample_total_network_usage(
        self,
    ) -> tuple[TimeSeconds, BytesReceived, BytesSent]:
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
        last: tuple[TimeSeconds, BytesReceived, BytesSent],
        current: tuple[TimeSeconds, BytesReceived, BytesSent],
    ) -> tuple[BytesReceived, BytesSent]:
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

    def _check_if_busy(self) -> bool:
        self._update_total_network_usage()
        return (
            self.bytes_received > self.received_usage_threshold
            or self.bytes_sent > self.sent_usage_threshold
        )

    def get_debug_entry(self) -> dict[str, Any]:
        return {
            "network_usage": {
                "is_busy": self.is_busy,
                "total": {
                    "bytes_received_per_second": self.bytes_received,
                    "bytes_sent_per_second": self.bytes_sent,
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

        if not DISABLE_JUPYTER_KERNEL_MONITOR:
            self._monitors.append(JupyterKernelMonitor(KERNEL_CHECK_INTERVAL_S))
        if not DISABLE_CPU_USAGE_MONITOR:
            self._monitors.append(
                CPUUsageMonitor(
                    CHECK_INTERVAL_S,
                    busy_threshold=BUSY_USAGE_THRESHOLD_CPU,
                )
            )
        if not DISABLE_DISK_USAGE_MONITOR:
            self._monitors.append(
                DiskUsageMonitor(
                    CHECK_INTERVAL_S,
                    read_usage_threshold=BUSY_USAGE_THRESHOLD_DISK_READ,
                    write_usage_threshold=BUSY_USAGE_THRESHOLD_DISK_WRITE,
                )
            )
        if not DISABLE_NETWORK_USAGE_MONITOR:
            self._monitors.append(
                NetworkUsageMonitor(
                    CHECK_INTERVAL_S,
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

    def get_debug(self) -> dict[str, Any]:
        merged_dict: dict[str, Any] = {}
        for x in self._monitors:
            merged_dict.update(x.get_debug_entry())
        return merged_dict

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


class JSONRequestHandler(BaseHTTPRequestHandler):
    def _send_response(self, code: int, data: dict) -> None:
        self.send_response(code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    @property
    def activity_manager(self) -> ActivityManager:
        return self.server.state.activity_manager

    def do_GET(self):
        if self.path == "/activity":
            self._send_response(
                200, {"seconds_inactive": self.activity_manager.get_idle_seconds()}
            )
        elif self.path == "/debug":
            self._send_response(200, self.activity_manager.get_debug())
        else:  # Handle case where the endpoint is not found
            self._send_response(404, {"error": "Resource not found"})


def make_server(port: int) -> HTTPServerWithState:
    state = ServerState()
    state.activity_manager = ActivityManager(CHECK_INTERVAL_S)
    state.activity_manager.start()

    server_address = ("", port)  # Listen on all interfaces, port 8000
    return HTTPServerWithState(server_address, JSONRequestHandler, state)


def main():
    http_server = make_server(LISTEN_PORT)
    http_server.serve_forever()


if __name__ == "__main__":
    main()
