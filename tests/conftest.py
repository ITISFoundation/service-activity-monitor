import ctypes
import pytest
import socket
import json
import threading
import time
import requests
import requests_mock

from concurrent.futures import ThreadPoolExecutor, wait
from multiprocessing import Array, Process
from tempfile import NamedTemporaryFile
from tenacity import Retrying
from tenacity.stop import stop_after_delay
from tenacity.wait import wait_fixed
from typing import Callable, Iterable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..docker import activity_monitor
else:
    from _import_utils import allow_imports

    allow_imports()
    import activity_monitor


_LOCAL_LISTEN_PORT: int = 12345


class _ListenSocketServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("localhost", _LOCAL_LISTEN_PORT))
        self.server_socket.listen(100)  # max number of connections
        self._process: Process | None = None

    def start(self):
        self._process = Process(target=self._accept_clients, daemon=True)
        self._process.start()

    def stop(self):
        if self._process:
            self._process.terminate()
            self._process.join()

    def _accept_clients(self):
        while True:
            client_socket, _ = self.server_socket.accept()
            threading.Thread(
                target=self._handle_client, daemon=True, args=(client_socket,)
            ).start()

    def _handle_client(self, client_socket):
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
        finally:
            client_socket.close()


@pytest.fixture
def socket_server() -> None:
    socket_server = _ListenSocketServer()
    socket_server.start()
    yield None
    socket_server.stop()


class _ActivityGenerator:
    def __init__(self, *, network: bool, cpu: bool, disk: bool) -> None:
        self._process: Process | None = None

        _keep_running = True
        self.shared_array = Array(ctypes.c_bool, 4)
        self.shared_array[0] = network
        self.shared_array[1] = cpu
        self.shared_array[2] = disk
        self.shared_array[3] = _keep_running

    def __load_cpu(self) -> None:
        for _ in range(1000000):
            pass

    def __load_network(self) -> None:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("localhost", _LOCAL_LISTEN_PORT))
        client_socket.sendall("mock_message_to_send".encode())
        client_socket.close()

    def __load_disk(self) -> None:
        with NamedTemporaryFile() as temp_file:
            temp_file.write(b"0" * 1024 * 1024)  # 1MB
            temp_file.read()

    def _run(self) -> None:
        with ThreadPoolExecutor(max_workers=3) as executor:
            while self.shared_array[3]:
                futures = []
                if self.shared_array[0]:
                    futures.append(executor.submit(self.__load_network))
                if self.shared_array[1]:
                    futures.append(executor.submit(self.__load_cpu))
                if self.shared_array[2]:
                    futures.append(executor.submit(self.__load_disk))

                wait(futures)
                time.sleep(0.1)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self) -> None:
        self._process = Process(target=self._run, daemon=True)
        self._process.start()

    def stop(self) -> None:
        _keep_running = False
        self.shared_array[3] = _keep_running
        if self._process:
            self._process.join()

    def get_pid(self) -> int:
        assert self._process
        return self._process.pid


@pytest.fixture
def create_activity_generator() -> (
    Iterable[Callable[[bool, bool, bool], _ActivityGenerator]]
):
    created: list[_ActivityGenerator] = []

    def _(*, network: bool, cpu: bool, disk: bool) -> _ActivityGenerator:
        instance = _ActivityGenerator(network=network, cpu=cpu, disk=disk)
        instance.start()
        created.append(instance)
        return instance

    yield _

    for instance in created:
        instance.stop()


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


@pytest.fixture
def server_url() -> str:
    return f"http://localhost:{activity_monitor.LISTEN_PORT}"


@pytest.fixture
def http_server(mock_jupyter_kernel_monitor: None, server_url: str) -> None:
    server = activity_monitor.make_server(activity_monitor.LISTEN_PORT)

    def _run_server_worker() -> None:
        server.serve_forever()

    thread = threading.Thread(target=_run_server_worker, daemon=True)
    thread.start()

    # ensure server is running
    for attempt in Retrying(
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
