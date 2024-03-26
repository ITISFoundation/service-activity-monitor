import os

from typing import Final
import requests

LISTEN_PORT: Final[int] = int(os.environ.get("ACTIVITY_MONITOR_LISTEN_PORT", 19597))


def main():
    response = requests.get(f"http://localhost:{LISTEN_PORT}/activity")
    print(response.text)


if __name__ == "__main__":
    main()
