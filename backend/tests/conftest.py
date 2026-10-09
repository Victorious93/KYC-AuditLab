import os
import socket
import threading
import time

import pytest
import uvicorn

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_identityshield.db")
os.environ.setdefault("IDENTITYSHIELD_ALLOWED_TARGETS", "127.0.0.1,localhost")
os.environ.setdefault("IDENTITYSHIELD_SIM_VULNERABLE", "true")

from app.main import app  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server():
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("server did not start in time")

    yield f"127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def _reset_simulator(live_server):
    import requests

    requests.post(f"http://{live_server}/simulator/admin/reset", timeout=5)
    requests.post(
        f"http://{live_server}/scope",
        json={"target": "127.0.0.1", "authorized_by": "test-suite", "note": "automated tests"},
        timeout=5,
    )
    yield
