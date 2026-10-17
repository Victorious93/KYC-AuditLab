import os
import socket
import threading
import time

import pytest
import uvicorn

os.environ.setdefault("DATABASE_URL", "sqlite:///./test_identityshield.db")
os.environ.setdefault("IDENTITYSHIELD_ALLOWED_TARGETS", "127.0.0.1,localhost")
os.environ.setdefault("IDENTITYSHIELD_SIM_VULNERABLE", "true")

# Test-only API keys, configured the production way (sha256-hashed).
import hashlib  # noqa: E402

from tests.helpers import ADMIN_KEY, BOTH_KEY, OPERATOR_KEY  # noqa: E402

os.environ["IDENTITYSHIELD_API_KEYS"] = ",".join(
    f"{ident}:{roles}:{hashlib.sha256(key.encode()).hexdigest()}"
    for ident, roles, key in [
        ("test-admin", "admin", ADMIN_KEY),
        ("test-operator", "operator", OPERATOR_KEY),
        ("test-both", "admin+operator", BOTH_KEY),
    ]
)
os.environ.pop("IDENTITYSHIELD_DEV_API_KEYS", None)

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

    from tests.helpers import ADMIN_HEADERS

    requests.post(f"http://{live_server}/simulator/admin/reset", headers=ADMIN_HEADERS, timeout=5)
    requests.post(
        f"http://{live_server}/scope",
        json={"target": "127.0.0.1", "note": "automated tests"},
        headers=ADMIN_HEADERS,
        timeout=5,
    )
    yield


@pytest.fixture(autouse=True)
def _reset_auth_state():
    """Rate-limit counters and the token denylist are process-global; keep
    tests independent."""
    from app.auth import reset_auth_state

    reset_auth_state()
    yield
    reset_auth_state()
