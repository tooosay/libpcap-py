from __future__ import annotations

import os
from pathlib import Path

import pytest
from lib.pcap_data import make_one_packet_pcap


def _flag_enabled(name: str) -> bool:
    v = os.getenv(name, "")
    return v.lower() in {"1", "true", "yes", "on"}


@pytest.fixture(autouse=True)
def _gate(request):
    if request.node.get_closest_marker("online") and not _flag_enabled("ONLINE_TESTS"):
        pytest.skip("set ONLINE_TESTS=1 to run online tests")


def test_offline_ok():
    assert True


@pytest.mark.online
def test_online_ok():
    assert True


@pytest.fixture(scope="session")
def one_packet_pcap_path(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("pcaps")
    p = d / "one.pcap"
    p.write_bytes(make_one_packet_pcap())
    return p


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise pytest.UsageError(f"must be an integer: {value!r}")

    if parsed <= 0:
        raise pytest.UsageError(f"must be positive: {parsed}")

    return parsed


def pytest_addoption(parser):
    parser.addoption(
        "--pycap-repeat",
        action="store",
        default=os.environ.get("PYCAP_TEST_REPEAT", "1000"),
        type=positive_int,
        help="repeat count for libpcap-py stress tests",
    )


@pytest.fixture(scope="session")
def repeat(request) -> int:
    return request.config.getoption("--pycap-repeat")
