from __future__ import annotations
import os
import pytest
from lib.pcap_data import make_one_packet_pcap
from pathlib import Path

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