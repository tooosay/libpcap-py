import libpcap_py as p
import pytest
import gc


def test_repeated_close(one_packet_pcap_path, repeat):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)

    for _ in range(repeat):
        p.close(pc)

    gc.collect()

def test_use_handle_after_close(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(pc)
    p.next(pc)

def test_use_handle_after_close_ex(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(pc)
    p.next_ex(pc)

def test_close_none():
    with pytest.raises(TypeError):
        p.close(None)

def test_close_del(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(None)
    del pc