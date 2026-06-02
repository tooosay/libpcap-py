import gc

import pytest

import libpcap_py as p


def test_repeated_close(one_packet_pcap_path, repeat):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)

    for _ in range(repeat):
        p.close(pc)

    gc.collect()


def test_use_handle_after_close_raises_value_error(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(pc)
    with pytest.raises(ValueError, match="closed"):
        p.next(pc)


def test_use_handle_after_close_ex_raises_value_error(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(pc)
    with pytest.raises(ValueError, match="closed"):
        p.next_ex(pc)


def test_close_none_raises_type_error():
    with pytest.raises(TypeError):
        p.close(None)


def test_del_without_close(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    del pc
    gc.collect()

def test_del_after_close(one_packet_pcap_path):
    path = str(one_packet_pcap_path)
    pc = p.open_offline(path)
    p.close(pc)
    del pc
    gc.collect()