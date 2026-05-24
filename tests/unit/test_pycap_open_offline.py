import gc

import libpcap_py as p


def test_repeated_open_close(one_packet_pcap_path, repeat):
    path = str(one_packet_pcap_path)

    for _ in range(repeat):
        pc = p.open_offline(path)
        try:
            assert pc is not None
        finally:
            p.close(pc)

    gc.collect()


def test_many_open_handles(one_packet_pcap_path, repeat):
    path = str(one_packet_pcap_path)

    pcaps = []

    try:
        for _ in range(repeat):
            pcaps.append(p.open_offline(path))
    finally:
        for handle in pcaps:
            p.close(handle)

    pcaps.clear()
    gc.collect()
