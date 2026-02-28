import pytest
import libpcap_py as p

def test_offline_open_and_read_one_packet(one_packet_pcap_path):
    pcap = p.open_offline(str(one_packet_pcap_path))
    
    pkt1 = next(pcap)
    assert pkt1 is not None

    print(pcap)

    pkt2 = next(pcap)
    assert pkt2 is None

    pcap.close()

def test_offline_invalid_file_raises(tmp_path):

    file = tmp_path / "bad.pcap"
    file.write_bytes(b"not a pcap")

    with pytest.raises(Exception):
        p.open_offline(str(file))