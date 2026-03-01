import pytest
import libpcap_py as p

def test_offline_open_and_read_one_packet(one_packet_pcap_path):
    pcap = p.open_offline(str(one_packet_pcap_path))
    
    pkt1 = p.next_ex(pcap)
    assert pkt1 is not None

    pkt2 = p.next_ex(pcap)
    assert pkt2.data is None

    p.close(pcap)

def test_offline_invalid_file_raises(tmp_path):

    file = tmp_path / "bad.pcap"
    file.write_bytes(b"not a pcap")

    with pytest.raises(Exception):
        p.open_offline(str(file))