import struct

def make_one_packet_pcap() -> bytes:
    """
    Generate a minimal PCAP (pcap, not pcapng) containing exactly 1 Ethernet frame.
    - little-endian
    - microsecond timestamps
    - linktype = 1 (Ethernet)
    """
    # PCAP global header
    # magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network(linktype)
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    # Minimal Ethernet frame (60 bytes)
    frame = (
        b"\xaa\xbb\xcc\xdd\xee\xff"  # dst
        b"\x11\x22\x33\x44\x55\x66"  # src
        b"\x08\x00"                  # ethertype: IPv4
        + b"\x00" * 46               # payload/padding
    )

    # Per-packet record header: ts_sec, ts_usec, incl_len, orig_len
    rh = struct.pack("<IIII", 1, 2, len(frame), len(frame))

    return gh + rh + frame
