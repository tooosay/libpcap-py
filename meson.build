project('libpcap-py', 'c')

py = import('python').find_installation('python3.10',pure: false)

py.extension_module(
    'libpcap_py',
    ['pcap.c'],
    install: true
)

