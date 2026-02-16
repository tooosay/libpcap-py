project('libpcap-py', 'c')

py = import('python').find_installation('python3.10',pure: false)
pcap_dep = dependency('pcap', required: true)

py.extension_module(
    'pppy',
    ['pcap.c'],
    dependencies: [pcap_dep],
    install: true
)

