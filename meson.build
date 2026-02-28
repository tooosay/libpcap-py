project('libpcap-py', 'c')

py = import('python').find_installation('python3.10',pure: false)

backend = get_option('pcap_backend')
if backend == 'auto'
  backend = (host_machine.system() == 'linux') ? 'libpcap' : ''
endif

sources = files()

deps = []

if backend == 'libpcap'
  pcap_dep = dependency('pcap', required: true)
  deps += [pcap_dep]
  sources += files('src/libpcap_py/_pcap/libpcap/pcap.c')
else
  error('unknown backend: ' + backend)
endif


py.extension_module(
    '_pcap',
    sources,
    include_directories: [],
    dependencies: deps,
    install: true,
    subdir: 'libpcap_py'
)

py.install_sources(
  'src/libpcap_py/__init__.py',
  subdir: 'libpcap_py',
)