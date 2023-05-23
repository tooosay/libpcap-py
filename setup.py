from distutils.core import setup, Extension

module = Extension("pcap", 
                   include_dirs = ["/usr/include","/usr/include/python3.10"],
                   libraries= ["pcap"],
                   sources=["pcap.c"])

setup (name = "pcap",
       version = "0.1.0",
       description = "libpcap python wrapper",
       author="tooosay",
       url = "https://github.com/tooosay/libpcap-py",
       ext_modules = [module])