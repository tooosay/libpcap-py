from distutils.core import setup, Extension

module = Extension("pppy", 
                   include_dirs = ["/usr/include","/usr/include/python3.10"],
                   libraries= ["pcap"],
                   sources=["pcap.c"])

setup (name = "libpcap-py",
       version = "0.3.0",
       description = "libpcap python wrapper",
       author="tooosay",
       url = "https://github.com/tooosay/libpcap-py",
       ext_modules = [module])
