# libpcap-py
[libpcap](https://www.tcpdump.org/) Python binding

## :pray:Prerequisite
 * Python >= 3.10
 * libpcap >= 1.10
 
## :running:Installation
<details>
<summary>:muscle:self-build</summary>

##### step 1
install followings
```sh
sudo apt install libpcap-dev
sudo apt install python3.10-dev libpython3.10-dev
```
##### step 2
clone and build using setup.py
```sh
git clone https://github.com/tooosay/libpcap-py
cd libpcap-py
python3 setup.py build
```
##### step 3
install using setup.py
```sh
python3 setup.py install
```
</details>


## :construction: Supported Functions [36/74][48%]
- [X] pcap_create
- [X] pcap_activate
- [X] pcap_findalldevs
- [ ] pcap_freealldevs
- [X] pcap_lookupdev
- [X] pcap_lookupnet
- [ ] pcap_open_offline
- [ ] pcap_open_offline_with_tstamp_precision
- [ ] pcap_fopen_offline
- [ ] pcap_fopen_offline_with_tstamp_precision
- [X] pcap_open_live
- [X] pcap_open_dead
- [X] pcap_close
- [X] pcap_set_snaplen
- [X] pcap_set_promisc
- [X] pcap_set_protocol_linux
- [X] pcap_set_rfmon
- [ ] pcap_can_set_rfmon
- [X] pcap_set_timeout
- [ ] pcap_set_immediate_mode
- [ ] pcap_set_buffer_size
- [ ] pcap_set_stapmp_type
- [ ] pcap_list_tsamp_types
- [ ] pcap_free_tstamp_types
- [ ] pcap_tstamp_type_val_to_name
- [ ] pcap_tsamp_type_val_to_description
- [ ] pcap_tsamp_type_name_to_val
- [ ] pcap_set_tstamp_precisoin
- [ ] pcap_get_tstamp_precision
- [X] pcap_datalink
- [ ] pcap_file
- [ ] pcap_is_swapped
- [ ] pcap_major_version
- [ ] pcap_minor_version
- [X] pcap_list_datalinks
- [ ] pcap_free_datalinks
- [X] pcap_set_datalink
- [X] pcap_datalink_val_to_name
- [X] pcap_datalink_val_to_description
- [ ] pcap_datalink_val_to_description_or_dlt
- [X] pcap_datalink_name_to_val
- [X] pcap_dispatch
- [X] pcap_loop
- [X] pcap_next
- [ ] pcap_next_ex
- [X] pcap_breakloop
- [X] pcap_setnonblock
- [X] pcap_getnonblock
- [ ] pcap_get_selectable_fd
- [ ] pcap_get_required_select_timeout
- [X] pcap_compile
- [X] pcap_compile_nopcap
- [X] pcap_freecode
- [X] pcap_setfilter
- [ ] pcap_offline_filter
- [ ] pcap_setdirection
- [X] pcap_stats
- [ ] pcap_dump_open
- [ ] pcap_dump_open_append
- [ ] pcap_dump_fopen
- [ ] pcap_dump_close
- [ ] pcap_dump_file
- [ ] pcap_dump
- [ ] pcap_dump_flush
- [ ] pcap_dump_ftell
- [ ] pcap_inject
- [ ] pcap_sendpacket
- [ ] pcap_statustostr
- [X] pcap_lib_version
- [X] pcap_fileno
- [X] pcap_snapshot
- [X] pcap_geterr
- [X] pcap_strerror
- [X] pcap_perror

## :oden:LICENSE
[2-clause BSD License](https://opensource.org/license/bsd-2-clause/)

