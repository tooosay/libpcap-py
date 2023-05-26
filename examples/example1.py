import pcap as p
import time

filter_exp = "tcp"
device = p.lookupdev()
mask = p.lookupnet(device).mask
pcap = p.open_live(device,timeout_ms=10)
filter_program = p.compile(pcap, filter_exp ,mask, optimize=True) #note that function args are compile(pcap_t, "filter exp", mask, optimize)
p.setfilter(pcap,filter_program)

# define callback function
# the function implicitly takes arguments "header" and "packet", userdefined arguments are "args"
def callback(arg):
    x = arg.args[0]
    y = arg.args[1]
    header = arg.header
    packet = arg.packet
    print(time.ctime(header.tv_sec))
    print(packet.hex())
    
p.loop(pcap, callback, args=[1,2], count=10)
