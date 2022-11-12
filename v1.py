import pyshark
from colorama import init, Fore

# initialize colorama
init()

# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET

flags = ['ack', 'urg', 'push', 'syn', 'fin']

#live capture the packets
def livecapture_packets(interf:str, filter:str):
    capture = pyshark.LiveCapture(interface=interf, bpf_filter=filter)
    #capture.sniff(timeout=10)
    return capture

def filecapture_packets(path:str, display_fltr:str):
    capture = pyshark.FileCapture(path, display_filter=display_fltr)
    return capture

#Returns all the flags present in a packet
def find_flags_in_packet(flags):
    out = ""
    if(flags & 0x01):
       out += "FIN "
    if(flags & 0x02):
       out += "SYN "
    if(flags & 0x08):
       out += "PUSH "
    if(flags & 0x10):
       out += "ACK "
    if(flags & 0x20):
       out += "URG "

    return out.strip()

#https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters
def get_flag_filter(sel_flags:list):
    fltr = ""
    n = len(sel_flags)
    for flag in range(n):
        if sel_flags[flag].lower() in flags:
            if flag != n-1:
                fltr += f"tcp-{sel_flags[flag].lower()}|"
            else:
                fltr += f"tcp-{sel_flags[flag].lower()}"
#tcp[tcpflags] & (tcp-syn|tcp-fin) != 0
#captures all requested flags
    flag_filter = f"tcp[tcpflags]&({fltr}) == ({fltr})"

    return flag_filter

#Check if the input flags are present in the packet
def check_for_flag(selected_flags:list, flags:list):
    count = 0
    for i in selected_flags:
        if i in flags:
            count += 1
    
    if count == len(selected_flags):
        return 1
    return 0

interface = 'en0'

sel_flag = input(f"{RED}Select the TCP flag: ACK URG PUSH SYN FIN \n{RESET}").split(" ")
flag_filter = get_flag_filter(sel_flag)

opt = int(input(f"\n{RED}Select (1)for Capturing Packets (2)for Reading from a exisisting file{RESET}\n"))

if opt == 1:
    cpt = livecapture_packets(interface, flag_filter)
    num_of_pkts = int(input(f"{RED}Enter the number of packets to be captured: {RESET}"))
    print()
    print("Capturing...\n")
    for packet in cpt.sniff_continuously(packet_count=num_of_pkts):
        try:
            print(f"Source IP: {GREEN}{packet.ip.src}{RESET}")
            print(f"Destination IP:{GREEN}{packet.ip.dst}{RESET}")
        except:
            print(f"Source IP: {GREEN}{packet.ipv6.src}{RESET}")
            print(f"Destination IP:{GREEN}{packet.ipv6.dst}{RESET}")
        print(f"Source Port:{GREEN}{packet.tcp.srcport}{RESET}")
        print(f"Destination Port:{GREEN}{packet.tcp.dstport}{RESET}")
        flags = int(str(packet.tcp.flags), 16)
        print(f"Flags present in Packet: {GREEN}{find_flags_in_packet(flags)}{RESET}")
        print()

#Reads from a pcap file and prints packet information
elif opt == 2:
    path = input(f"{RED}Enter path to pcap file:{RESET} ")
    capture = filecapture_packets(path,"tcp")
    tcp_count = 0
    req_count = 0
    for packet in capture:
        flags_in_pkt = int(str(packet.tcp.flags), 16)
        flags_in_pkt = find_flags_in_packet(flags_in_pkt)
        tcp_count+=1
        if check_for_flag(sel_flag, flags_in_pkt):
            req_count+=1
            try:
                print(f"Source IP: {GREEN}{packet.ip.src}{RESET}")
                print(f"Destination IP:{GREEN}{packet.ip.dst}{RESET}")
            except:
                print(f"Source IP: {GREEN}{packet.ipv6.src}{RESET}")
                print(f"Destination IP:{GREEN}{packet.ipv6.dst}{RESET}")
            print(f"Source Port:{GREEN}{packet.tcp.srcport}{RESET}")
            print(f"Destination Port:{GREEN}{packet.tcp.dstport}{RESET}")
            flags = int(str(packet.tcp.flags), 16)
            print(f"Flags present in Packet: {GREEN}{find_flags_in_packet(flags)}{RESET}")
            print()
    print(f"Total TCP packets in file: {GREEN}{tcp_count}{RESET}")
    print(f"Total packets with input flags: {GREEN}{req_count}{RESET}")