import logging
from scapy.all import *
from collections import Counter




packet_counts = Counter()

capturedPacketsSize = 0

## Define our Custom Action function
def custom_action(packet):
    global capturedPacketsSize
    global packet_counts
    # Create tuple of Src/Dst in sorted order
    capturedPacketsSize += len(packet)     
    key = tuple(sorted([packet[0][1].src, packet[0][1].dst]))
    packet_counts.update([key])


    
print("_____.:|Entering infinite while loop|:._____")

n=1
while n<20:
    print("Analysing Multicast packets")
    pkt = sniff(iface="lo", filter="host 2100::102", prn=custom_action, timeout=1)
    print("\n".join("{0} <--> {1} :{2}".format(key[0], key[1], count) for key, count in packet_counts.items()))
    packet_counts.clear()
    print("Byterate for this moment is equal to: {0} Bytes per second".format(capturedPacketsSize))
    n=n+1
    