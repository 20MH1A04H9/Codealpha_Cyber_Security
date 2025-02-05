import logging
from datetime import datetime
import subprocess
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

print("\n! Make sure to run this program as ROOT !\n")

net_iface = input("* Enter the interface on which to run the sniffer (e.g. 'eth0'): ")

try:
    subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)
    print(f"\nInterface {net_iface} was set to PROMISC mode.\n")
except Exception as e:
    print(f"\nFailed to configure interface as promiscuous: {e}\n")


pkt_to_sniff = input("* Enter the number of packets to capture (0 is infinity): ")
pkt_to_sniff = int(pkt_to_sniff)

if pkt_to_sniff != 0:
    print(f"\nThe program will capture {pkt_to_sniff} packets.\n")
else:
    print("\nThe program will capture packets until the timeout expires.\n")

time_to_sniff = input("* Enter the number of seconds to run the capture: ")
time_to_sniff = int(time_to_sniff)

if time_to_sniff != 0:
    print(f"\nThe program will capture packets for {time_to_sniff} seconds.\n")

proto_sniff = input("* Enter the protocol to filter by (arp|bootp|icmp|0 is all): ").lower()

if proto_sniff in ("arp", "bootp", "icmp"):
    print(f"\nThe program will capture only {proto_sniff.upper()} packets.\n")
elif proto_sniff == "0":
    print("\nThe program will capture all protocols.\n")

file_name = input("* Please give a name to the log file: ")

try:
    sniffer_log = open(file_name, "a")
except Exception as e:
    print(f"Error opening log file: {e}")
    sys.exit()



def packet_log(packet):
    now = datetime.now()
    protocol = "ALL" if proto_sniff == "0" else proto_sniff.upper()
    print(f"Time: {now} Protocol: {protocol} SMAC: {packet[0].src} DMAC: {packet[0].dst}", file=sniffer_log)


print("\n* Starting the capture...")

try:
    if proto_sniff == "0":
        sniff(iface=net_iface, count=pkt_to_sniff, timeout=time_to_sniff, prn=packet_log)
    elif proto_sniff in ("arp", "bootp", "icmp"):
        sniff(iface=net_iface, filter=proto_sniff, count=pkt_to_sniff, timeout=time_to_sniff, prn=packet_log)
    else:
        print("\nCould not identify the protocol.\n")
        sys.exit()

    print(f"\n* Please check the {file_name} file to see the captured packets.\n")

except Exception as e:
    print(f"An error occurred during sniffing: {e}")

finally:
    if 'sniffer_log' in locals() and not sniffer_log.closed:
        sniffer_log.close()
