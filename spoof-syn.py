from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.5")
tcp = TCP(sport=1023, dport=514, flags="S", seq=1)
send(ip/tcp)