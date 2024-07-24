# Mitnick Attack

This project simulates the Mitnick Attack using Docker Containers. This attack was possible because of two TCP vulnerabilities: predictable initial sequence number (ISN) and the posssibility to take down a server by SYN flooding it. There are three hosts involved in the attack. The intention of the attack is to implement a backdoor in host A, the target. Host B is a trusted server, which is allowed to log into host A without a password. The attack is performed by faking a TCP connection between host B and A using the vulnerabilities described before. To simulate this attack, we can consider a LAN environment where we can get the ISN used by host A by sniffing the network, and where we can take down host B by ARP spoofing it.

## Executing the attack

The first step to complete the task was to initialize the Docker containers. Next, it was necessary to create the .rhosts file on the X-Terminal machine as a pre-configuration step. In this file, only the IP of the Trusted Server was added.

Once this was done, the rest of the attack was carried out using only the attacking machine. The first step was to install dsniff, a package that contains a set of network tools. The tool I used was arpspoof, to "take down" the Trusted Server. The second step was to disable IP Forwarding. This was necessary because the attacking machine was redirecting the stolen packets to the correct machines, rendering arpspoof useless. Then, I proceeded with the arpspoof attack using the following commands: arpspoof -i $interface 10.9.0.5 and arpspoof -i $interface 10.9.0.6. These commands broadcast messages to the network, asserting that the attacking machine has the MAC address of IP 10.9.0.5 and also of IP 10.9.0.6.

With arpspoof running, it was time to send TCP messages from the attacking machine simulating the Trusted Server, i.e., with source IP = 10.9.0.6 and destination IP = 10.9.0.5. First, a SYN message with a sequence number of 0 is sent. After sending the message, the sniff function from the Python Scapy library is called. Whenever a packet is received, the spoof function is triggered. This function checks if the source of the message is the X-Terminal, and if so, it sends a response depending on the message received.

After the first SYN, the X-Terminal sends a SYN ACK, with an ACK number of 1. Then, an ACK is sent, completing the three-way handshake, and the RSH protocol message with the command to insert "+ +" in the .rhosts file of the X-Terminal is sent. As part of the RSH protocol, the X-Terminal initiates another TCP connection, to which the script responds with a SYN ACK message. Once the command execution is complete, the X-Terminal terminates the two created connections by sending two FIN messages. Upon receiving these messages, the script sends a FIN ACK, completing the attack.

At this point, the attacking machine (and any other) has access to the X-Terminal.
