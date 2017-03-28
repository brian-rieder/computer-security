#!/bin/bash

# Linux Firewall
# Brian Rieder (brieder)

# Place no restriction on outbound packets
iptables -I OUTPUT 1 -j ACCEPT

# Block a list of specific IP addresses for all incoming connections
iptables -A INPUT -s 64.0.0.0/101.255.255.255 -j DROP

# Block your computer from being pinged by all other hosts
iptables -A INPUT -p icmp --icmp-type echo-request -j REJECT

# Set up port forwarding from an unused port to port 22
iptables -t nat -A PREROUTING -p tcp --dport 7900 -j DNAT --to 128.58.10.100:22
iptables -A INPUT -p tcp --dport 7900 -j ACCEPT
iptables -A FORWARD -p tcp --dport 22 -j ACCEPT

# Allow SSH access from only ECN
iptables -A INPUT -p tcp --dport 22 -j REJECT
iptables -A INPUT -s ecn.purdue.edu -p tcp --dport 22 -j ACCEPT

# Allow only a single IP address to access for HTTP
iptables -A INPUT -p tcp --dport 80 -j REJECT
iptables -A INPUT -p tcp -s 128.58.10.100 --dport 80 -j ACCEPT

# Permit auth/ident (113) for SMTP, IRC, etc.
iptables -A INPUT -p tcp -m tcp --syn --dport 113 -j ACCEPT