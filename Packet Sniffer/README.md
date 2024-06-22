## Project IPK - Varianta Zeta: Sniffer paketu

A packet sniffer — also known as a packet analyzer. Used to monitor network traffic.

### Usage:

`sudo ./ipk-sniffer [-i interface | --interface interface] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} `

The program need root access to the interface to be capable of reading the packets.

The arguments can be in any order.
- *interface* says what interface should the program use for sniffing. If the argument `-i`
  is omitted, then the program prints out the available interfaces.
- *port* filters the packets depending on the given port number. If not specified, all ports are considered.
- *num* states how many packets we wish to be printed out. If not specified, consider displaying only one packet.
- if `-t` or `--tcp` outputs only TCP packets
- if `-u` or `--udp` outputs only UDP packets
- if `--icmp` outputs only ICMPv4 and ICMPv6 packets
- if `--arp` outputs only ARP frames 

If specific protocols are not specified, they are all considered for printing.


#### Example
sudo ./ipk-sniffer -i eth0 -p 23 --tcp -n 2

sudo ./ipk-sniffer -i eth0 --udp

sudo ./ipk-sniffer -i eth0 -n 10

sudo ./ipk-sniffer -i
### Extensions
- Handling program errors

### Files
- ipk-sniffer.c
- makefile
- manual.pdf
- README.md