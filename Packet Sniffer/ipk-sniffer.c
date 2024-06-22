// Vladyslav Kovalests (xkoval21)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

// Inspired by the macro idea: https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
// For option with optional argument.
#define OPTIONAL_ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))

#define MIN_PRINT_ASCII 32
#define MAX_PRINT_ASCII 128

// Maximum bytes per packet to capture.
#define SNAP_LEN 1518

// To work with arguments.
typedef struct{
    bool interface;
    char interface_arg[10];
    bool port;
    int port_arg;
    bool tcp;
    bool udp;
    bool arp;
    bool icmp;
    bool number_packets;
    int number_packets_arg;
}Arguments;

// To work with printing packages.
typedef struct{
    char *timestamp;
    struct ether_header *ether_header; //mac
    bpf_u_int32 frame_length;
    char src_ip[50];
    char dst_ip[50];
    int src_port;
    int dst_port;
    const u_char *packet_p;
}Packet;


// Finalizes the timestamp: output format and milliseconds.
char *handle_timestamp(struct tm *time, long int ms);
// Prepares a string with the required protocols.
void handle_protocols(Arguments * arguments);
// Works with command line arguments and fills structure with arguments.
void handle_args(int argc, char **argv, Arguments * arguments);
// Outputs data with active interfaces.
void print_active_interface();
// Stores the source and destination IP address (ARP).
void handle_arp(Packet *packet, const u_char* buffer);
// Outputs hexadecimal view;
void handle_hex_dump(Packet packet);
// Works with Internet Protocol IP.
void handle_ip(Packet * packet);
// Works with Internet Protocol IP version 6.
void handle_ipv6(Packet * packet);
// Outputs information about the package.
void handle_packet(Packet packet);
// Call back function that parses and displays the contents of each captured packet.
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Error buffer.
char errbuf[PCAP_ERRBUF_SIZE];

//For interface.
pcap_if_t *alldevsp , *device;

// Contains the requested protocols.
char protocols[70];

int main(int argc, char *argv[])
{
    // Struct initialization.
    Arguments arguments;
    // Works with command line arguments and fills structure with arguments.
    handle_args(argc, argv, &arguments);

    // To get a list of all available interfaces.
    if (pcap_findalldevs(&alldevsp, errbuf))
    {
        printf("Error: Failed to find interfaces: %s", errbuf);
        exit(EXIT_SUCCESS);
    }

    // If no interface is specified, or if an interface is specified without a value,
    // a list of active interfaces is displayed.
    if (arguments.interface == false || arguments.interface_arg[0] == 0)
        print_active_interface();


    // Interface netmask.
    bpf_u_int32 mask;
    // Interface source IP.
    bpf_u_int32 net;
    // Get interface source IP and netmask.
    if (pcap_lookupnet(arguments.interface_arg, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Error: Failed to get netmask for interface - %s: %s\n", arguments.interface_arg, errbuf);
        exit(EXIT_FAILURE);
    }

    // Structure pointer identifies the packet capture channel.
    pcap_t *handle;
    //Open the interface for sniffing.
    handle = pcap_open_live(arguments.interface_arg, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error: Failed to open interface - %s : %s\n", arguments.interface_arg, errbuf);
        exit(EXIT_FAILURE);
    }

    // Prepares a string with the required protocols.
    handle_protocols(&arguments);

    // Compiled filter expression.
    struct bpf_program fp;
    // Compiles protocols into a filter program.
    if(pcap_compile(handle, &fp, protocols, 0, net) == -1)
    {
        fprintf(stderr, "Error: Failed to parse filter - %s: %s\n", protocols, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Specifies the filter program.
    if(pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error: Failed to install filter - %s: %s\n", protocols, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Starts sniffing interface.
    pcap_loop(handle, arguments.number_packets_arg, got_packet, NULL);

    // Frees up allocated memory pointed.
    pcap_freecode(&fp);
    // Closes the files associated with "handle" and deallocates resources.
    pcap_close(handle);

    return 0;
}

void handle_args(int argc, char **argv, Arguments * arguments)
{
    //Initial filling of the structure.
    arguments->interface = false;
    arguments->interface_arg[0] = 0;
    arguments->port = false;
    arguments->tcp = false;
    arguments->udp = false;
    arguments->arp = false;
    arguments->icmp = false;
    arguments->number_packets = false;
    // If the number of packages is not specified, then output only one package.
    arguments->number_packets_arg = 1;

    // Long arguments.
    static struct option options[] =
            {
                    {"interface",     optional_argument,       0, 'i'},
                    {"tcp",  no_argument,       0, 't'},
                    {"udp",  no_argument, 0, 'u'},
                    {"arp",  no_argument, 0, 'a'},
                    {"icmp",    no_argument, 0, 'c'},
                    {"help",    no_argument, 0, 'h'},
                    {NULL, 0, 0, '\0'}
            };

    int opt;
    // Parses arguments and processes them.
    while ((opt = getopt_long(argc, argv, "tuachi::p::n::", options, NULL)) != -1)
    {
        switch(opt)
        {
            case 'i': // Stores an optional argument parameter, if present.
                arguments->interface = true;

                if (OPTIONAL_ARGUMENT_IS_PRESENT)
                    strcpy(arguments->interface_arg,  optarg);
                else
                    printf("Option -i without parameter.\n\n");
                break;

            case 'p': // Stores an optional argument parameter, if present.
                arguments->port = true;

                if (OPTIONAL_ARGUMENT_IS_PRESENT)
                    arguments->port_arg = atoi(optarg);
                else
                    printf("Option -p without parameter\n");
                break;

            case 't':
                arguments->tcp = true;
                break;

            case 'u':
                arguments->udp = true;
                break;

            case 'a':
                arguments->arp = true;
                break;

            case 'c':
                arguments->icmp = true;
                break;

            case 'n': // Stores an optional argument parameter, if present.
                arguments->number_packets = true;
                if (OPTIONAL_ARGUMENT_IS_PRESENT)
                    arguments->number_packets_arg = atoi(optarg);
                break;

            case 'h': //Help message.
                printf(("\nUsage: sudo ./ipk-sniffer [-i interface | --interface interface] {-p port} "
                        "{[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} \n\n"));
                printf("-i eth0 (just one interface to listen on. If this parameter is not specified, or if "
                       "only -i is specified without a value, a list of active interfaces will be displayed)\n");
                printf("-p 23 (will filter packets on the given interface by port; if not specified, "
                       "all ports are considered)\n");
                printf("-n 10 (specifies the number of packets to display; if not specified, consider "
                       "displaying only one packet)\n");
                printf("-t or --tcp (outputs only TCP packets)\n");
                printf("-u or --udp (outputs only UDP packets)\n");
                printf("--icmp (outputs only ICMPv4 and ICMPv6 packets)\n");
                printf("--arp (outputs only ARP frames)\n");
                printf("\nIf specific protocols are not specified, they are all considered for printing.\n");
                printf("The arguments can be in any order\n");
                exit(EXIT_SUCCESS);

            default:
                fprintf(stderr, "Use -h|--help for usage.\n");
        }
    }
}

void print_active_interface() {
    for (device = alldevsp; device != NULL; device = device->next) {
        printf("%s\n",device->name);
    }
    exit(EXIT_SUCCESS);
}

void handle_protocols(Arguments * arguments)
{
    // For strcat later.
    char port_str[10];
    sprintf(port_str, "%d", arguments->port_arg);

    // If protocols are not specified, they are all considered.
    if (!arguments->tcp && !arguments->udp && !arguments->icmp && !arguments->arp)
        printf("allowed protocols: TCP UDP ICMPv4 ICMPv6 ARP\n");
    // If specific protocols are specified
    else
    {
        printf("allowed protocols: ");
        // Put TCP in the protocols array.
        if(arguments->tcp)
        {
            printf("TCP ");
            // If a specific port is specified.
            if (arguments->port == true)
                sprintf(protocols, "tcp port %d", arguments->port_arg);
            else
                sprintf(protocols, "tcp");
        }
        // Put UDP in the protocols array.
        if(arguments->udp)
        {
            printf("UDP ");
            if(arguments->tcp)
                strcat(protocols, " or ");
            // If a specific port is specified.
            if (arguments->port == true)
            {
                strcat(protocols, "udp port ");
                strcat(protocols, port_str);
            } else
                strcat(protocols, "udp");
        }
        // Put ICMP in the protocols array.
        if(arguments->icmp)
        {
            printf("ICMPv4 ICMPv6 ");
            if(arguments->tcp || arguments->udp)
                strcat(protocols, " or ");
            strcat(protocols, "icmp or icmp6");
        }
        // Put ARP in the protocols array.
        if(arguments->arp)
        {
            printf("ARP ");
            if(arguments->tcp || arguments->udp || arguments->icmp)
                strcat(protocols, " or ");
            strcat(protocols, "arp");
        }
        printf("\n");
    }
}

char *handle_timestamp(struct tm *time, long int ms)
{
    size_t i;
    static char timestamp[45];

    // Improves the timestamp format.
    i = strftime(timestamp, 45, "%Y-%m-%dT%H:%M:%S%z", time);
    char time_zone[] = {timestamp[i-5], timestamp[i-4], timestamp[i-3], ':', timestamp[i-2], timestamp[i-1], '\0'};

    // Adds milliseconds.
    sprintf(timestamp+i-5, ".%ld%s", ms, time_zone);
    return timestamp;
}

void handle_arp(Packet *packet, const u_char* buffer)
{
    // Stores the source and destination IP address (ARP).
    struct ether_arp* arp = (struct ether_arp *)(buffer + 14);
    sprintf(packet->src_ip, "%u:%u:%u:%u", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]);
    sprintf(packet->dst_ip, "%u:%u:%u:%u", arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]);
}

void handle_hex_dump(Packet packet)
{
    bpf_u_int32 i;
    bpf_u_int32 j;
    // As long as no more than the length of the frame.
    for (i = 0; i < packet.frame_length; i += 16)
    {
        // First column.
        printf("0x%04x:", i);

        // Hexadecimal format.
        for (j = 0; j < 16; j++)
        {
            if (j == 8)
                printf(" ");

            if (j + i >= packet.frame_length)
                printf("   ");
            else
                printf(" %02x", packet.packet_p[j + i]);
        }

        printf("  ");

        for (j = 0; j < 16; j++)
        {
            if (j == 8)
                printf(" ");

            // Replace the unprintable character with a dot.
            if (j + i != packet.frame_length)
                if (packet.packet_p[j+i] >= MIN_PRINT_ASCII && packet.packet_p[j+i] <= MAX_PRINT_ASCII)
                    printf("%c", packet.packet_p[j+i]);
                else
                    printf("%s", ".");
            else
                break;
        }
        printf("\n");
    }
    printf("\n\n");
}

void handle_ipv6(Packet * packet)
{
    // Protocol headers.
    struct tcphdr *tcp;
    struct udphdr *udp;
    // Converts the IPv6 address into a strings.
    struct ip6_hdr* ip_6 = (struct ip6_hdr*)(packet->packet_p + sizeof(struct ether_header));
    inet_ntop(AF_INET6, &ip_6->ip6_src, packet->src_ip, NI_MAXHOST);
    inet_ntop(AF_INET6, &ip_6->ip6_dst, packet->dst_ip, NI_MAXHOST);

    // Determines the protocol.
    switch (ip_6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
    {
        case 6:
            // Save ports in correct format.
            tcp = (struct tcphdr*)(packet->packet_p + 40 + sizeof(struct ether_header));
            packet->src_port = ntohs(tcp->th_sport);
            packet->dst_port = ntohs(tcp->th_dport);
            break;

        case 17:
            // Saves ports.
            udp = (struct udphdr*)(packet->packet_p + 40 + sizeof(struct ether_header));
            packet->src_port = ntohs(udp->uh_sport);
            packet->dst_port = ntohs(udp->uh_dport);
            break;

            // Skip.
        case 1: //IPv4 ICMP
        case 58: //IPv6 ICMP
        packet->src_port = 0;
        packet->dst_port = 0;
            break;

        default:
            printf("Error: Can't work with protocol - %d.\n", ip_6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
            break;
    }
}

void handle_ip(Packet * packet)
{
    // Protocol headers.
    struct tcphdr *tcp;
    struct udphdr *udp;
    // Converts the IP address into a strings.
    struct ip *ip_p = (struct ip*)(packet->packet_p + sizeof(struct ether_header));
    inet_ntop(AF_INET, &ip_p->ip_src, packet->src_ip, NI_MAXHOST);
    inet_ntop(AF_INET, &ip_p->ip_dst, packet->dst_ip, NI_MAXHOST);

    // Determines the protocol.
    switch (ip_p->ip_p)
    {
        case 6:
            // Saves ports.
            tcp = (struct tcphdr*)(packet->packet_p + 40 + sizeof(struct ether_header));
            packet->src_port = ntohs(tcp->th_sport);
            packet->dst_port = ntohs(tcp->th_dport);
            break;

        case 17:
            // Saves ports.
            udp = (struct udphdr*)(packet->packet_p + 40 + sizeof(struct ether_header));
            packet->src_port = ntohs(udp->uh_sport);
            packet->dst_port = ntohs(udp->uh_dport);
            break;

            // Skip.
        case 1: //IPv4 ICMP
        case 58: //IPv6 ICMP
            packet->src_port = 0;
            packet->dst_port = 0;
            break;

        default:
            printf("Error: Can't work with protocol - %d.\n", ip_p->ip_p);
            break;
    }
}

void handle_packet(Packet packet)
{
    // Outputs information about the package.
    printf("timestamp: %s\n", packet.timestamp);
    printf("src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", packet.ether_header->ether_shost[0],
           packet.ether_header->ether_shost[1], packet.ether_header->ether_shost[2],
           packet.ether_header->ether_shost[3], packet.ether_header->ether_shost[4], packet.ether_header->ether_shost[5]);
    printf("dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", packet.ether_header->ether_dhost[0], packet.ether_header->ether_dhost[1],
           packet.ether_header->ether_dhost[2], packet.ether_header->ether_dhost[3],
           packet.ether_header->ether_dhost[4], packet.ether_header->ether_dhost[5]);
    printf("frame length: %d bytes\n", packet.frame_length);
    printf("src IP: %s\n", packet.src_ip);
    printf("dst IP: %s\n", packet.dst_ip);

    if (packet.src_port != 0)
        printf("src port: %u\n", packet.src_port);
    if (packet.dst_port != 0)
        printf("dst port: %u\n", packet.dst_port);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Struct initialization.
    Packet my_packet;
    my_packet.packet_p = packet;
    my_packet.src_port = 0;
    my_packet.src_port = 0;

    // For determines the protocol.
    struct ether_header *ether = (struct ether_header *) packet;
    switch (ntohs(ether->ether_type))
    {
        case ETHERTYPE_IP:
            handle_ip(&my_packet);
            break;

        case ETHERTYPE_IPV6:
            handle_ipv6(&my_packet);
            break;

        case ETHERTYPE_ARP:
            handle_arp(&my_packet, packet);
            break;

        default:
            printf("Error: Can't work with ether header - %d.\n", ether->ether_type);
            return;
    }

    // Saves local time from packet.
    struct tm *time = localtime(&header->ts.tv_sec);
    long int ms = header->ts.tv_usec/1000;
    my_packet.timestamp = handle_timestamp(time, ms);
    // Saves protocol number.
    my_packet.ether_header = ether;
    // Saves frame length.
    my_packet.frame_length = header->len;

    // Outputs about package.
    handle_packet(my_packet);
    handle_hex_dump(my_packet);
}
