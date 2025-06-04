#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// Thresholds for detection
#define PPS_THRESHOLD     1000
#define SYN_THRESHOLD     800
#define ICMP_THRESHOLD    500
#define UDP_THRESHOLD     700
#define INTERVAL          10   // seconds
#define MAX_IP_ENTRIES    100  // Max unique IPs to track per interval

// Structure to store IP and packet count
typedef struct {
    char ip[INET_ADDRSTRLEN];
    u_int64_t count;
} IpCount;

// Global counters
static u_int64_t packet_count = 0;
static u_int64_t syn_count = 0;
static u_int64_t icmp_count = 0;
static u_int64_t udp_count = 0;
static time_t start_time = 0;

// IP tracking
static IpCount ip_counts[MAX_IP_ENTRIES];
static int ip_count_size = 0;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    struct udphdr *udp_header;
    struct icmphdr *icmp_header;

    if (!start_time) {
        start_time = header->ts.tv_sec;
        ip_count_size = 0;  // Reset IP tracker
    }

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) return;

    ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    double elapsed = difftime(header->ts.tv_sec, start_time);
    if (elapsed >= INTERVAL) {
        // Only print if attack detected
        double pps = packet_count / elapsed;

        if (syn_count > SYN_THRESHOLD || udp_count > UDP_THRESHOLD || icmp_count > ICMP_THRESHOLD) {
            printf("[!] DDoS Attack Detected at %s", ctime((const time_t*)&header->ts.tv_sec));
            printf("Top Source IPs:\n");

            for (int i = 0; i < ip_count_size && i < 10; i++) {  // Print top 10
                printf("    %s : %" PRIu64 " packets\n", ip_counts[i].ip, ip_counts[i].count);
            }

            if (syn_count > SYN_THRESHOLD)
                printf("    TCP SYN Flood: %" PRIu64 " packets\n", syn_count);
            if (udp_count > UDP_THRESHOLD)
                printf("    UDP Flood: %" PRIu64 " packets\n", udp_count);
            if (icmp_count > ICMP_THRESHOLD)
                printf("    ICMP Flood: %" PRIu64 " packets\n", icmp_count);
            printf("-----------------------------------------------\n");
        }

        // Reset counters
        packet_count = 0;
        syn_count = 0;
        icmp_count = 0;
        udp_count = 0;
        ip_count_size = 0;
        start_time = header->ts.tv_sec;
        return;
    }

    // Track source IP
    int found = 0;
    for (int i = 0; i < ip_count_size; i++) {
        if (strcmp(ip_counts[i].ip, src_ip) == 0) {
            ip_counts[i].count++;
            found = 1;
            break;
        }
    }

    if (!found && ip_count_size < MAX_IP_ENTRIES) {
        strcpy(ip_counts[ip_count_size].ip, src_ip);
        ip_counts[ip_count_size].count = 1;
        ip_count_size++;
    }

    packet_count++;

    switch(ip_header->ip_p) {
        case IPPROTO_TCP:
            tcp_header = (struct tcphdr *)((u_char*)ip_header + ip_header->ip_hl * 4);
            if (tcp_header->syn && !tcp_header->ack) {
                syn_count++;
            }
            break;

        case IPPROTO_UDP:
            udp_header = (struct udphdr *)((u_char*)ip_header + ip_header->ip_hl * 4);
            udp_count++;
            break;

        case IPPROTO_ICMP:
            icmp_header = (struct icmphdr *)((u_char*)ip_header + ip_header->ip_hl * 4);
            icmp_count++;
            break;
    }
}

int main() {
    pcap_if_t *devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Get device list
    if (pcap_findalldevs(&devices, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Open selected interface (change "eth0" to match your system)
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Could not open device eth0: %s\n", errbuf);
        return 1;
    }

    printf("Starting DDoS Detection Engine...\n");
    printf("Monitoring interface 'eth0' for attacks.\n");

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_freealldevs(devices);
    pcap_close(handle);
    return 0;
}
