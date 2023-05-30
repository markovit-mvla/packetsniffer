#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
};

void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet_data);

ethhdr* enetterpret(const unsigned char* packet_data) {
    return reinterpret_cast<struct ethhdr*>(const_cast<unsigned char*>(packet_data));
}

ip* inetterpret(const unsigned char* packet_data) {
    return reinterpret_cast<struct ip*>(const_cast<unsigned char*>(packet_data+sizeof(struct ethhdr)));
}

tcphdr* tnetterpret(const unsigned char* packet_data) {
    return reinterpret_cast<struct tcphdr*>(const_cast<unsigned char*>(packet_data+sizeof(struct ethhdr)+sizeof(struct ip)));
}

udphdr* unetterpret(const unsigned char* packet_data) {
    return reinterpret_cast<struct udphdr*>(const_cast<unsigned char*>(packet_data+sizeof(struct ethhdr)+sizeof(struct ip)));
}