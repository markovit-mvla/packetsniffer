#include "sniffer.hpp"

void packet_handler(unsigned char* user_data, const struct pcap_pkthdr* pkthdr, const unsigned char* packet_data)
{
    struct ethhdr* ethernet_header = enetterpret(packet_data);

    if (ntohs(ethernet_header->h_proto) == ETHERTYPE_IP) {
        struct ip* ip_header = inetterpret(packet_data);
        std::cout<<"Source IP: "<<inet_ntoa(ip_header->ip_src)<<"\n";
        std::cout<<"Destination IP: "<<inet_ntoa(ip_header->ip_dst)<<"\n";

        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr* tcp_header = tnetterpret(packet_data);
            std::cout<<"Source Port: "<<ntohs(tcp_header->th_sport)<<"\n";
            std::cout<<"Destination Port: "<<ntohs(tcp_header->th_dport)<<"\n"; 
        }
        else if (ip_header->ip_p == IPPROTO_UDP) {
            struct udphdr* udp_header = unetterpret(packet_data);
            std::cout<<"Source Port: "<<ntohs(udp_header->uh_sport)<<"\n";
            std::cout<<"Destination Port: "<<ntohs(udp_header->uh_dport)<<"\n";
        }
    }
}

int main()
{
    pcap_t* handle;
    char err_buffer[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, err_buffer);
    if (handle == NULL) {
        std::cout<<"Error opening interface: "<<err_buffer<<"\n";
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
}