/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   main.cpp
 * Author: viegas
 *
 * Created on February 1, 2017, 10:08 AM
 */

#include <cstdlib>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/types.h>
#include <linux/icmp.h>

 #define TH_CWR 0x80

using namespace std;

struct PacketDTO {
    //ip
    unsigned char ip_ttl;
    char ip_p[100];
    char ip_src[100];
    char ip_dst[100];

    //udp
    __u16 udp_source;
    __u16 udp_dest;
    __u16 udp_len;

    //tcp
    __be16 tcp_source;
    __be16 tcp_dest;
    __be32 tcp_seq;
    __be32 tcp_ack_seq;


    char tcp_fin;
    char tcp_syn;
    char tcp_rst;
    char tcp_psh;
    char tcp_ack;
    char tcp_urg;
    char tcp_cwr;

    //icmp
    __u8 icmp_type;
    __u8 icmp_code;

    int packet_size;
} PacketDTO;

/*
 * 
 */
int main(int argc, char** argv) {

    //get file
    char filename[100];

    strcpy(filename, argv[1]);

    //error buffer
    char errbuff[PCAP_ERRBUF_SIZE];

    //open file and create pcap handler
    pcap_t * handler = pcap_open_offline(filename, errbuff);

    //The header that pcap gives us
    struct pcap_pkthdr *header;

    //The actual packet 
    const u_char *packet;

    int packetCount = 0;
    int i;

    //write to file 
    FILE *fp = fopen(argv[2], "w");

    u_int size_ip;
    u_int size_tcp;

    struct ether_header *eth;
    struct ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    
    int normal = 0;
    int attack = 0;
    int window = 1000;

    while (pcap_next_ex(handler, &header, &packet) >= 0) {

        eth = (struct ether_header*) packet;

        struct PacketDTO packetDTO;
        memset(&packetDTO, 0, sizeof (packetDTO));

        //if ipv4
        if (ntohs(eth->ether_type) == 0x0800) {

            ip = (struct ip*) (packet + sizeof (struct ether_header));


            char src[100];
            char dst[100];

            inet_ntop(AF_INET, &(ip->ip_src), src, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->ip_dst), dst, INET_ADDRSTRLEN);

            strcpy(packetDTO.ip_src, src);
            strcpy(packetDTO.ip_dst, dst);

            packetDTO.ip_ttl = ip->ip_ttl;
            packetDTO.packet_size = header->len;


            if (ip->ip_p == 6) {//if TCP
                tcp = (struct tcphdr*) (packet + sizeof (struct ether_header) + sizeof (struct ip));

                strcpy(packetDTO.ip_p, "TCP");

                packetDTO.tcp_source = ntohs(tcp->source);
                packetDTO.tcp_dest = ntohs(tcp->dest);
                packetDTO.tcp_seq = ntohs(tcp->seq);
                packetDTO.tcp_ack_seq = ntohs(tcp->ack);

                packetDTO.tcp_fin = (tcp->th_flags & TH_FIN) ? '1' : '0';
                packetDTO.tcp_syn = (tcp->th_flags & TH_SYN) ? '1' : '0';
                packetDTO.tcp_ack = (tcp->th_flags & TH_ACK) ? '1' : '0';
                packetDTO.tcp_psh = (tcp->th_flags & TH_PUSH) ? '1' : '0';
                packetDTO.tcp_rst = (tcp->th_flags & TH_RST) ? '1' : '0';
                packetDTO.tcp_urg = (tcp->th_flags & TH_URG) ? '1' : '0';
                packetDTO.tcp_cwr = (tcp->th_flags & TH_CWR) ? '1' : '0';


            } else if (ip->ip_p == 17) {//if UDP
                udp = (struct udphdr*) (packet + sizeof (struct ether_header) + sizeof (struct ip));

                strcpy(packetDTO.ip_p, "UDP");

                packetDTO.udp_dest = ntohs(udp->dest);
                packetDTO.udp_source = ntohs(udp->source);
                packetDTO.udp_len = ntohs(udp->len);


            } else if (ip->ip_p == 1) {
                icmp = (struct icmphdr*) (packet + sizeof (struct ether_header) + sizeof (struct ip));
                
                strcpy(packetDTO.ip_p, "ICMP");

                packetDTO.icmp_code = icmp->code;
                packetDTO.icmp_type = icmp->type;
            }
            /*
            if(strcmp(packetDTO.ip_src,"192.168.0.114") == 0){
                attack++;
            }else if(strcmp(packetDTO.ip_src,"192.168.0.112") != 0 &&
                    strcmp(packettDTO.ip_src,"192.168.0.113") != 0 &&
                    strcmp(packetDTO.ip_src,"192.168.0.115") != 0 &&
                    strcmp(packetDTO.ip_src,"192.168.0.116") != 0 &&
                    strcmp(packetDTO.ip_src,"192.168.0.117") != 0 &&
                    strcmp(packetDTO.ip_src,"192.168.0.118") != 0 &&
                    
                    strcmp(packetDTO.ip_dst,"192.168.0.112") != 0 &&
                    strcmp(packetDTO.ip_dst,"192.168.0.113") != 0 &&
                    strcmp(packetDTO.ip_dst,"192.168.0.115") != 0 &&
                    strcmp(packetDTO.ip_dst,"192.168.0.116") != 0 &&
                    strcmp(packetDTO.ip_dst,"192.168.0.117") != 0&&
                    strcmp(packetDTO.ip_dst,"192.168.0.118") != 0){
                normal++;
            }
            
            if((attack + normal) % window == 0 &&
                    (attack + normal) > 0){
                
                fprintf(fp, "%d;%d;\n", normal, attack);
                attack = 0;
                normal = 0;
            }
             */
            


            fprintf(fp,
                    "%lu;" //timestamp
                    "%s;" //ip_src
                    "%s;" //ip_dst
                    "%s;" //ip_proto
                    "%u;" //ip_ttl   
                    "%hu;" //udp_source
                    "%hu;" //udp_dest
                    "%hu;" //udp_len
                    "%hu;" //tcp_source
                    "%hu;" //tcp_dest
                    "%u;" //tcp_seq
                    "%u;" //tcp_ack
                    "%c;" //tcp_fin
                    "%c;" //tcp_syn
                    "%c;" //tcp_rst
                    "%c;" //tcp_psh
                    "%c;" //tcp_ack
                    "%c;" //tcp_urg
                    "%c;" //tcp_cwr
                    "%u;" //icmp_type
                    "%u;" //icmp_code
                    "%d\n", //packet_size
                    (header->ts.tv_sec * 1000000L + header->ts.tv_usec),
                    packetDTO.ip_src,
                    packetDTO.ip_dst,
                    packetDTO.ip_p,
                    packetDTO.ip_ttl,
                    packetDTO.udp_source,
                    packetDTO.udp_dest,
                    packetDTO.udp_len,
                    packetDTO.tcp_source,
                    packetDTO.tcp_dest,
                    packetDTO.tcp_seq,
                    packetDTO.tcp_ack_seq,
                    packetDTO.tcp_fin,
                    packetDTO.tcp_syn,
                    packetDTO.tcp_rst,
                    packetDTO.tcp_psh,
                    packetDTO.tcp_ack,
                    packetDTO.tcp_urg,
                    packetDTO.tcp_cwr,
                    packetDTO.icmp_type,
                    packetDTO.icmp_code,
                    packetDTO.packet_size
                    );
            

        }
    }
    fclose(fp);
    return (0);
}

