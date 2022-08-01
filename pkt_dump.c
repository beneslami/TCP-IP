//
// Created by Ben on 8/1/22.
//

#include <stdio.h>
#include "Layer2/layer2.h"
#include "tcpconst.h"
#include "utils.h"

void pkt_dump(ethernet_hdr_t *ethernet_hdr, unsigned int pkt_size){
    printf("----Ethernet Header----\n");
    printf("\t Src Mac : %u:%u:%u:%u:%u:%u\n",
           ethernet_hdr->src_mac.mac[0], ethernet_hdr->src_mac.mac[1],
           ethernet_hdr->src_mac.mac[2], ethernet_hdr->src_mac.mac[3],
           ethernet_hdr->src_mac.mac[4], ethernet_hdr->src_mac.mac[5]);
    printf("\t Dst Mac : %u:%u:%u:%u:%u:%u\n",
           ethernet_hdr->dst_mac.mac[0], ethernet_hdr->dst_mac.mac[1],
           ethernet_hdr->dst_mac.mac[2], ethernet_hdr->dst_mac.mac[3],
           ethernet_hdr->dst_mac.mac[4], ethernet_hdr->dst_mac.mac[5]);
    switch(ethernet_hdr->type){
        case ARP_MSG: {
            arp_hdr_t *arp_hdr = (arp_hdr_t *) (ethernet_hdr->payload);
            printf("\t-------ARP Hdr-----\n");
            printf("\t\t Src Mac : %u:%u:%u:%u:%u:%u\n",
                   ethernet_hdr->src_mac.mac[0], ethernet_hdr->src_mac.mac[1],
                   ethernet_hdr->src_mac.mac[2], ethernet_hdr->src_mac.mac[3],
                   ethernet_hdr->src_mac.mac[4], ethernet_hdr->src_mac.mac[5]);
            printf("\t\t Dst Mac : %u:%u:%u:%u:%u:%u\n",
                   ethernet_hdr->dst_mac.mac[0], ethernet_hdr->dst_mac.mac[1],
                   ethernet_hdr->dst_mac.mac[2], ethernet_hdr->dst_mac.mac[3],
                   ethernet_hdr->dst_mac.mac[4], ethernet_hdr->dst_mac.mac[5]);

            char ip[16];
            tcp_ip_covert_ip_n_to_p(arp_hdr->src_ip, ip);
            printf("\t\t Src Ip: %s\n", ip);

            tcp_ip_covert_ip_n_to_p(arp_hdr->dst_ip, ip);
            printf("\t\t Dest Ip: %s\n", ip);
            break;
        }
        default:
        {
            unsigned int offset = (char *)&(((ethernet_hdr_t *)0)->payload);
            printf("Payload offset: %d, Payload size: %d\n", offset, pkt_size - ETH_HDR_SIZE_EXCL_PAYLOAD);
            break;
        }
    }
}