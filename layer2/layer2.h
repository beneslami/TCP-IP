 //
// Created by Ben on 7/21/22.
//

#ifndef TCP_IP_LAYER2_H
#define TCP_IP_LAYER2_H

#include "../net.h"
#include "../utils.h"
#include "../graph.h"
#include "../gluethread/glthread.h"
#include <stdlib.h>
#include <stdio.h>

#pragma pack (push, 1)  // to let the compiler not to add padding byte
typedef struct ethernet_hdr_{
    mac_add_t dest_mac;
    mac_add_t src_mac;
    unsigned short type;
    char payload[248];
    unsigned int FCS;
}ethernet_hdr_t;
#pragma pack(pop)


#define ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(ethernet_hdr_t) - sizeof(((ethernet_hdr_t*)0)->payload))
#define ETH_FCS(eth_hdr_ptr, payload_size) \
                        (*(unsigned int *)(((char *)(((ethernet_hdr_t *)eth_hdr_ptr)->payload) + payload_size)))


static inline ethernet_hdr_t *ALLOC_ETH_HDR_WITH_PAYLOAD(char *pkt, unsigned int pkt_size){
    char *temp = calloc(1, pkt_size);
    memcpy(temp, pkt, pkt_size);

    ethernet_hdr_t *eth_hdr = (ethernet_hdr_t*)(pkt - ETH_HDR_SIZE_EXCL_PAYLOAD);
    memset((char*)eth_hdr, 0, ETH_HDR_SIZE_EXCL_PAYLOAD);
    memcpy(eth_hdr->payload, temp, pkt_size);
    free(temp);
    return eth_hdr;
}


static inline bool_t l2_frame_recv_qualify_on_interface(interface_t *interface, ethernet_hdr_t *ethernet_hdr){
    if(!IS_INTF_L3_MODE(interface)){
        return FALSE;
    }
    if(memcmp(IF_MAC(interface),
              ethernet_hdr->dest_mac.mac,
              sizeof(mac_add_t)) == 0){
        return TRUE;

    }
    if(IS_MAC_BROADCAST_ADDR(ethernet_hdr->dest_mac.mac)){
        return TRUE;
    }
    return FALSE;
}

//void layer2_frame_recv(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size);

#if 0
        +----------+---------+------+--------------+-------+
        | dest_mac | src_mac | type |     DATA     |  CRC  |
        +----------+---------+------+--------------+-------+
#endif

#endif //TCP_IP_LAYER2_H
