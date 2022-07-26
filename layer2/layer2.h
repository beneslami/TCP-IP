 //
// Created by Ben on 7/21/22.
//

#ifndef TCP_IP_LAYER2_H
#define TCP_IP_LAYER2_H

#include "../net.h"
#include "../utils.h"
#include "../graph.h"
#include "../tcpconst.h"
#include "../gluethread/glthread.h"
#include <stdlib.h>
#include <stdio.h>

#pragma pack (push, 1)  // to let the compiler not to add padding byte
typedef struct arp_hdr_{
    short hw_type;          /* 1 for ethernet cable */
    short proto_type;       /* 0x0800 for IPV4 */
    char hw_addr_len;       /* 6 for MAC */
    char proto_addr_len;    /*4 for IPV4*/
    short op_code;          /* req or rep */
    mac_add_t src_mac;      /* MAC for OIF interface */
    unsigned int src_ip;    /* IP of OIF */
    mac_add_t dst_mac;
    unsigned int dst_ip;    /* IP for which ARP is being resolved */
}arp_hdr_t;

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

typedef struct arp_table_{
    glthread_t arp_entries;
}arp_table_t;

typedef struct arp_pending_entry_ arp_pending_entry_t;
typedef struct arp_entry_ arp_entry_t;
 typedef void (*arp_processing_fn)(node_t *,
                                   interface_t *oif,
                                   arp_entry_t *,
                                   arp_pending_entry_t *);

struct arp_pending_entry_{
    glthread_t arp_pending_entry_glue;
    arp_processing_fn cb;
    unsigned int pkt_size;  /*Including ether net hdr*/
    char pkt[0];
};

GLTHREAD_TO_STRUCT(arp_pending_entry_glue_to_arp_pending_entry, \
        arp_pending_entry_t, arp_pending_entry_glue);

typedef struct arp_entry_{
    ip_add_t ip_addr;
    mac_add_t mac_addr;
    char oif_name[IF_NAME_SIZE];
    glthread_t arp_glue;
    bool_t is_sane;
    glthread_t arp_pending_list;
}arp_entry_t;

GLTHREAD_TO_STRUCT(arp_glue_to_arp_entry, arp_entry_t, arp_glue);
GLTHREAD_TO_STRUCT(arp_pending_list_to_arp_entry, arp_entry_t, arp_pending_list);

static inline char *GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_t *ethernet_hdr){
     return ethernet_hdr->payload;
 }

static bool_t arp_entry_sane(arp_entry_t *arp_entry){
    return arp_entry->is_sane;
}
//void layer2_frame_recv(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size);
void init_arp_table(arp_table_t **arp_table);
arp_entry_t *arp_table_lookup(arp_table_t *arp_table, char *ip_addr);
void clear_arp_table(arp_table_t *arp_table);
void delete_arp_entry(arp_entry_t *arp_entry);
void delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr);
bool_t arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry);
void dump_arp_table(arp_table_t *arp_table);
void arp_table_update_from_arp_reply(arp_table_t *arp_table, arp_hdr_t *arp_hdr, interface_t *iif);
void send_arp_broadcast_request(node_t *node, interface_t *oif, char *ip_addr);


#if 0
ethernet header:
        +----------+---------+------+--------------+-------+
        | dest_mac | src_mac | type |     DATA     |  CRC  |
        +----------+---------+------+--------------+-------+

Arp message:
        +----------+---------+------+--------------+-------+
        | dest_mac | src_mac |  806 |     DATA     |  CRC  |
        +----------+---------+------+--------------+-------+
                                    /               \
                                   /                 \
        +-------------+--------------------+-----------------+--------------------+
        | hw_type = 1 | proto type = 0x800 | hw_addr_len = 6 | proto_addr_len = 4 |
        +------------------+---------------+------------+-------------+-----------+
        | op_code = 1 Or 2 |    src_mac    |   src_IP   |   Dst_mac   |   Dst_IP  |
        +------------------+---------------+------------+-------------+-----------+
#endif

#endif //TCP_IP_LAYER2_H
