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

typedef struct vlan_8021q_hdr_{
    unsigned short tpid; // 0x8100;
    short tci_pcp : 3;
    short tci_dei : 1;
    short tci_vid : 12;
}vlan_8021q_hdr_t;

typedef struct vlan_ethernet_hdr_{
    mac_add_t dst_mac;
    mac_add_t src_mac;
    vlan_8021q_hdr_t vlan_8021q_hdr;
    unsigned short type;
    char payload[248];
    unsigned int FCS;
}vlan_ethernet_hdr_t;

#pragma pack(pop)


#define ETH_HDR_SIZE_EXCL_PAYLOAD (sizeof(ethernet_hdr_t) - sizeof(((ethernet_hdr_t*)0)->payload))
#define ETH_FCS(eth_hdr_ptr, payload_size) \
                        (*(unsigned int *)(((char *)(((ethernet_hdr_t *)eth_hdr_ptr)->payload) + payload_size)))

#define VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD  \
                        (sizeof(vlan_ethernet_hdr_t) - sizeof(((vlan_ethernet_hdr_t *)0)->payload))
#define VLAN_ETH_FCS(vlan_eth_hdr_ptr, payload_size)  \
                        (*(unsigned int *)(((char *)(((vlan_ethernet_hdr_t *)vlan_eth_hdr_ptr)->payload) + payload_size)))
#define GET_COMMON_ETH_FCS(eth_hdr_ptr, payload_size)

#define GET_COMMON_ETH_FCS(eth_hdr_ptr, payload_size)   \
                (is_pkt_vlan_tagged(eth_hdr_ptr) ? VLAN_ETH_FCS(eth_hdr_ptr, payload_size) : ETH_FCS(eth_hdr_ptr, payload_size))


static inline vlan_8021q_hdr_t *is_pkt_vlan_tagged(ethernet_hdr_t *ethernet_hdr){
    if(ethernet_hdr->type == 0x8100){
        return (vlan_8021q_hdr_t*)&(ethernet_hdr->type);
    }
    else{
        return NULL;
    }
}

static inline unsigned int GET_802_1Q_VLAN_ID(vlan_8021q_hdr_t *vlan_8021q_hdr){
    return (unsigned int)vlan_8021q_hdr->tci_vid;
}

static inline char *GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_t *ethernet_hdr){
    if(is_pkt_vlan_tagged(ethernet_hdr)){
        return ((vlan_ethernet_hdr_t*)(ethernet_hdr))->payload;
    }
    else{
        return ethernet_hdr->payload;
    }
}

static inline void SET_COMMON_ETH_FCS(ethernet_hdr_t *ethernet_hdr, unsigned int payload_size, unsigned int new_fcs){
    if(is_pkt_vlan_tagged(ethernet_hdr)){
        VLAN_ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
    else{
        ETH_FCS(ethernet_hdr, payload_size) = new_fcs;
    }
}

static inline unsigned int GET_ETH_HDR_SIZE_EXCL_PAYLOAD(ethernet_hdr_t *ethernet_hdr){
     if(is_pkt_vlan_tagged(ethernet_hdr)){
         return VLAN_ETH_HDR_SIZE_EXCL_PAYLOAD;
     }
     else{
         return ETH_HDR_SIZE_EXCL_PAYLOAD;
     }
}

static inline ethernet_hdr_t *ALLOC_ETH_HDR_WITH_PAYLOAD(char *pkt, unsigned int pkt_size){
     char *temp = calloc(1, pkt_size);
     memcpy(temp, pkt, pkt_size);
     ethernet_hdr_t *eth_hdr = (ethernet_hdr_t *)(pkt - ETH_HDR_SIZE_EXCL_PAYLOAD);
     memset((char *)eth_hdr, 0, ETH_HDR_SIZE_EXCL_PAYLOAD);
     memcpy(eth_hdr->payload, temp, pkt_size);
     SET_COMMON_ETH_FCS(eth_hdr, pkt_size, 0);
     free(temp);
     return eth_hdr;
}

static inline bool_t l2_frame_recv_qualify_on_interface(interface_t *interface, ethernet_hdr_t *ethernet_hdr){
    /*if(!IS_INTF_L3_MODE(interface) && IF_L2_MODE(interface) == L2_MODE_UNKNOWN){
        return FALSE;
    }*/
    if(memcmp(IF_MAC(interface),ethernet_hdr->dest_mac.mac,sizeof(mac_add_t)) == 0){
        return TRUE;

    }
    if(IS_MAC_BROADCAST_ADDR(ethernet_hdr->dest_mac.mac)){
        return TRUE;
    }
    //return FALSE;
    return TRUE;
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
void node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_mode);
void node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_mode);
void node_set_intf_vlan_membsership(node_t *node, char *intf_name, unsigned int vlan_id);
ethernet_hdr_t *tag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr, unsigned int total_pkt_size, int vlan_id, unsigned int new_pkt_size);
ethernet_hdr_t *untag_pkt_with_vlan_id(ethernet_hdr_t *ethernet_hdr, unsigned int total_pkt_size, unsigned int new_pkt_size);

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


tagged ethernet header
        +----------+---------+----------------------+------+--------------+-------+
        | dest_mac | src_mac | 802.1q Vlan tagging  | type |     DATA     |  CRC  |
        +----------+---------+----------------------+------+--------------+-------+
                             /                      \
                            /                        \
                            +-------------+-----+-----+---------+
                            | TPID 0x8100 | PRI | CFI | VLan ID |
                            +-------------+-----+-----+---------+
                            <------2B-----><-3b-><-1b-><--12b--->
#endif

#endif //TCP_IP_LAYER2_H
