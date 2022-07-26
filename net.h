//
// Created by Ben on 7/17/22.
//

#ifndef TCP_IP_NET_H
#define TCP_IP_NET_H

#include "utils.h"
#include "memory.h"

typedef struct node_ node_t;
typedef struct graph_ graph_t;
typedef struct interface_ interface_t;

typedef struct ip_add_ {
    char ip_addr[16];
}ip_add_t;

typedef struct mac_add_ {
    char mac[8];
}mac_add_t;

typedef struct arp_table_ arp_table_t;

typedef struct node_nw_prop_ {
    unsigned int flags;
    arp_table_t *arp_table;
    bool_t is_lb_addr_config;
    ip_add_t lb_addr;
}node_nw_prop_t;

typedef enum{
    ACCESS,
    TRUNK,
    L2_MODE_UNKNOWN
} intf_l2_mode_t;

static inline char *intf_l2_mode_str(intf_l2_mode_t intf_l2_mode){
    switch(intf_l2_mode){
        case ACCESS:
            return "access";
        case TRUNK:
            return "trunk";
        default:
            return "L2_MODE_UNKNWON";
    }
}

extern void init_arp_table(arp_table_t **arp_table);

static inline void init_node_nw_prop(node_nw_prop_t *node_nw_prop){
    node_nw_prop->flags = 0;
    node_nw_prop->is_lb_addr_config = FALSE;
    memset(node_nw_prop->lb_addr.ip_addr, 0, 16);
    init_arp_table(&(node_nw_prop->arp_table));
}

typedef struct intf_nw_props_ {
    mac_add_t mac_add; //L2 property
    intf_l2_mode_t intf_l2_mode;
    bool_t is_ipadd_config; //L3 property
    ip_add_t ip_add;
    char mask;
}intf_nw_props_t;

static inline void init_intf_nw_prop(intf_nw_props_t *intf_nw_props){
    memset(intf_nw_props->mac_add.mac, 0, 8);
    intf_nw_props->is_ipadd_config = FALSE;
    memset(intf_nw_props->ip_add.ip_addr, 0, 16);
    intf_nw_props->mask = 0;
}

#define IF_MAC(intf_ptr)        ((intf_ptr)->intf_nw_props.mac_add.mac)
#define IF_IP(intf_ptr)         ((intf_ptr)->intf_nw_props.ip_add.ip_addr)
#define NODE_LO_ADDR(node_ptr)  ((node_ptr)->node_nw_prop.lb_addr.ip_addr)
#define IF_L2_MODE(intf_ptr)    (intf_ptr->intf_nw_props.intf_l2_mode)
#define IS_INTF_L3_MODE(intf_ptr)  (intf_ptr->intf_nw_props.is_ipadd_config == TRUE)
#define NODE_ARP_TABLE(node_ptr)    (node_ptr->node_nw_prop.arp_table)

bool_t node_set_loopback_address(node_t*, char*);
bool_t node_set_intf_ip_address(node_t*, char*, char*, char);
bool_t node_unset_intf_ip_address(node_t*, char*);
void interface_assign_mac_address(interface_t *interface);
char *pkt_buffer_shift_right(char *pkt, unsigned int pkt_size, unsigned int total_buffer_size);

interface_t * node_get_matching_subnet_interface(node_t *node, char *ip_addr);
#endif //TCP_IP_NET_H
