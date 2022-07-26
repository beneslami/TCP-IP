//
// Created by Ben on 7/17/22.
//

#include "graph.h"
#include <stdio.h>
#include <stdlib.h>

static unsigned int hash_code(void *ptr, unsigned int size){
    unsigned int value = 0, i = 0;
    char *str = (char*)ptr;
    while(i < size){
        value += *str;
        value *= 97;
        str++;
        i++;
    }
    return value;
}


void interface_assign_mac_address(interface_t *interface){
    node_t *node = interface->att_node;
    if(!node)
        return;
    unsigned int hash_code_val = 0;
    hash_code_val = hash_code(node->node_name, NODE_NAME_SIZE);
    hash_code_val *= hash_code(interface->if_name, IF_NAME_SIZE);
    memset(IF_MAC(interface), 0, sizeof(IF_MAC(interface)));
    memcpy(IF_MAC(interface), (char*)&hash_code_val, sizeof(unsigned int));
}

bool_t node_set_loopback_address(node_t *node, char *ip_addr){
    assert(ip_addr);
    node->node_nw_prop.is_lb_addr_config = TRUE;
    strncpy(NODE_LO_ADDR(node), ip_addr, 16);
    NODE_LO_ADDR(node)[15] = '\0';
    return TRUE;
}

bool_t node_set_intf_ip_address(node_t *node, char *local_if, char *ip_addr, char mask){
    interface_t *interface = get_node_if_by_name(node, local_if);
    if(!interface)  assert(0);
    strncpy(IF_IP(interface), ip_addr, 16);
    IF_IP(interface)[15] = '\0';
    interface->intf_nw_props.mask = mask;
    interface->intf_nw_props.is_ipadd_config = TRUE;
    return TRUE;
}

bool_t node_unset_intf_ip_address(node_t *node, char *local_if){

}

char *pkt_buffer_shift_right(char *pkt, unsigned int pkt_size, unsigned int total_buffer_size){
    char *temp = NULL;
    bool_t need_temp_memory = FALSE;

    if(pkt_size * 2 > total_buffer_size){
        need_temp_memory = TRUE;
    }

    if(need_temp_memory){
        temp = calloc(1, pkt_size);
        memcpy(temp, pkt, pkt_size);
        memset(pkt, 0, total_buffer_size);
        memcpy(pkt + (total_buffer_size - pkt_size), temp, pkt_size);
        free(temp);
        return pkt + (total_buffer_size - pkt_size);
    }

    memcpy(pkt + (total_buffer_size - pkt_size), pkt, pkt_size);
    memset(pkt, 0, pkt_size);
    return pkt + (total_buffer_size - pkt_size);
}

interface_t * node_get_matching_subnet_interface(node_t *node, char *ip_addr){

    unsigned int i = 0;
    interface_t *intf;

    char *intf_addr = NULL;
    char mask;
    char intf_subnet[16];
    char subnet2[16];

    for( ; i < MAX_INTF_PER_NODE; i++){

        intf = node->intf[i];
        if(!intf) return NULL;

        if(intf->intf_nw_props.is_ipadd_config == FALSE)
            continue;

        intf_addr = IF_IP(intf);
        mask = intf->intf_nw_props.mask;

        memset(intf_subnet, 0 , 16);
        memset(subnet2, 0 , 16);
        apply_mask(intf_addr, mask, intf_subnet);
        apply_mask(ip_addr, mask, subnet2);

        if(strncmp(intf_subnet, subnet2, 16) == 0){
            return intf;
        }
    }
}