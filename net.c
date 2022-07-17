//
// Created by Ben on 7/17/22.
//

#include "graph.h"
#include <stdio.h>

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
