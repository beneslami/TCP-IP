//
// Created by Ben on 7/21/22.
//
#include "layer2.h"

void layer2_frame_recv(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size){
    unsigned int vlan_id_to_tag = 0;
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    if(l2_frame_recv_qualify_on_interface(interface, ethernet_hdr) == FALSE){
        printf("L2 Frame Rejected on node %s\n", node->node_name);
        return;
    }
    printf("L2 Frame Accepted on node %s\n", node->node_name);
    if(IS_INTF_L3_MODE(interface)){
        // promote packet to layer 2
    }
    else if (IF_L2_MODE(interface) == ACCESS || IF_L2_MODE(interface) == TRUNK){
        // l2 switch
    }
    else{
        return;
    }
}