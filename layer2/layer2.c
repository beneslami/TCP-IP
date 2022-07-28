//
// Created by Ben on 7/21/22.
//
#include "layer2.h"
#include "../comm.h"
#include <sys/socket.h>
#include <arpa/inet.h>

void init_arp_table(arp_table_t **arp_table){
    *arp_table = calloc(1, sizeof(arp_table_t));
    init_glthread(&((*arp_table)->arp_entries));
}

arp_entry_t *arp_table_lookup(arp_table_t *arp_table, char *ip_addr){
    glthread_t *curr;
    arp_entry_t *arp_entry;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        arp_entry = arp_glue_to_arp_entry(curr);
        if(strncmp(arp_entry->ip_addr.ip_addr, ip_addr, 16) == 0){
            return arp_entry;
        }
    }ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
    return NULL;
}

void clear_arp_table(arp_table_t *arp_table){
    glthread_t *curr;
    arp_entry_t *arp_entry;

    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
                arp_entry = arp_glue_to_arp_entry(curr);
                delete_arp_entry(arp_entry);
            } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
}

void delete_arp_table_entry(arp_table_t *arp_table, char *ip_addr){
    arp_entry_t *arp_entry = arp_table_lookup(arp_table, ip_addr);
    if(!arp_entry)
        return;
    delete_arp_entry(arp_entry);
}

bool_t arp_table_entry_add(arp_table_t *arp_table, arp_entry_t *arp_entry){
    arp_entry_t *arp_entry_old = arp_table_lookup(arp_table, arp_entry->ip_addr.ip_addr);
    if(arp_entry_old && memcmp(arp_entry_old, arp_entry, sizeof(arp_entry_t)) == 0)
        return FALSE;
    if(arp_entry_old){
        delete_arp_table_entry(arp_table, arp_entry->ip_addr.ip_addr);
    }
    init_glthread(&arp_entry->arp_glue);
    glthread_add_next(&arp_table->arp_entries, &arp_entry->arp_glue);
    return TRUE;
}

static void delete_arp_pending_entry(arp_pending_entry_t *arp_pending_entry){

    remove_glthread(&arp_pending_entry->arp_pending_entry_glue);
    free(arp_pending_entry);
}

void delete_arp_entry(arp_entry_t *arp_entry){

    glthread_t *curr;
    arp_pending_entry_t *arp_pending_entry;
    remove_glthread(&arp_entry->arp_glue);

    ITERATE_GLTHREAD_BEGIN(&arp_entry->arp_pending_list, curr){
        arp_pending_entry = arp_pending_entry_glue_to_arp_pending_entry(curr);
        delete_arp_pending_entry(arp_pending_entry);
    } ITERATE_GLTHREAD_END(&arp_entry->arp_pending_list, curr);

    free(arp_entry);
}

void send_arp_broadcast_request(node_t *node, interface_t *oif, char *ip_addr){
    unsigned int payload_size = sizeof(arp_hdr_t);
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t*)calloc(1, ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size);
    if(!oif){
        oif = node_get_matching_subnet_interface(node, ip_addr);
        if(!oif){
            printf("Error: %s : No eligible subnet for ARP resolution for IP-address : %s\n", node->node_name, ip_addr);
            return;
        }
    }
    /* step1: prepare ethernet header */
    layer2_fill_with_broadcast_mac(ethernet_hdr->dest_mac.mac);
    memcpy(ethernet_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    ethernet_hdr->type = ARP_MSG;

    /* step2: prepare ARP broadcast request msg out of oif */
    arp_hdr_t *arp_hdr = (arp_hdr_t*)ethernet_hdr->payload;
    arp_hdr->hw_type = 1;
    arp_hdr->proto_type = 0x800;
    arp_hdr->hw_addr_len = sizeof(mac_add_t);
    arp_hdr->proto_addr_len = 4;
    arp_hdr->op_code = ARP_BROAD_REQ;
    memcpy(arp_hdr->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    inet_pton(AF_INET, ip_addr, &arp_hdr->src_ip);
    arp_hdr->src_ip = htonl(arp_hdr->src_ip);
    memset(arp_hdr->dst_mac.mac, 0, sizeof(mac_add_t));
    inet_pton(AF_INET, ip_addr, &arp_hdr->dst_ip);
    arp_hdr->dst_ip = htonl(arp_hdr->dst_ip);
    ETH_FCS(ethernet_hdr, sizeof(arp_hdr_t)) = 0;
    send_pkt_out((char*)ethernet_hdr, ETH_HDR_SIZE_EXCL_PAYLOAD + payload_size, oif);
    free(ethernet_hdr);
}

static void send_arp_reply_msg(ethernet_hdr_t *ethernet_hdr_in, interface_t *oif){
    arp_hdr_t *arp_hdr_in = (arp_hdr_t*)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_in));
    ethernet_hdr_t *ethernet_hdr_reply = (ethernet_hdr_t*)calloc(1, MAX_PACKET_BUFFER_SIZE);
    memcpy(ethernet_hdr_reply->dest_mac.mac, arp_hdr_in->src_mac.mac, sizeof(mac_add_t));
    memcpy(ethernet_hdr_reply->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    ethernet_hdr_reply->type = ARP_MSG;
    arp_hdr_t *arp_hdr_reply = (arp_hdr_t*)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr_reply));
    arp_hdr_reply->hw_type = 1;
    arp_hdr_reply->proto_type = 0x800;
    arp_hdr_reply->hw_addr_len = sizeof(mac_add_t);
    arp_hdr_reply->proto_addr_len = 4;
    arp_hdr_reply->op_code = ARP_REPLY;
    memcpy(arp_hdr_reply->src_mac.mac, IF_MAC(oif), sizeof(mac_add_t));
    inet_pton(AF_INET, IF_IP(oif), &arp_hdr_reply->src_ip);
    arp_hdr_reply->src_ip = htonl(arp_hdr_reply->src_ip);
    memcpy(arp_hdr_reply->dst_mac.mac, arp_hdr_in->src_mac.mac, sizeof(mac_add_t));
    arp_hdr_reply->dst_ip = arp_hdr_in->src_ip;
    unsigned int total_pkt_size = ETH_HDR_SIZE_EXCL_PAYLOAD + sizeof(arp_hdr_t);
    char *shifted_pkt_buffer = pkt_buffer_shift_right((char*)ethernet_hdr_reply, total_pkt_size, MAX_PACKET_BUFFER_SIZE);
    send_pkt_out(shifted_pkt_buffer, total_pkt_size, oif);
    free(ethernet_hdr_reply);
}

static void process_arp_reply_msg(node_t *node, interface_t *iif, ethernet_hdr_t *ethernet_hdr){
    printf("%s : ARP reply msg recvd on interface %s of node %s\n", __FUNCTION__, iif->if_name, iif->att_node->node_name);
    arp_table_update_from_arp_reply(NODE_ARP_TABLE(node), (arp_hdr_t*) GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr), iif);
}

static void process_arp_broadcast_request(node_t *node, interface_t *iif, ethernet_hdr_t *ethernet_hdr){
    printf("%s : ARP broadcast msg recvd on interface %s of node %s\n", __FUNCTION__ , iif->if_name, iif->att_node->node_name);
    char ip_addr[16];
    arp_hdr_t *arp_hdr = (arp_hdr_t*)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
    unsigned int arp_dst_ip = htonl(arp_hdr->dst_ip);
    inet_ntop(AF_INET, &arp_dst_ip, ip_addr, 16);
    ip_addr[15] = '\0';
    if(strncmp(IF_IP(iif), ip_addr, 16)){
        printf("%s : ARP Broadcast msg dropped, Dst IP address %s did not match with interface IP : %s\n", node->node_name,
        ip_addr, IF_IP(iif));
        return;
    }
    send_arp_reply_msg(ethernet_hdr, iif);
}

void arp_table_update_from_arp_reply(arp_table_t *arp_table, arp_hdr_t *arp_hdr, interface_t *iif){
    unsigned int src_ip = 0;
    assert(arp_hdr->op_code == ARP_REPLY);
    arp_entry_t *arp_entry = calloc(1, sizeof(arp_entry_t));
    src_ip = htonl(arp_hdr->src_ip);
    inet_ntop(AF_INET, &src_ip, &arp_entry->ip_addr.ip_addr, 16);
    arp_entry->ip_addr.ip_addr[15] = '\0';
    memcpy(arp_entry->mac_addr.mac, arp_hdr->src_mac.mac, sizeof(mac_add_t));
    strncpy(arp_entry->oif_name, iif->if_name, IF_NAME_SIZE);
    bool_t rc = arp_table_entry_add(arp_table, arp_entry);
    if(rc == FALSE)
        free(arp_entry);
}

void dump_arp_table(arp_table_t *arp_table){
    glthread_t *curr;
    arp_entry_t *arp_entry;
    ITERATE_GLTHREAD_BEGIN(&arp_table->arp_entries, curr){
        arp_entry = arp_glue_to_arp_entry(curr);
        printf("IP : %s, MAC : %u:%u:%u:%u:%u:%u, OIF = %s, Is Sane : %s\n",
               arp_entry->ip_addr.ip_addr,
               arp_entry->mac_addr.mac[0],
               arp_entry->mac_addr.mac[1],
               arp_entry->mac_addr.mac[2],
               arp_entry->mac_addr.mac[3],
               arp_entry->mac_addr.mac[4],
               arp_entry->mac_addr.mac[5],
               arp_entry->oif_name,
               arp_entry_sane(arp_entry) ? "TRUE" : "FALSE");
    } ITERATE_GLTHREAD_END(&arp_table->arp_entries, curr);
}

static void promote_pkt_to_layer2(node_t *node, interface_t *iif, ethernet_hdr_t *ethernet_hdr, uint32_t pkt_size){
    switch (ethernet_hdr->type) {
        case ARP_MSG:
        {
            /*Can be ARP Broadcast or ARP reply*/
            arp_hdr_t *arp_hdr = (arp_hdr_t *)(GET_ETHERNET_HDR_PAYLOAD(ethernet_hdr));
            switch(arp_hdr->op_code){
                case ARP_BROAD_REQ:
                    process_arp_broadcast_request(node, iif, ethernet_hdr);
                    break;
                case ARP_REPLY:
                    process_arp_reply_msg(node, iif, ethernet_hdr);
                    break;
                default:
                    break;
            }
        }
            break;
        default:
            ;
    }
}

void layer2_frame_recv(node_t *node, interface_t *interface, char *pkt, unsigned int pkt_size){
    unsigned int vlan_id_to_tag = 0;
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    if(l2_frame_recv_qualify_on_interface(interface, ethernet_hdr) == FALSE){
        printf("L2 Frame Rejected on node %s\n", node->node_name);
        return;
    }
    printf("L2 Frame Accepted on node %s\n", node->node_name);
    if(IS_INTF_L3_MODE(interface)){
        promote_pkt_to_layer2(node, interface, ethernet_hdr, pkt_size);
    }
    else if (IF_L2_MODE(interface) == ACCESS || IF_L2_MODE(interface) == TRUNK){
        // l2 switch
    }
    else{
        return;
    }
}

void interface_set_l2_mode(node_t *node, interface_t *interface, char *l2_mode_option){
    intf_l2_mode_t intf_l2_mode;
    if(strncmp(l2_mode_option, "access", strlen("access")) == 0){
        intf_l2_mode = ACCESS;
    }
    else if(strncmp(l2_mode_option, "trunk", strlen("trunk")) == 0){
        intf_l2_mode = TRUNK;
    }
    else{
        assert(0);
    }
    if(IS_INTF_L3_MODE(interface)){
        //interface->intf_nw_props.is_ipadd_config_backup = FALSE;
        interface->intf_nw_props.is_ipadd_config = FALSE;
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }
    if(IF_L2_MODE(interface) == L2_MODE_UNKNOWN){
        IF_L2_MODE(interface) = intf_l2_mode;
        return;
    }
    if(IF_L2_MODE(interface) == intf_l2_mode)
        return;
    if(IF_L2_MODE(interface) == ACCESS && intf_l2_mode == TRUNK){
        IF_L2_MODE(interface) = intf_l2_mode;
    }
    if(IF_L2_MODE(interface) == TRUNK && intf_l2_mode == ACCESS){
        IF_L2_MODE(interface) = intf_l2_mode;
    }
}

void node_set_intf_l2_mode(node_t *node, char *intf_name, intf_l2_mode_t intf_l2_modde){
    interface_t *interface = get_node_if_by_name(node, intf_name);
    assert(interface);
    interface_set_l2_mode(node, interface, intf_l2_mode_str(intf_l2_modde));
}