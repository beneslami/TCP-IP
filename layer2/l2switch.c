//
// Created by Ben on 7/28/22.
//
#include "../comm.h"
#include <stdlib.h>
#include <stdio.h>
#include "../graph.h"
#include "layer2.h"
#include "../gluethread/glthread.h"

typedef struct mac_table_entry_{
    mac_add_t mac;
    char oif_name[IF_NAME_SIZE];
    glthread_t mac_entry_glue;
} mac_table_entry_t;
GLTHREAD_TO_STRUCT(mac_entry_glue_to_mac_entry, mac_table_entry_t, mac_entry_glue);

typedef struct mac_table_{
    glthread_t mac_entries;
} mac_table_t;

void init_mac_table(mac_table_t **mac_table){
    *mac_table = calloc(1, sizeof(mac_table_t));
    init_glthread(&((*mac_table)->mac_entries));
}

mac_table_entry_t * mac_table_lookup(mac_table_t *mac_table, char *mac){

    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

                mac_table_entry = mac_entry_glue_to_mac_entry(curr);
                if(strncmp(mac_table_entry->mac.mac, mac, sizeof(mac_add_t)) == 0){
                    return mac_table_entry;
                }
            } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
    return NULL;
}

void clear_mac_table(mac_table_t *mac_table){
    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;

    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){

                mac_table_entry = mac_entry_glue_to_mac_entry(curr);
                remove_glthread(curr);
                free(mac_table_entry);
            } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

void delete_mac_table_entry(mac_table_t *mac_table, char *mac){
    mac_table_entry_t *mac_table_entry;
    mac_table_entry = mac_table_lookup(mac_table, mac);
    if(!mac_table_entry)
        return;
    remove_glthread(&mac_table_entry->mac_entry_glue);
    free(mac_table_entry);
}

#define IS_MAC_TABLE_ENTRY_EQUAL(mac_entry_1, mac_entry_2)   \
    (strncmp(mac_entry_1->mac.mac, mac_entry_2->mac.mac, sizeof(mac_add_t)) == 0 && \
            strncmp(mac_entry_1->oif_name, mac_entry_2->oif_name, IF_NAME_SIZE) == 0)


bool_t mac_table_entry_add(mac_table_t *mac_table, mac_table_entry_t *mac_table_entry){
    mac_table_entry_t *mac_table_entry_old = mac_table_lookup(mac_table,
                                                              mac_table_entry->mac.mac);
    if(mac_table_entry_old &&
       IS_MAC_TABLE_ENTRY_EQUAL(mac_table_entry_old, mac_table_entry)){

        return FALSE;
    }
    if(mac_table_entry_old){
        delete_mac_table_entry(mac_table, mac_table_entry_old->mac.mac);
    }
    init_glthread(&mac_table_entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &mac_table_entry->mac_entry_glue);
    return TRUE;
}

void dump_mac_table(mac_table_t *mac_table){
    glthread_t *curr;
    mac_table_entry_t *mac_table_entry;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, curr){
                mac_table_entry = mac_entry_glue_to_mac_entry(curr);
                printf("\tMAC : %u:%u:%u:%u:%u:%u   | Intf : %s\n",
                       mac_table_entry->mac.mac[0],
                       mac_table_entry->mac.mac[1],
                       mac_table_entry->mac.mac[2],
                       mac_table_entry->mac.mac[3],
                       mac_table_entry->mac.mac[4],
                       mac_table_entry->mac.mac[5],
                       mac_table_entry->oif_name);
            } ITERATE_GLTHREAD_END(&mac_table->mac_entries, curr);
}

static void l2_switch_perform_mac_learning(node_t *node, char *src_mac, char *if_name){
    bool_t rc;
    mac_table_entry_t *mac_table_entry = calloc(1, sizeof(mac_table_entry_t));
    memcpy(mac_table_entry->mac.mac, src_mac, sizeof(mac_table_entry_t));
    strncpy(mac_table_entry->oif_name, if_name, IF_NAME_SIZE);
    mac_table_entry->oif_name[IF_NAME_SIZE - 1] = '\0';
    /*rc = mac_table_entry_add(NODE_MAC_TABLE(node, mac_table_entry));
    if(rc == FALSE){
        free(mac_table_entry);
    }*/
}

static bool_t l2_switch_send_pkt_out(char *pkt, unsigned int pkt_size, interface_t *oif){
    assert(!IS_INTF_L3_MODE(oif));
    intf_l2_mode_t intf_l2_mode= IF_L2_MODE(oif);
    if(intf_l2_mode == L2_MODE_UNKNOWN){
        return FALSE;
    }
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t *)pkt;
    switch(intf_l2_mode){
        case ACCESS:
        {
            send_pkt_out(pkt, pkt_size, oif);
            return TRUE;
        }
        break;
        case TRUNK:
        {
            send_pkt_out(pkt, pkt_size, oif);
            return TRUE;
        }
        break;
        case L2_MODE_UNKNOWN:
            break;
        default:
            ;
    }
}

static bool_t l2_switch_flood_pkt_out(node_t *node, interface_t *exempted_intf, char *pkt, unsigned int pkt_size){
    interface_t *oif = NULL;
    unsigned int i = 0;
    char *pkt_copy = NULL;
    char *temp_pkt = calloc(1, MAX_PACKET_BUFFER_SIZE);
    pkt_copy = temp_pkt + MAX_PACKET_BUFFER_SIZE - pkt_size;
    for( ; i < MAX_INTF_PER_NODE; i++){
        oif = node->intf[i];
        if(!oif)
            break;
        if(oif == exempted_intf || IS_INTF_L3_MODE(oif))
            continue;
        memcpy(pkt_copy, pkt, pkt_size);
        l2_switch_send_pkt_out(pkt_copy, pkt_size, oif);
    }
    free(temp_pkt);
}

static void l2_switch_forward_frame(node_t *node, interafce_t *recv_intf, char *pkt, unsigned int pkt_size){
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t*)pkt;
    if(IS_MAC_BROADCAST_ADDR(ethernet_hdr->dst_mac.mac)){
        send_pkt_flood_l2_intf_only(node, recv_intf, pkt, pkt_size);
        return;
    }
    mac_table_entry_t *mac_table_entry = mac_table_lookup(NODE_MAC_TABLE(node), ethernet_hdr->dst_mac.mac);
    if(!mac_table_entry){
        send_pkt_flood_l2_intf_only(node, recv_intf, pkt, pkt_size);
        return
    }
    char *oif_name = mac_table_entry->oif_name;
    interface_t *oif = get_node_if_by_name(node, oif_name);
    if(!oif)
        return;
    send_pkt_out(pkt, pkt_size, oif);
}

void l2_switch_recv_frame(interface_t interface, char *pkt, unsigned int pkt_size){
    node_t *node = interface->att_node;
    ethernet_hdr_t *ethernet_hdr = (ethernet_hdr_t*)pkt;
    char *dst_mac = (char*) ethernet_hdr->dst_mac.mac;
    char *src_mac = (char*) ethernet_hdr->src_mac.mac;
    l2_switch_perform_mac_learning(node, src_mac, interface->if_name);
    l2_switch_forward_frame(node, interface, pkt, pkt_size);
}