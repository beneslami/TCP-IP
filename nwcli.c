//
// Created by Ben on 7/17/22.
//

#include "CommandParser/libcli.h"
#include "CommandParser/cmdtlv.h"
#include "cmdcodes.h"
#include "graph.h"
#include <stdio.h>

extern graph_t *topo;

static int show_nw_topology_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
    int CMDCODE = -1;
    CMDCODE = EXTRACT_CMD_CODE(tlv_buf);
    switch (CMDCODE) {
        case CMDCODE_SHOW_NW_TOPOLOGY:
            dump_graph(topo);
            break;
        default:
            ;
    }
}

void display_graph_nodes(param_t *param, ser_buff_t *tlv_buf){

    node_t *node;
    glthread_t *curr;

    ITERATE_GLTHREAD_BEGIN(&topo->node_list, curr){

        node = graph_glue_to_node(curr);
        printf("%s\n", node->node_name);
    } ITERATE_GLTHREAD_END(&topo->node_list, curr);
}

int validate_node_extistence(char *node_name){
    node_t *node = get_node_by_node_name(topo, node_name);
    if(node)
        return VALIDATION_SUCCESS;
    printf("Error : Node %s do not exist\n", node_name);
    return VALIDATION_FAILED;
}

typedef struct arp_table_ arp_table_t;
extern void dump_arp_table(arp_table_t *arp_table);
static int show_arp_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
    node_t *node;
    char *node_name;
    tlv_struct_t *tlv = NULL;
    TLV_LOOP_BEGIN(tlv_buf, tlv){
        if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
            node_name = tlv->value;

    }TLV_LOOP_END;
    node = get_node_by_node_name(topo, node_name);
    dump_arp_table(NODE_ARP_TABLE(node));
    return 0;
}

extern void send_arp_broadcast_request(node_t *node, interface_t *oif, char *ip_addr);
static int arp_handler(param_t *param, ser_buff_t *tlv_buf, op_mode enable_or_disable){
    node_t *node;
    char *node_name;
    char *ip_addr;
    tlv_struct_t *tlv = NULL;
    TLV_LOOP_BEGIN(tlv_buf, tlv){
            if(strncmp(tlv->leaf_id, "node-name", strlen("node-name")) == 0)
                node_name = tlv->value;
            else if(strncmp(tlv->leaf_id, "ip-address", strlen("ip-address")) == 0)
                ip_addr = tlv->value;
        }TLV_LOOP_END
    node = get_node_by_node_name(topo, node_name);
    send_arp_broadcast_request(node, NULL, ip_addr);
    return 0;
}

void nw_init_cli(){
    init_libcli();
    param_t *show   = libcli_get_show_hook();
    param_t *config = libcli_get_config_hook();
    {
        // show topology
        static param_t topology;
        init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID, 0, "Dump complete network topology");
        libcli_register_param(show, &topology);
        set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
        {
            //show node
            static param_t node;
            init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
            libcli_register_param(show, &node);
            libcli_register_display_callback(&node, display_graph_nodes);
            {
                //show node <NODE_NAME>
                static param_t node_name;
                init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
                libcli_register_param(&node, &node_name);
                {
                    //show node <NODE_NAME> arp
                    static param_t arp;
                    init_param(&arp, CMD, "arp", show_arp_handler, 0, INVALID, 0, "Dump Arp Table");
                    libcli_register_param(&node_name, &arp);
                    set_param_cmd_code(&arp, CMDCODE_SHOW_NODE_ARP_TABLE);
                }
            }
        }
    }
    {
        //config node
        static param_t node;
        init_param(&node, CMD, "node", 0, 0, INVALID, 0, "\"node\" keyword");
        libcli_register_param(config, &node);
        libcli_register_display_callback(&node, display_graph_nodes);
        {
            //config node <NODE_NAME>
            static param_t node_name;
            init_param(&node_name, LEAF, 0, 0, validate_node_extistence, STRING, "node-name", "Node Name");
            libcli_register_param(&node, &node_name);
            {
                //config node <NODE_NAME> resolve-arp
                static param_t resolve_arp;
                init_param(&resolve_arp, CMD, "resolve-arp", 0, 0, INVALID, 0, "Resolve ARP");
                libcli_register_param(&node_name, &resolve_arp);
                {
                    //config node <NODE_NAME> resolve-arp <IP_ADDRESS>
                    static param_t ip_addr;
                    init_param(&ip_addr, LEAF, 0, arp_handler, 0, IPV4, "ip-address", "Nbr IPv4 Address");
                    libcli_register_param(&resolve_arp, &ip_addr);
                    set_param_cmd_code(&ip_addr, CMDCODE_RUN_ARP);
                }
            }
        }
    }

    support_cmd_negation(config);
}