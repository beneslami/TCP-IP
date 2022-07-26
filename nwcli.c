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

void nw_init_cli(){
    init_libcli();
    param_t *show = libcli_get_show_hook();
    param_t *config = libcli_get_config_hook();
    {
        static param_t topology;
        init_param(&topology, CMD, "topology", show_nw_topology_handler, 0, INVALID, 0, "Dump complete network topology");
        libcli_register_param(show, &topology);
        set_param_cmd_code(&topology, CMDCODE_SHOW_NW_TOPOLOGY);
    }

    support_cmd_negation(config);
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