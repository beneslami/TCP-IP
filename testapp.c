//
// Created by Ben on 7/5/22.
//
#include "graph.h"
#include "comm.h"
#include "CommandParser/libcli.h"
#include <stdio.h>

graph_t *topo = NULL;

extern graph_t *build_first_topo();
extern graph_t *build_linear_topo();
extern graph_t *build_simple_l2_switch_topo();
extern void nw_init_cli();

int main(int argc, char **argv){
    nw_init_cli();
    topo = build_simple_l2_switch_topo();

    /*node_t *snode = get_node_by_node_name(topo, "R0_re");
    interface_t *oif = get_node_if_by_name(snode, "eth0/0");
    char msg[] = "Hello. this is test\0";
    send_pkt_out(msg, strlen(msg), oif);*/

    start_shell();
    return 0;
}