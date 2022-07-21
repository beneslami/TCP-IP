//
// Created by Ben on 7/5/22.
//

#include "graph.h"
#include "net.h"

extern void network_start_pkt_receiver_thread(graph_t *topo);
extern void interface_assign_mac_address(interface_t *interface);

graph_t *build_first_topo(){
    graph_t *topo = create_new_graph("Generic graph");
    node_t *R0_re = create_graph_node(topo, "R0_re");
    node_t *R1_re = create_graph_node(topo, "R1_re");
    node_t *R2_re = create_graph_node(topo, "R2_re");

    insert_link_between_two_nodes(R0_re, R1_re, "eth0/0", "eth0/1", 1);
    insert_link_between_two_nodes(R1_re, R2_re, "eth0/2", "eth0/3", 1);
    insert_link_between_two_nodes(R0_re, R2_re, "eth0/4", "eth0/5", 1);

    node_set_loopback_address(R0_re, "122.1.1.0");
    node_set_intf_ip_address(R0_re, "eth0/4", "40.1.1.1", 24);
    node_set_intf_ip_address(R0_re, "eth0/0", "20.1.1.1", 24);

    node_set_loopback_address(R1_re, "122.1.1.1");
    node_set_intf_ip_address(R1_re, "eth0/1", "20.1.1.2", 24);
    node_set_intf_ip_address(R1_re, "eth0/2", "30.1.1.1", 24);

    node_set_loopback_address(R2_re, "122.1.1.2");
    node_set_intf_ip_address(R2_re, "eth0/3", "30.1.1.2", 24);
    node_set_intf_ip_address(R2_re, "eth0/5", "40.1.1.2", 24);

    network_start_pkt_receiver_thread(topo);
    return topo;
}

graph_t *build_linear_topo(){
    graph_t *topo = create_new_graph("Linear topology");
    node_t *R1 = create_graph_node(topo, "R1");
    node_t *R2 = create_graph_node(topo, "R2");
    node_t *R3 = create_graph_node(topo, "R3");

    insert_link_between_two_nodes(R1, R2, "eth0/1", "eth0/2", 1);
    insert_link_between_two_nodes(R2, R3, "eth0/3", "eth0/4", 1);

    node_set_loopback_address(R1, "122.1.1.1");
    node_set_loopback_address(R2, "122.1.1.2");
    node_set_loopback_address(R3, "122.1.1.3");

    node_set_intf_ip_address(R1, "eth0/1", "10.1.1.1", 24);
    node_set_intf_ip_address(R2, "eth0/2", "10.1.1.2", 24);
    node_set_intf_ip_address(R2, "eth0/3", "20.1.1.2", 24);
    node_set_intf_ip_address(R3, "eth0/4", "20.1.1.1", 24);

    network_start_pkt_receiver_thread(topo);
    return topo;
}