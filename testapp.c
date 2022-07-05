//
// Created by Ben on 7/5/22.
//
#include "graph.h"

graph_t *topo = NULL;
extern graph_t *build_first_topo();
int
main(int argc, char **argv){
    graph_t *topo = build_first_topo();
    dump_graph(topo);
    return 0;
}