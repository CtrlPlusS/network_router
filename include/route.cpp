#include "./route.h"

struct ROUTE_ENTRY_NODE {
    struct ROUTE_ENTRY data;
    struct ROUTE_ENTRY_NODE* left;
    struct ROUTE_ENTRY_NODE* right;
}

struct ROUTE_ENTRY_NODE root;

struct ROUTE_ENTRY_NODE make_node(uint32_t src) {
    struct ROUTE_ENTRY node;
    node.destination = 0;
    node.netmask = 0;
    node.gateway = 0;
    node.interface[0] = '\0';
    node.metric = 0;
    node.left = &root;
    node.right = &root;

    return node;
}


root = make_node(0);

/**
* @brief Find the routing table entry for the given source IP
* @param src Source IP address
* @return Corresponding ROUTE_ENTRY structure
 */
struct ROUTE_ENTRY routing_table(uint32_t src) {
    struct ROUTE_ENTRY* current = &root;
    uint8_t depth = 1;

    while(true){
        if(src & (1 << (32 - depth))){ // 비트가 1이면 오른쪽으로
            if(current->right == &root){
                return *current;
            }
            current = current->right;
        } else {
            if(current->left == &root){
                return *current;
            }
            current = current->left;
        }
        depth++;
    }
}