//
// Created by Ben on 7/17/22.
//

#ifndef TCP_IP_UTILS_H
#define TCP_IP_UTILS_H

typedef enum{
    FALSE,
    TRUE
} bool_t;

#define IS_MAC_BROADCAST_ADDR(mac)  \
    (mac[0] == 0xFF  &&  mac[1] == 0xFF && mac[2] == 0xFF && \
     mac[3] == 0xFF  &&  mac[4] == 0xFF && mac[5] == 0xFF)

void layer2_fill_with_broadcast_mac(char *mac_array);
#endif //TCP_IP_UTILS_H
