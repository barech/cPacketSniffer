#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "ipaddress.h"

// print operator displaying the IP address in dot form  (X.X.X.X)
void print_ipaddress(ipaddress *i) {
    unsigned int n = 0;
    for (n = 0; n < i->p_int; n++) {
        printf("%d", i->p_data[n]);
        if (n < i->p_int - 1) printf(".");
    }
    printf("\n"); 
}

char* get_ipaddress(ipaddress *i) {
    char *ip = malloc(sizeof(char)*20);
    ip[0] = 0; // malloc doesn't initialize the memory
    unsigned int n = 0;
    for(n = 0; n < i->p_int; n++) {
        char s[3];
        sprintf(s, "%d", i->p_data[n]);
        strcat(ip, s);
        if (n < i->p_int - 1) {
            strcat(ip, ".");
        }
    }
    return ip;
}

ipaddress* new_ipaddress(bool owned, unsigned char *p_data) {
    ipaddress *ip = malloc(sizeof(ipaddress));
    ip->p_int = IPADR_LEN;
    ip->owned = owned;
    ip->print_ipaddress = print_ipaddress;
    if (ip->owned) {
        memcpy(ip->p_data, p_data, ip->p_int);
    } else {
        ip->p_data = p_data;
    }
    return ip;
}
