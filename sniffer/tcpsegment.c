#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tcpsegment.h"
#include "utils.h"

// Returns source port
unsigned int source_port(tcpsegment *t) {
    return char2word(t->p_data);
}

// Return destination port
unsigned int dst_port(tcpsegment *t) {
    return char2word(t->p_data + 2);
}

// Return the sequence number filed
unsigned int sequence_nb(tcpsegment *t) {
    return char4word(t->p_data + 4);
}

// Returns the acknowledgement number filed
unsigned int ack_nb(tcpsegment *t) {
    return char4word(t->p_data + 8);
}

// TCP segment length in byte
static unsigned int length(tcpsegment *t) {
    return t->p_len;
}

// Returns the TCP segment header length in bytes
// one word is 32 bits length, thus 4 bytes length
static unsigned int header_length(tcpsegment *t) {
    return t->offset(t) * 4;
}

// Return the data offset field (header length in 4-bytes words or 32 bits words)
unsigned int offset(tcpsegment *t) {
    return t->p_data[12] >> 4;
}

// Returns the reserved field
unsigned int reserved(tcpsegment *t) {
    return (char2word(t->p_data + 12) & 0x0FC0) >> 6;
}

// Returns the NS flag value
bool flag_ns(tcpsegment *t) {
    return t->p_data[12] & 0x01;
}

// Returns the CWR flag value
bool flag_cwr(tcpsegment *t) {
    return t->p_data[13] & 0x80;
}

// Returns the ECE flag value
bool flag_ece(tcpsegment *t) {
    return t->p_data[13] & 0x40;
}

// Returns the URG flag value
bool flag_urg(tcpsegment *t) {
    return t->p_data[13] & 0x20;
}

// Return the ACK flag value 
bool flag_ack(tcpsegment *t) {
    return t->p_data[13] & 0x10;
}

// Returns the PSH flag value
bool flag_psh(tcpsegment *t) {
    return t->p_data[13] & 0x08;
}

// Return the RST flag value
bool flag_rst(tcpsegment *t) {
    return t->p_data[13] & 0x04;
}

// Return the SYN flag value
bool flag_syn(tcpsegment *t) {
    return t->p_data[13] & 0x02;
}

// Return the FIN flag value
bool flag_fin(tcpsegment *t) {
    return t->p_data[13] & 0x01;
}

// Return the window size 
unsigned int window_size(tcpsegment *t) {
    return char2word(t->p_data + 14);
}

// Return the checksum field
static unsigned int checksum(tcpsegment *t) {
    return char2word(t->p_data + 16);
}

// Return the urgent pointer field
unsigned int pointer_urg(tcpsegment *t) {
    return char2word(t->p_data + 18);
}

// Returns a string textually identifying most popular standard ports
char* port_name(unsigned int num) {
    switch(num) {
        case 20:
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67:
        case 68: return "DHCP";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 137:
        case 150: return "NetBIOS";
        case 389: return "LDAP";
        case 546:
        case 547: return "DHCP";
    }
    if (num < 1024) {
        return "unknown";
    } else {
        return "ephemeral";
    }
}

// Display the TCP segment header fields in human readable
void print_tcpsegment(tcpsegment *t) {
    if(t->p_data) {
        char outstr[16];
        printf("src_port = %d [%s]\t dst_port = %d %s]\n", t->src_port(t), t->port_name(t->src_port(t)), t->dst_port(t), t->port_name(t->dst_port(t)));
        printf("seq_nbr = %d\t ack_nbr = %d\n", t->sequence_nb(t), t->ack_nb(t));
        printf("offset = %d\n", t->offset(t));
        printf("reserved = %d\n", t->reserved(t));
        
        printf("NS  := %d\t CWR := %d\t ECE := %d\t URG := %d\t ACK := %d\n", t->flag_ns(t), t->flag_cwr(t), t->flag_ece(t), t->flag_urg(t), t->flag_ack(t));
        printf("PSH := %d\t RST := %d\t SYN := %d\t FIN := %d\n", t->flag_psh(t), t->flag_rst(t), t->flag_syn(t), t->flag_fin(t));

        printf("Win Size := %d\t URG Ptr := %d\t CHKSUM := 0x%.4x\n", t->window_size(t),  t->pointer_urg(t), t->checksum(t));
    }
}

tcpsegment* new_tcpsegment(bool owned, unsigned char *p_data, unsigned int p_len) {
    tcpsegment *t = malloc(sizeof(tcpsegment)); 
    t->p_len = p_len;
    t->owned = owned;
    t->offset = offset;
    t->length = length;
    t->header_length = header_length;
    t->src_port = source_port;
    t->dst_port = dst_port;
    t->sequence_nb = sequence_nb;
    t->ack_nb = ack_nb;
    t->reserved = reserved;
    t->flag_ns = flag_ns;
    t->flag_cwr = flag_cwr;
    t->flag_ece = flag_ece;
    t->flag_urg = flag_urg;
    t->flag_ack = flag_ack;
    t->flag_psh = flag_psh;
    t->flag_rst = flag_rst;
    t->flag_syn = flag_syn;
    t->flag_fin = flag_fin;
    t->window_size = window_size;
    t->checksum = checksum;
    t->pointer_urg = pointer_urg;
    t->port_name = port_name;
    t->print_tcpsegment = print_tcpsegment;
    if (t->owned) { // copy the data into a new block
        memcpy(t->p_data, p_data, p_len);
    } else {
       t->p_data = p_data; 
    }
    return t;
}
