// This is a tuple declaration including creating_time, src_ip, src_port, dst_ip, dst_port, pkt_count.
#ifndef SNIFF_TUPLE_H
#define SNIFF_TUPLE_H 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/in.h>

#define SUCCESS		0
#define FAILURE		-1
#define SNIFFER_LENGTH	128

#define MAXINUM_ADDR_LENGTH		16

struct sniff_tuple {
    /* data */
	char src[MAXINUM_ADDR_LENGTH] ;
	char dst[MAXINUM_ADDR_LENGTH];
	in_port_t src_port;
	in_port_t dst_port;
	time_t tv_sec;
	uint32_t pkt_cnt;
};

struct sniff_list {
	struct sniff_tuple *list;
	uint32_t total_length;
	uint32_t current;
};

extern struct sniff_list sniffer_list;
static pthread_mutex_t sniff_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline int sniff_list_init(void)
{
	sniffer_list.total_length = SNIFFER_LENGTH;
	sniffer_list.current = 0;
	sniffer_list.list  = (struct sniff_tuple *) malloc(SNIFFER_LENGTH * sizeof(struct sniff_tuple));
	if (sniffer_list.list == NULL) {
		fprintf(stderr, "malloc failed.\n");
		return FAILURE;
	}

	memset(sniffer_list.list, 0, SNIFFER_LENGTH * sizeof(struct sniff_tuple));

	return SUCCESS;
}

static inline int sniff_list_push(struct sniff_tuple tuple_info)
{
	uint32_t current = 0;
	
	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current;

	if (current >= sniffer_list.total_length) {
		sniffer_list.list = 
						(struct sniff_tuple *) realloc(sniffer_list.list, 
								(sniffer_list.total_length + SNIFFER_LENGTH) * sizeof(struct sniff_tuple));
		if (sniffer_list.list == NULL) {
			fprintf(stderr, "realloc failed.\n");
			return FAILURE;
		}

		sniffer_list.total_length += SNIFFER_LENGTH;
	}

    memcpy(&sniffer_list.list[current], &tuple_info, sizeof(struct sniff_tuple));
    sniffer_list.list[current].pkt_cnt = 1;
	
    sniffer_list.current++;
	pthread_mutex_unlock(&sniff_mutex);

	return SUCCESS;
}

static inline int sniff_list_pull(struct sniff_tuple *data)
{
	uint32_t current = 0;
	uint32_t len = 0;

	pthread_mutex_lock(&sniff_mutex);
	current = sniffer_list.current - 1;
	if (current == -1) {
		pthread_mutex_unlock(&sniff_mutex);
		return FAILURE;
	}

    memcpy(data, &sniffer_list.list[current], sizeof(struct sniff_tuple));

	sniffer_list.current--;
	
	pthread_mutex_unlock(&sniff_mutex);\

	return SUCCESS;
}

static inline int sniff_list_destroy(void)
{
	uint32_t current = sniffer_list.current;
	int i = 0; 

	if (sniffer_list.list != NULL) {
		free(sniffer_list.list);
		sniffer_list.list = NULL;
	}
		
	return 0;
}

#endif