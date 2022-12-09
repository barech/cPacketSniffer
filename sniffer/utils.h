#ifndef _UTILS_H
#define _UTILS_H

#include <pthread.h>
#include <stdint.h>

struct config {
	const char *program_name;
	pthread_t *thread;
	uint32_t cpu_number;
	uint32_t thr_number;
} sniff_conf;

unsigned int char2word(const unsigned char *p);
unsigned int char4word(const unsigned char *p);

void error(const char *fmt, ...);
void warning(const char *fmt, ...);

#endif