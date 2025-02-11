
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

// Utility function to extract an unsigned int from 2 bytes
unsigned int char2word(const unsigned char *p) {
    unsigned int i = p[0];
    return i << 8 | p[1];
}

// Utility function to extract an unsigned int from 4 bytes
unsigned int char4word(const unsigned char *p) {
    unsigned int res = p[0];

    res = res << 8 | p[1];
    res = res << 8 | p[2];
    res = res << 8 | p[3];

    return res;
}

void error(const char *fmt, ...)
{
	va_list ap;

	(void) fprintf(stderr, "%s: ", sniff_conf.program_name);
	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void) fputc('\n', stderr);
	}

	exit(1);
}

void warning(const char *fmt, ...)
{
    va_list ap;

    (void)fprintf(stderr, "%s: WARNING: ", sniff_conf.program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt) {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    
}