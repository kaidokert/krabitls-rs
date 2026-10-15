#ifndef KRABITLS_RA6M5_STRING_H
#define KRABITLS_RA6M5_STRING_H

#include <stddef.h>

void * memcpy(void * destination, const void * source, size_t count);
void * memset(void * destination, int value, size_t count);
int memcmp(const void * left, const void * right, size_t count);
void * memchr(const void * buffer, int value, size_t count);

#endif
