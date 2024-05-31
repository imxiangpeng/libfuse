
#ifndef TCLOUD_BUFFER_H
#define TCLOUD_BUFFER_H
#include <stddef.h>
struct tcloud_buffer {
    char *data;
    size_t size;
    size_t offset;
    
    int preallocated;
};


int tcloud_buffer_alloc(struct tcloud_buffer *buf, size_t size);
int tcloud_buffer_prealloc(struct tcloud_buffer *buf, void* data, size_t size);
int tcloud_buffer_realloc(struct tcloud_buffer *buf, size_t size);
int tcloud_buffer_free(struct tcloud_buffer *buf);
int tcloud_buffer_reset(struct tcloud_buffer *buf);
int tcloud_buffer_append(struct tcloud_buffer *buf, void *data, size_t size);
int tcloud_buffer_append_string(struct tcloud_buffer *buf, const char *str);

#endif
