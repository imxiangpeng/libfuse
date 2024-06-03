
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

// the cycle buffer structure
typedef struct {
    unsigned char *buff;
    unsigned int buff_size;
    unsigned int pos_in;
    unsigned int pos_out;
}cycle_buffer_t;


int cycle_buffer_init(cycle_buffer_t **cycle_buffer, unsigned int data_len);
int cycle_buffer_destroy(cycle_buffer_t **cycle_buffer);
int cycle_buffer_reset(cycle_buffer_t *cycle_buffer);
unsigned int cycle_buffer_available_size(cycle_buffer_t *cycle_buf);
unsigned int cycle_buffer_get(cycle_buffer_t *cycle_buf, unsigned char *buf, unsigned int len);
unsigned int cycle_buffer_put(cycle_buffer_t *cycle_buf, unsigned char *buf, unsigned int len, int immediate);

#endif
