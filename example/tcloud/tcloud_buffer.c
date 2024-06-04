
#include "tcloud_buffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRING_EXTRA_SIZE (64)

int tcloud_buffer_alloc(struct tcloud_buffer *buf, size_t size) {
    if (!buf)
        return -1;

    // assert(!buf->data);

    // assert(buf->size > 0);
    memset((void *)buf, 0, sizeof(*buf));
    buf->offset = 0;
    buf->size = size;
    buf->data = (char *)calloc(1, buf->size);
    if (!buf->data) {
        printf("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
        return -1;
    }
    // buf->preallocated = 0;

    return 0;
}

int tcloud_buffer_prealloc(struct tcloud_buffer *buf, void *data, size_t size) {
    if (!buf)
        return -1;

    // assert(!buf->data);

    // assert(buf->size > 0);
    memset((void *)buf, 0, sizeof(*buf));
    buf->offset = 0;
    buf->size = size;
    buf->data = data;
    buf->preallocated = 1;

    return 0;
}

int tcloud_buffer_realloc(struct tcloud_buffer *buf, size_t size) {
    void *data = NULL;
    if (!buf /*|| !buf->data*/)
        return -1;

    if (buf->preallocated) {
        // not support!
        return -1;
    }

    data = (char *)realloc(buf->data, size);
    if (!data) {
        printf("%s(%d): can not reallocate memory ...\n", __FUNCTION__, __LINE__);
        return -1;
    }
    buf->data = data;
    buf->size = size;
    memset((void *)((const char *)buf->data + buf->offset), 0, buf->size - buf->offset);
    return 0;
}
int tcloud_buffer_free(struct tcloud_buffer *buf) {
    if (!buf)
        return -1;
    buf->offset = 0;
    if (buf->preallocated != 0) {
        return 0;
    }
    memset((void *)buf->data, 0, buf->size);

    free(buf->data);

    memset((void *)buf, 0, sizeof(*buf));
    return 0;
}
int tcloud_buffer_reset(struct tcloud_buffer *buf) {
    if (!buf || !buf->data)
        return -1;
    buf->offset = 0;
    memset((void *)buf->data, 0, buf->size);

    return 0;
}

int tcloud_buffer_append(struct tcloud_buffer *buf, void *data, size_t size) {
    if (!buf || !buf->data || !data || size == 0)
        return -1;
    if (size > buf->size - buf->offset) {
        int ret = tcloud_buffer_realloc(buf, buf->size + size);
        if (ret != 0) {
            return -1;  // memory not enough
        }
    }
    memcpy((void *)(buf->data + buf->offset), data, size);
    buf->offset += size;
    return 0;
}

int tcloud_buffer_append_string(struct tcloud_buffer *buf, const char *str) {
    int length = 0;
    if (!buf || !str) return -1;

    length = strlen(str); // '\0'
    if (length > buf->size - buf->offset) {
        int ret = tcloud_buffer_realloc(buf, buf->size + length + STRING_EXTRA_SIZE + 1);
        if (ret != 0) {
            return -1;  // memory not enough
        }
    }
    memcpy((void *)(buf->data + buf->offset), (void*)str, length);
    buf->offset += length;
   
    return 0;
}



/*the len must be power of 2 */
#define MAX_CYCLE_BUFFER_LEN (0x80000) /*(0x10000)*/ /*1M/ 4k = 256 , it means we can transport 256 sections at least*/
#define MIN(X, Y) (X) > (Y) ? (Y) : (X)
#define MAX(X, Y) (X) > (Y) > (X) : (Y)

int cycle_buffer_init(cycle_buffer_t **cycle_buffer, unsigned int data_len){
    int size = data_len; //MAX_ESINJECT_BUFFER_LEN;
    if ( !cycle_buffer || data_len <= 0 ) {
        return -1;
    }
    if ( size & (size - 1) ) {
        printf(" size must be power of 2 \n");
        return -1;
    }
    *cycle_buffer = (cycle_buffer_t *)malloc(sizeof(cycle_buffer_t));
    if ( !(*cycle_buffer) ) {
        return -1;
    }
    memset((void*) (*cycle_buffer), 0, sizeof(cycle_buffer_t));

    (*cycle_buffer)->buff_size = size;
    (*cycle_buffer)->pos_in = (*cycle_buffer)->pos_out = 0;


    (*cycle_buffer)->buff = (unsigned char *)malloc((*cycle_buffer)->buff_size);
    if ( !(*cycle_buffer)->buff ) {

        free(*cycle_buffer);
        return -1;
    }

    memset((*cycle_buffer)->buff, 0, (*cycle_buffer)->buff_size);

    return 0;
}

int cycle_buffer_destroy(cycle_buffer_t **cycle_buffer){
    if ( !cycle_buffer || !(*cycle_buffer) ) {
        return -1;
    }
    if ( (*cycle_buffer)->buff ) {
        free((*cycle_buffer)->buff);
        (*cycle_buffer)->buff = NULL;
    }
    memset((void *)(*cycle_buffer), 0, sizeof(cycle_buffer_t));
    free(*cycle_buffer);
    *cycle_buffer = NULL;
    return 0;
}

int cycle_buffer_reset(cycle_buffer_t *cycle_buffer){


    if ( !cycle_buffer ) {
        return -1;
    }
    cycle_buffer->pos_in = cycle_buffer->pos_out = 0;
    return 0;
}

unsigned int cycle_buffer_get(cycle_buffer_t *cycle_buf, unsigned char *buf, unsigned int len){
    cycle_buffer_t *cycle_buff = cycle_buf;
    if ( !cycle_buff ) {
        printf("%s(%d): invalid handle ...\n", __FUNCTION__, __LINE__);
        return 0;
    }
    unsigned int left = 0;

    len = MIN(len, (cycle_buff->pos_in - cycle_buff->pos_out));
    left = MIN(len, cycle_buff->buff_size - (cycle_buff->pos_out & (cycle_buff->buff_size - 1)));
    memcpy((void *)buf, cycle_buff->buff + (cycle_buff->pos_out & (cycle_buff->buff_size - 1)), left);
    memcpy((void *)(buf + left), cycle_buff->buff , len - left);
    cycle_buff->pos_out += len;
    return len;
}

unsigned int cycle_buffer_put(cycle_buffer_t *cycle_buf, unsigned char *buf, unsigned int len, int immediate){
    cycle_buffer_t *cycle_buff = cycle_buf;
    unsigned real_len = len;
    if ( !cycle_buff ) {

        printf("%s(%d): invalid handle ...\n", __FUNCTION__, __LINE__);
        return 0;
    }
    unsigned int left = 0;
    /*2014-11-16, firstly check enough space otherwise return immediate do not wait block*/
    if( immediate)
    {
        real_len = MIN(real_len, cycle_buff->buff_size - (cycle_buff->pos_in - cycle_buff->pos_out));

        if( real_len < len)
        {
            printf("%s(%d): no enough space for :%d\n", __FUNCTION__, __LINE__, len);
            return 0;
        }
    }

    real_len = len;
    real_len = MIN(real_len, cycle_buff->buff_size - (cycle_buff->pos_in - cycle_buff->pos_out));

    if( immediate && real_len < len)
    {
        printf("%s(%d): no enough space for :%d\n", __FUNCTION__, __LINE__, len);
        return 0;
    }
    left = MIN(real_len, cycle_buff->buff_size - (cycle_buff->pos_in & (cycle_buff->buff_size - 1)));
    memcpy((void *)(cycle_buff->buff + (cycle_buff->pos_in & (cycle_buff->buff_size - 1))), (void *)buf, left);
    memcpy((void *)cycle_buff->buff , buf + left, real_len - left);


    cycle_buff->pos_in += real_len;

    return real_len;
}

unsigned int cycle_buffer_data_size(cycle_buffer_t *cycle_buf) {
    return cycle_buf->pos_in - cycle_buf->pos_out;
}
unsigned int cycle_buffer_available_size(cycle_buffer_t *cycle_buf) {
    return cycle_buf->buff_size - (cycle_buf->pos_in - cycle_buf->pos_out);
}