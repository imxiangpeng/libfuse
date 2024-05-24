
#include "tcloud_buffer.h"





int tcloud_buffer_alloc(struct tcloud_buffer *buf, size_t size) {
    if (!buf)
        return -1;

    // assert(!buf->data);

    // assert(buf->size > 0);
    buf->offset = 0;
    buf->size = size;
    buf->data = (char *)calloc(1, buf->size);
    if (!buf->data) {
        printf("%s(%d): can not allocate memory ...\n", __FUNCTION__, __LINE__);
        return -1;
    }

    return 0;
}
int tcloud_buffer_realloc(struct tcloud_buffer *buf, size_t size) {
    if (!buf /*|| !buf->data*/)
        return -1;

    buf->data = (char *)realloc(buf->data, size);
    if (!buf->data) {
        printf("%s(%d): can not reallocate memory ...\n", __FUNCTION__, __LINE__);
        return -1;
    }
    buf->size = size;
    memset((void *)((const char *)buf->data + buf->offset), 0, buf->size - buf->offset);
    return 0;
}
int tcloud_buffer_free(struct tcloud_buffer *buf) {
    if (!buf)
        return -1;
    buf->offset = 0;
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
