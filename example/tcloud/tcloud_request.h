#ifndef TCLOUD_REQUEST_H
#define TCLOUD_REQUEST_H

#include "tcloud_buffer.h"

typedef enum {
    TR_METHOD_GET = 0,
    TR_METHOD_POST,
    TR_METHOD_PUT,
} tcloud_request_method_e;
struct tcloud_request {
    struct tcloud_buffer url;
    tcloud_request_method_e method;
    int (*set_query)(struct tcloud_request *, const char *, const char *);
    int (*set_form)(struct tcloud_request *, const char *, const char *);
    int (*set_header)(struct tcloud_request *, const char *, const char *);
    int (*allow_redirect)(struct tcloud_request *, int);
    int (*get)(struct tcloud_request *, const char *url, struct tcloud_buffer *b);
    int (*post)(struct tcloud_request *, const char *url, struct tcloud_buffer *b);
    int (*put)(struct tcloud_request *, const char *url, struct tcloud_buffer *b, size_t size, size_t (*read_callback)(void *ptr, size_t size, size_t nmemb, void *userdata), void *args);
    int (*request)(struct tcloud_request *, const char *url, struct tcloud_buffer *b);
};

struct tcloud_request_pool {
    struct tcloud_request *(*acquire)(struct tcloud_request_pool *self);
    void (*release)(struct tcloud_request_pool *self, struct tcloud_request *request);
};

struct tcloud_request *tcloud_request_new(void);
void tcloud_request_free(struct tcloud_request *req);

struct tcloud_request_pool *tcloud_request_pool_create(int max);
void tcloud_request_pool_destroy(struct tcloud_request_pool *pool);

#endif