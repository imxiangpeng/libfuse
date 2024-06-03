#ifndef TCLOUD_REQUEST_H
#define TCLOUD_REQUEST_H

#include "tcloud_buffer.h"

typedef enum {
    TR_METHOD_GET=0,
    TR_METHOD_POST
} tcloud_request_method_e;
struct tcloud_request {
    struct tcloud_buffer url;
    tcloud_request_method_e method;
    int (*set_query)(struct tcloud_request *, const char *, const char *);
    int (*set_form)(struct tcloud_request *, const char *, const char *);
    int (*set_header)(struct tcloud_request *, const char *, const char *);
    int (*allow_redirect)(struct tcloud_request *, int);
    int (*get)(struct tcloud_request *,const char* url, struct tcloud_buffer *b, struct tcloud_buffer *h);
    int (*post)(struct tcloud_request *,const char* url, struct tcloud_buffer *b, struct tcloud_buffer *h);
    int (*request)(struct tcloud_request *, const char* url, struct tcloud_buffer *b, struct tcloud_buffer *h);
    // int (*request_params)(struct tcloud_request *, struct tcloud_buffer *b, struct tcloud_buffer *h);
};


struct tcloud_request *tcloud_request_new(void);
void tcloud_request_free(struct tcloud_request *req);

#endif