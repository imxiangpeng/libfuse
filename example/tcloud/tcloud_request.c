// mxp, 20240530, simple libcurl wrapper for http request
// support adjust query & header & form data

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include "hr_log.h"
#endif

#include "tcloud_request.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "hr_list.h"
#include "tcloud_buffer.h"

struct tcloud_param {
    char *value;
    struct hr_list_head entry;
};
struct tcloud_request_priv {
    // must make sure it's first element
    struct tcloud_request request;

    CURL *curl;
    // tcloud_request_method_e type;
    int allow_redirect;  // allow redirect
    struct hr_list_head query;
    struct hr_list_head form;
    struct curl_slist *headers;
    // char *url
    // char url[];  // input url is appended end

    struct hr_list_head pool_entry;  // can be attached to pool
};

struct tcloud_request_pool_priv {
    struct tcloud_request_pool pool;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    struct hr_list_head head;
};

static struct tcloud_request *tcloud_request_pool_acquire(struct tcloud_request_pool *self) {
    struct tcloud_request_priv *req = NULL;
    struct tcloud_request_pool_priv *priv = (struct tcloud_request_pool_priv *)self;

    if (!priv) {
        return NULL;
    }

    HR_LOGD("%s(%d): acquire..............\n", __FUNCTION__, __LINE__);
    pthread_mutex_lock(&priv->lock);

    if (hr_list_empty(&priv->head)) {
        HR_LOGD("%s(%d): no available wait ..............\n", __FUNCTION__, __LINE__);
        // no available, wait available
        pthread_cond_wait(&priv->cond, &priv->lock);
        HR_LOGD("%s(%d): available wait completed ..............\n", __FUNCTION__, __LINE__);
    }

    req = hr_list_first_entry(&priv->head, struct tcloud_request_priv, pool_entry);

    // take off from list
    hr_list_del(&req->pool_entry);

    pthread_mutex_unlock(&priv->lock);

    HR_LOGD("%s(%d): acquire....%p..........\n", __FUNCTION__, __LINE__, &req->request);
    return &req->request;
}
static void tcloud_request_pool_release(struct tcloud_request_pool *self, struct tcloud_request *req) {
    struct tcloud_request_pool_priv *priv = (struct tcloud_request_pool_priv *)self;

    if (!priv || !req) {
        return;
    }
    HR_LOGD("%s(%d): release ........req:%p......\n", __FUNCTION__, __LINE__, req);
    pthread_mutex_lock(&priv->lock);
    hr_list_add_tail(&((struct tcloud_request_priv *)req)->pool_entry, &priv->head);
    pthread_mutex_unlock(&priv->lock);
    pthread_cond_signal(&priv->cond);
}
struct tcloud_request_pool *tcloud_request_pool_create(int max) {
    struct tcloud_request_pool_priv *priv = (struct tcloud_request_pool_priv *)calloc(1, sizeof(struct tcloud_request_pool_priv));
    if (!priv) {
        // no memory
        return NULL;
    }

    pthread_mutex_init(&priv->lock, NULL);
    pthread_cond_init(&priv->cond, NULL);

    HR_INIT_LIST_HEAD(&priv->head);

    for (int i = 0; i < max; i++) {
        struct tcloud_request_priv *req = (struct tcloud_request_priv *)tcloud_request_new();
        hr_list_add_tail(&req->pool_entry, &priv->head);
    }

    priv->pool.acquire = tcloud_request_pool_acquire;
    priv->pool.release = tcloud_request_pool_release;
    return &priv->pool;
}
void tcloud_request_pool_destroy(struct tcloud_request_pool *self) {
    struct tcloud_request_priv *n, *p;
    struct tcloud_request_pool_priv *priv = (struct tcloud_request_pool_priv *)self;

    if (!priv) {
        return;
    }

    HR_LOGD("%s(%d): ..........\n", __FUNCTION__, __LINE__);
    hr_list_for_each_entry_safe(p, n, &priv->head, pool_entry) {
        hr_list_del(&p->pool_entry);
        tcloud_request_free((struct tcloud_request *)p);
    }

    HR_INIT_LIST_HEAD(&priv->head);

    free(priv);
}
static int _set_query(struct tcloud_request *req, const char *name, const char *val) {
    struct tcloud_param *param = NULL;
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;

    if (!priv || !name) return -1;

    param = (struct tcloud_param *)calloc(1, sizeof(struct tcloud_param));
    HR_INIT_LIST_HEAD(&param->entry);

    asprintf(&param->value, "%s=%s", name, val ? val : "");

    hr_list_add_tail(&param->entry, &priv->query);
    return 0;
}

static int _set_form(struct tcloud_request *req, const char *name, const char *val) {
    struct tcloud_param *param = NULL;
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;

    if (!priv || !name) return -1;

    param = (struct tcloud_param *)calloc(1, sizeof(struct tcloud_param));
    HR_INIT_LIST_HEAD(&param->entry);

    asprintf(&param->value, "%s=%s", name, val ? val : "");

    hr_list_add_tail(&param->entry, &priv->form);

    return 0;
}

static int _set_header(struct tcloud_request *req, const char *name, const char *val) {
    char *str = NULL;
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;

    if (!priv || !name) return -1;

    asprintf(&str, "%s: %s", name, val ? val : "");

    priv->headers = curl_slist_append(priv->headers, str);

    free(str);

    return 0;
}

static int _allow_redirect(struct tcloud_request *req, int val) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;

    priv->allow_redirect = !!val;
    return 0;
}
static size_t _data_receive(void *ptr, size_t size, size_t nmemb,
                            void *userdata) {
    struct tcloud_buffer *buf = (struct tcloud_buffer *)userdata;
    size_t total = size * nmemb;
    if (!ptr || !userdata)
        return total;  // drop all data

    tcloud_buffer_append(buf, ptr, total);
    return total;
}

static int _http_request(struct tcloud_request *req, const char *url, struct tcloud_buffer *b, struct tcloud_buffer *h) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;
    CURLcode rc;
    CURL *curl = NULL;
    CURLU *_curl = NULL;
    long response_code = 0;
    char *redirect_url = NULL;
    struct tcloud_param *n, *p;
    char *payload = NULL;

    // b maybe null, when you do not care data
    if (!req) return -1;

    curl = priv->curl;
    if (!curl) {
        return -1;
    }

    if (hr_list_empty(&priv->query)) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
    } else {
        _curl = curl_url();
        curl_url_set(_curl, CURLUPART_URL, url, 0);
        // release memory directly ...
        // because request maybe reused!
        hr_list_for_each_entry_safe(p, n, &priv->query, entry) {
            curl_url_set(_curl, CURLUPART_QUERY, p->value, CURLU_APPENDQUERY);
            if (p->value) free(p->value);
            hr_list_del(&p->entry);
            free(p);
        }
        curl_easy_setopt(curl, CURLOPT_CURLU, _curl);
    }

    if (priv->headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, priv->headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
    if (!b) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    }

    if (TR_METHOD_POST == req->method) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        int len = 1;  // end '\0'
        hr_list_for_each_entry(p, &priv->form, entry) {
            len += strlen(p->value);
        }
        payload = (char *)calloc(1, len);

        // release memory directly ...
        // because request maybe reused!
        hr_list_for_each_entry_safe(p, n, &priv->form, entry) {
            payload = strcat(payload, p->value);
            if (p->value) free(p->value);
            hr_list_del(&p->entry);
            free(p);
        }

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len - 1);
    }

    // follow redirect
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    rc = curl_easy_perform(curl);

    if (payload) {
        free(payload);
    }

    if (_curl) {
        curl_url_cleanup(_curl);
    }

    if (rc != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rc));
        fprintf(stderr, "curl_easy_perform() url: %s\n", url);
        return -1;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &redirect_url);
    if (redirect_url != NULL) {
    }

    // clean memory, because we may use this socket to other request

    if (priv->headers) {
        curl_slist_free_all(priv->headers);
        priv->headers = NULL;
    }
    hr_list_for_each_entry_safe(p, n, &priv->form, entry) {
        if (p->value) free(p->value);
        hr_list_del(&p->entry);
        free(p);
    }

    return 0;
}

static int _http_do_get(struct tcloud_request *req, const char *url, struct tcloud_buffer *b, struct tcloud_buffer *h) {
    if (!req || !req->request | !url) {
        return -1;
    }

    req->method = TR_METHOD_GET;
    return req->request(req, url, b, h);
}
static int _http_do_post(struct tcloud_request *req, const char *url, struct tcloud_buffer *b, struct tcloud_buffer *h) {
    if (!req || !req->request | !url) {
        return -1;
    }

    req->method = TR_METHOD_POST;
    return req->request(req, url, b, h);
}

static int _http_do_put(struct tcloud_request *req, const char *url, struct tcloud_buffer *b, size_t size, size_t (*read_callback)(void *ptr, size_t size, size_t nmemb, void *userdata), void *args) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;
    CURLcode rc;
    CURL *curl = NULL;
    CURLU *_curl = NULL;
    long response_code = 0;
    char *redirect_url = NULL;
    struct tcloud_param *n, *p;
    char *payload = NULL;

    // b maybe null, when you do not care data
    if (!req) return -1;

    curl = priv->curl;
    if (!curl) {
        return -1;
    }

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    if (hr_list_empty(&priv->query)) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    } else {
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
        _curl = curl_url();
        curl_url_set(_curl, CURLUPART_URL, url, 0);
        // release memory directly ...
        // because request maybe reused!
        hr_list_for_each_entry_safe(p, n, &priv->query, entry) {
            curl_url_set(_curl, CURLUPART_QUERY, p->value, CURLU_APPENDQUERY);
            if (p->value) free(p->value);
            hr_list_del(&p->entry);
            free(p);
        }
        curl_easy_setopt(curl, CURLOPT_CURLU, _curl);
    }
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);

    if (priv->headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, priv->headers);

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
    if (!b) {
        curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
    }
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);

    curl_easy_setopt(curl, CURLOPT_PUT, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, (void *)args);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE, size);
 
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    
     /* enable all supported built-in compressions */
    // curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");   

    // follow redirect
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    rc = curl_easy_perform(curl);

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    if (payload) {
        free(payload);
    }

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    if (_curl) {
        curl_url_cleanup(_curl);
    }

    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    if (rc != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rc));
        fprintf(stderr, "curl_easy_perform() url: %s\n", url);
        return -1;
    }
    HR_LOGD("%s(%d): response url:%s\n", __FUNCTION__, __LINE__, url);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &redirect_url);
    if (redirect_url != NULL) {
    }

    // clean memory, because we may use this socket to other request

    if (priv->headers) {
        curl_slist_free_all(priv->headers);
        priv->headers = NULL;
    }
    hr_list_for_each_entry_safe(p, n, &priv->form, entry) {
        if (p->value) free(p->value);
        hr_list_del(&p->entry);
        free(p);
    }

    return 0;
}
struct tcloud_request *tcloud_request_new(void) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)calloc(1, sizeof(struct tcloud_request_priv));

    priv->curl = curl_easy_init();
    if (!priv->curl) {
        return NULL;
    }

    priv->request.method = TR_METHOD_GET;

    // tcloud_buffer_alloc(&priv->url);

    priv->request.set_query = _set_query;
    priv->request.set_form = _set_form;
    priv->request.set_header = _set_header;
    priv->request.allow_redirect = _allow_redirect;
    priv->request.get = _http_do_get;
    priv->request.post = _http_do_post;
    priv->request.put = _http_do_put;
    priv->request.request = _http_request;

    priv->headers = NULL;
    HR_INIT_LIST_HEAD(&priv->query);
    HR_INIT_LIST_HEAD(&priv->form);

    // init for pool
    HR_INIT_LIST_HEAD(&priv->pool_entry);
    return (struct tcloud_request *)priv;
}

void tcloud_request_free(struct tcloud_request *req) {
    struct tcloud_param *n, *p;
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;
    if (!req) return;

    // you should not release, when it's attached on one pool
    if (priv->curl) {
        curl_easy_cleanup(priv->curl);
        priv->curl = NULL;
    }

    if (priv->headers) {
        curl_slist_free_all(priv->headers);
        priv->headers = NULL;
    }

    hr_list_for_each_entry_safe(p, n, &priv->query, entry) {
        if (p->value) free(p->value);
        hr_list_del(&p->entry);
        free(p);
    }

    hr_list_for_each_entry_safe(p, n, &priv->form, entry) {
        if (p->value) free(p->value);
        hr_list_del(&p->entry);
        free(p);
    }

    HR_INIT_LIST_HEAD(&priv->pool_entry);
    free(priv);
}
