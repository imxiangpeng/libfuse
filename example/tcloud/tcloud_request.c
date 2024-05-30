// mxp, 20240530, simple libcurl wrapper for http request
// support adjust query & header & form data

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "tcloud_request.h"

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

#include "hr_list.h"
#include "tcloud_buffer.h"

struct tcloud_param {
    char *value;
    struct hr_list_head entry;
};
struct tcloud_request_priv {
    // must make sure it's first element
    struct tcloud_request request;

    tcloud_request_method_e type;
    int allow_redirect;  // allow redirect
    struct hr_list_head query;
    struct hr_list_head form;
    struct curl_slist *headers;
    char *effect_url;
    char url[]; // input url is appended end
};

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

static int _http_request(struct tcloud_request *req, struct tcloud_buffer *b, struct tcloud_buffer *h) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;
    CURLcode res;
    CURL *curl = NULL;
    CURLU *url = NULL;
    int rc = 0;
    long response_code = 0;
    char *redirect_url = NULL;
    struct tcloud_param *p;
    char *payload = NULL;

    // b maybe null, when you do not care data
    if (!req) return -1;

    curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    if (hr_list_empty(&priv->query)) {
        curl_easy_setopt(curl, CURLOPT_URL, &priv->url);
    } else {
        url = curl_url();
        rc = curl_url_set(url, CURLUPART_URL, priv->url, 0);
        hr_list_for_each_entry(p, &priv->query, entry) {
            curl_url_set(url, CURLUPART_QUERY, p->value, CURLU_APPENDQUERY);
        }

        curl_easy_setopt(curl, CURLOPT_CURLU, url);
    }

    if (priv->headers)
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, priv->headers);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _data_receive);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
    
    if (T_REQ_POST == priv->type) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        int len = 1; // end '\0'
        hr_list_for_each_entry(p, &priv->form, entry) {
            len += strlen(p->value);
        }
        payload = (char*)calloc(1, len);
        hr_list_for_each_entry(p, &priv->form, entry) {
            payload = strcat(payload, p->value);
        }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, len - 1);
    }

    // follow redirect
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

    res = curl_easy_perform(curl);

    if (payload) {
        free(payload);
    }

    if (url) {
        curl_url_cleanup(url);
    }

    if (res != CURLE_OK) {
        curl_easy_cleanup(curl);
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return -1;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
    curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &redirect_url);
    if (redirect_url != NULL) {
        priv->effect_url = strdup(redirect_url);
    }
    printf("code:%d, response code:%ld\n", CURLE_OK, response_code);
    printf("code:%d, redirect url:%s\n", CURLE_OK, redirect_url);

    curl_easy_cleanup(curl);
    return 0;
}

struct tcloud_request *tcloud_request_new(tcloud_request_method_e type, const char *url) {
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)calloc(1, sizeof(struct tcloud_request_priv) + strlen(url) + 1);

    priv->type = type;

    memcpy(priv->url, url, strlen(url));

    priv->request.set_query = _set_query;
    priv->request.set_form = _set_form;
    priv->request.set_header = _set_header;
    priv->request.allow_redirect = _allow_redirect;
    priv->request.request = _http_request;

    priv->headers = NULL;
    HR_INIT_LIST_HEAD(&priv->query);
    HR_INIT_LIST_HEAD(&priv->form);
    return (struct tcloud_request *)priv;
}

void tcloud_request_free(struct tcloud_request *req) {
    struct tcloud_param *n, *p;
    struct tcloud_request_priv *priv = (struct tcloud_request_priv *)req;
    if (!req) return;
    
    if (priv->effect_url) {
        free(priv->effect_url);
    }

    if (priv->headers)
        curl_slist_free_all(priv->headers);

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

    free(priv);
}
