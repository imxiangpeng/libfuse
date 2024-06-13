#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <json-c/json.h>
#include <json-c/json_object.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "hr_log.h"
#include "tcloud/hr_list.h"
#include "tcloud/tcloud_utils.h"
#include "tcloud_buffer.h"
#include "tcloud_request.h"

const char *_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#define CHUNK_SIZE (1024 * 1024 * 10)
#define MAX_QUEUE (30)

#define CHUNK_10M (1024 * 1024 * 10)

#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

struct {
    size_t slice_size;
    size_t min;
    size_t max;
} _slice_table[] = {
    {CHUNK_10M, 0, 1000L * CHUNK_10M},
    {CHUNK_10M * 2, 1000L * CHUNK_10M, 1000L * CHUNK_10M * 2},
    {CHUNK_10M * 5, 1000L * CHUNK_10M * 2, 2000L * CHUNK_10M * 5},
    // n >= 6
    // 2000*(n-1)*10MB  ->  2000_n_10MB  -> 2000 片 n*10MB
    // {CHUNK_10M * n, 1000L * CHUNK_10M * ( n - 1), 2000L * CHUNK_10M * n},
};

const char *secret = "705DD28638B377C924486C7132D4AB9A";
const char *session_key = "ce152573-2cc1-4438-a3db-efe63a43993c";
const char *aes_public =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZLyV4gHNDUGJMZoOcYauxmNEsKrc0TlLeBEVVIIQNzG4WqjimceOj5R9ETwDeeSN3yejAKLGHgx83lyy2wBjvnbfm/nLObyWwQD/09CmpZdxoFYCH6rdDjRpwZOZ2nXSZpgkZXoOBkfNXNxnN74aXtho2dqBynTw3NFTWyQl8BQIDAQAB"
    "\n-----END PUBLIC KEY-----";

struct write_chunk {
    off_t offset;
    size_t size;
    void *payload;

    struct hr_list_head entry;
};

int _fd = -1;

struct write_queue {
    int seq;

    int is_eof;
    char *name;
    size_t total_size;

    int slice_size;
    char md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    char slice_md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    struct tcloud_buffer slice_md5sum_data;
    EVP_MD_CTX *mdctx;

    char *upload_id;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int num;
    off_t processing_offset;
    off_t chunk_offset;
    struct hr_list_head head;
} _queue;

struct upload_queue {
    int part;
    char *url;
    size_t content_length;
    // md5
    char md5sum[MD5_DIGEST_LENGTH * 2 + 1];
    EVP_MD_CTX *mdctx;
    CURLM *multi;
    CURL *curl;  // opened handle
    struct hr_list_head head;
} _upload_queue;

struct init_multi_upload_data {
    int type;
    char *host;
    char *id;
    int exists;
};

struct multi_upload_urls_resp {
    char *url;
    char *header;
};

static pthread_t _tid = 0;

static int _dump_fd = -1;

static int do_stream_upload(struct upload_queue *upload);
static int do_commit_upload(struct write_queue *queue);

void chunk_free(struct write_chunk *ch) {
    if (!ch) return;

    HR_INIT_LIST_HEAD(&ch->entry);

    if (ch->payload) {
        free(ch->payload);
    }

    free(ch);
}

static int open_chunk(int seq) {
    char tmp[512] = {0};
    snprintf(tmp, sizeof(tmp), "/home/alex/workspace/workspace/libfuse/libfuse/build/upload.dump.%04d", seq);

    return open(tmp, O_CREAT | O_TRUNC | O_RDWR, 0755);
}
static void *write_routin(void *arg) {
    while (1) {
        int should_upload = 0;
        pthread_mutex_lock(&_queue.mutex);
        if (hr_list_empty(&_queue.head) || _queue.num == 0) {
            // we should wait
            HR_LOGD("%s(%d): now queue is empty ...\n", __FUNCTION__, __LINE__);
            if (_queue.is_eof == 1) {
                HR_LOGD("%s(%d): now queue is empty, goto finished ...\n", __FUNCTION__, __LINE__);
                // finished un uploaded data
                pthread_mutex_unlock(&_queue.mutex);
                break;
            }
            pthread_cond_wait(&_queue.cond, &_queue.mutex);
            pthread_mutex_unlock(&_queue.mutex);
            continue;
        }

        struct write_chunk *ch = hr_list_first_entry(&_queue.head, struct write_chunk, entry);
        if (!ch) {
            pthread_mutex_unlock(&_queue.mutex);
            continue;
        }

        // 0 chunk -> write end
        if (ch->size == 0) {
            break;
        }

        if (_queue.processing_offset == 0) {
            _queue.mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(_queue.mdctx, EVP_md5(), NULL);
        }

        if (_queue.chunk_offset == 0) {
            _upload_queue.mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(_upload_queue.mdctx, EVP_md5(), NULL);
        }

        HR_LOGD("%s(%d): now request:%p -> %ld, wait _queue.processing_offset:%ld ... num:%d\n", __FUNCTION__, __LINE__, ch, ch->offset, _queue.processing_offset, _queue.num);
        if (_queue.processing_offset == ch->offset) {
            HR_LOGD("%s(%d): found chunk at %ld ...\n", __FUNCTION__, __LINE__, ch->offset);
            // take off from queue

            if (_dump_fd == -1) {
                _dump_fd = open_chunk(_queue.seq);
            }
            // dump data every 10M
            if (_queue.chunk_offset + ch->size < CHUNK_SIZE) {
                // continue this chunk
                write(_dump_fd, ch->payload, ch->size);
                EVP_DigestUpdate(_queue.mdctx, ch->payload, ch->size);
                EVP_DigestUpdate(_upload_queue.mdctx, ch->payload, ch->size);
                _queue.chunk_offset += ch->size;
                _queue.processing_offset = ch->offset + ch->size;

                hr_list_move_tail(&ch->entry, &_upload_queue.head);
                _upload_queue.content_length += ch->size;
                // hr_list_del(&ch->entry);
                _queue.num--;
                HR_LOGD("%s(%d): consume total chunk..... next offset:%ld\n", __FUNCTION__, __LINE__, _queue.processing_offset);

                pthread_mutex_unlock(&_queue.mutex);
                pthread_cond_signal(&_queue.cond);
                continue;
            } else {
                // we will fill one chunk and try to upload
                size_t ws = CHUNK_SIZE - _queue.chunk_offset;
                write(_dump_fd, ch->payload, ws);
                EVP_DigestUpdate(_queue.mdctx, ch->payload, ws);
                EVP_DigestUpdate(_upload_queue.mdctx, ch->payload, ws);
                _queue.chunk_offset += ws;
                _queue.processing_offset = ch->offset + ws;
                _upload_queue.content_length += ws;

                close(_dump_fd);
                _dump_fd = -1;
                // open new chunk
                //_queue.seq++;
                // ch->offset += ws;
                // ch->size -= ws;

                if (ch->size - ws > 0) {
                    // split this chunk into two chunk
                    struct write_chunk *c1 = (struct write_chunk *)calloc(1, sizeof(struct write_chunk));
                    HR_INIT_LIST_HEAD(&c1->entry);

                    c1->offset = ch->offset;
                    c1->size = ws;
                    c1->payload = calloc(1, ws);
                    // copy data to new chunk
                    memcpy(c1->payload, ch->payload, ws);
                    // add data to upload queue
                    hr_list_add_tail(&c1->entry, &_upload_queue.head);
                    _upload_queue.content_length += ws;

                    // keep ch in incoming queue
                    ch->offset += ws;
                    ch->size -= ws;
                    // adjust left data to begin
                    memcpy(ch->payload, ch->payload + ws, ch->size);

                    HR_LOGD("%s(%d): split ..... next offset:%ld, adjust chunk:%ld, size:%ld\n", __FUNCTION__, __LINE__, _queue.processing_offset, ch->offset, ch->size);
                } else {
                    HR_LOGD("%s(%d): consume total chunk..... next offset:%ld\n", __FUNCTION__, __LINE__, _queue.processing_offset);
                    hr_list_move_tail(&ch->entry, &_upload_queue.head);
                    // hr_list_del(&ch->entry);
                    _queue.num--;
                }
                _queue.seq++;
                _queue.chunk_offset = 0;

                pthread_mutex_unlock(&_queue.mutex);
                pthread_cond_signal(&_queue.cond);

                unsigned char *md5_digest = NULL;
                unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
                char *ptr = _upload_queue.md5sum;
                int available = sizeof(_upload_queue.md5sum);

                md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
                EVP_DigestFinal_ex(_upload_queue.mdctx, md5_digest, &md5_digest_len);
                EVP_MD_CTX_free(_upload_queue.mdctx);
                _upload_queue.mdctx = NULL;

                for (unsigned int i = 0; i < md5_digest_len; i++) {
                    if (available < 2) break;
                    int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
                    available -= ret;
                    ptr += ret;
                }
                OPENSSL_free(md5_digest);

                HR_LOGD("%s(%d): now md5sum:%s\n", __FUNCTION__, __LINE__, _upload_queue.md5sum);

                if (_upload_queue.part != 0) {
                    tcloud_buffer_append_string(&_queue.slice_md5sum_data, "\n");
                }
                tcloud_buffer_append_string(&_queue.slice_md5sum_data, _upload_queue.md5sum);
                // try upload
                do_stream_upload(&_upload_queue);
                _upload_queue.part++;

                // release all elements

                _upload_queue.content_length = 0;
                HR_INIT_LIST_HEAD(&_upload_queue.head);
            }

        } else {
            HR_LOGD("%s(%d): we should wait chunk at %ld but found:%ld...\n", __FUNCTION__, __LINE__, _queue.processing_offset, ch->offset);
            pthread_cond_wait(&_queue.cond, &_queue.mutex);
        }

        // pthread_mutex_unlock(&_queue.mutex);
        // pthread_cond_signal(&_queue.cond);

        // usleep(1000 * 1000);
    }

    HR_LOGD("%s(%d): finished .........\n", __FUNCTION__, __LINE__);

    // update left data
    if (!hr_list_empty(&_upload_queue.head)) {
        unsigned char *md5_digest = NULL;
        unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
        char *ptr = _upload_queue.md5sum;
        int available = sizeof(_upload_queue.md5sum);

        md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
        EVP_DigestFinal_ex(_upload_queue.mdctx, md5_digest, &md5_digest_len);
        EVP_MD_CTX_free(_upload_queue.mdctx);
        _upload_queue.mdctx = NULL;

        for (unsigned int i = 0; i < md5_digest_len; i++) {
            if (available < 2) break;
            int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
            available -= ret;
            ptr += ret;
        }
        OPENSSL_free(md5_digest);

        HR_LOGD("%s(%d): now md5sum:%s\n", __FUNCTION__, __LINE__, _upload_queue.md5sum);
        if (_upload_queue.part != 0) {
            tcloud_buffer_append_string(&_queue.slice_md5sum_data, "\n");
        }
        tcloud_buffer_append_string(&_queue.slice_md5sum_data, _upload_queue.md5sum);
        // try upload
        do_stream_upload(&_upload_queue);
        _upload_queue.part++;
        _queue.slice_size = _upload_queue.part;
        //_upload_queue.content_length = 0;
        HR_INIT_LIST_HEAD(&_upload_queue.head);
    }

    unsigned char *md5_digest = NULL;
    unsigned int md5_digest_len = EVP_MD_size(EVP_md5());
    char *ptr = _queue.md5sum;
    int available = sizeof(_queue.md5sum);

    md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
    EVP_DigestFinal_ex(_queue.mdctx, md5_digest, &md5_digest_len);

    for (unsigned int i = 0; i < md5_digest_len; i++) {
        if (available < 2) break;
        int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
        available -= ret;
        ptr += ret;
    }
    OPENSSL_free(md5_digest);

    // generate slice_md5sum
    // if one slice, copy _queue.slice_md5sum_data.data -> slice_md5sum, no need calc again
    HR_LOGD("%s(%d): slice_md5sum data:%s\n", _queue.slice_md5sum_data.data);
    if (_queue.slice_size == 1) {
        snprintf(_queue.slice_md5sum, sizeof(_queue.slice_md5sum), "%s", _queue.slice_md5sum_data.data);
    } else {
        EVP_DigestUpdate(_queue.mdctx, _queue.slice_md5sum_data.data, _queue.slice_md5sum_data.offset);
        md5_digest_len = EVP_MD_size(EVP_md5());
        ptr = _queue.slice_md5sum;
        available = sizeof(_queue.slice_md5sum);

        md5_digest = (unsigned char *)OPENSSL_malloc(md5_digest_len);
        EVP_DigestFinal_ex(_queue.mdctx, md5_digest, &md5_digest_len);

        for (unsigned int i = 0; i < md5_digest_len; i++) {
            if (available < 2) break;
            int ret = snprintf(ptr, available, "%02X", md5_digest[i]);
            available -= ret;
            ptr += ret;
        }
        OPENSSL_free(md5_digest);

        HR_LOGD("%s(%d): slice_md5sum:%s\n", _queue.slice_md5sum);
    }
    EVP_MD_CTX_free(_queue.mdctx);
    _queue.mdctx = NULL;

    do_commit_upload(&_queue);
    return NULL;
}

static int do_write(char *data, off_t off, size_t length) {
    if (!data || length == 0) return -1;
    struct write_chunk *ch = (struct write_chunk *)calloc(1, sizeof(struct write_chunk));
    if (!ch) {
        return -ENOMEM;
    }

    ch->offset = off;
    ch->size = length;
    ch->payload = calloc(1, length);
    memmove(ch->payload, data, length);

    // HR_LOGD("%s(%d): do write in -> %d ...\n", __FUNCTION__, __LINE__, _queue.num);
    pthread_mutex_lock(&_queue.mutex);
    if (_queue.num > MAX_QUEUE) {
        HR_LOGD("%s(%d): now queue is too long -> %d ...\n", __FUNCTION__, __LINE__, _queue.num);
        pthread_cond_wait(&_queue.cond, &_queue.mutex);
    }

    _queue.num++;

    struct hr_list_head *n = NULL, *p = NULL;
    int found = 0;

    hr_list_for_each_prev(p, &_queue.head) {
        struct write_chunk *c1 = container_of(p, struct write_chunk, entry);
        // HR_LOGD("%s(%d): cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);

        // the last should always bigger
        if (c1->offset < ch->offset) {
            found = 1;
            // HR_LOGD("%s(%d): found cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);
            break;
        }
    }

    // HR_LOGD("%s(%d): add request:%p -> %ld...\n", __FUNCTION__, __LINE__, ch, ch->offset);
    /*if (found == 0) {
        hr_list_add_tail(&ch->entry, &_queue.head);
    } else*/
    {
        hr_list_add(&ch->entry, p);
    }

    pthread_mutex_unlock(&_queue.mutex);
    pthread_cond_signal(&_queue.cond);

    HR_LOGD("%s(%d): do write out -> %d ...\n", __FUNCTION__, __LINE__, _queue.num);
    return 0;
}

int do_write_sync(char *data, off_t off, size_t length) {
    return 0;
}
char *hex_to_string(const char *data, size_t len) {
    int size = 0;
    size_t offset = 0;
    char *ptr = NULL;
    if (!data) return NULL;

    size = len * 2 + 1;

    ptr = (unsigned char *)calloc(1, size);
    if (!ptr) return NULL;

    for (int i = 0; i < len; i++) {
        int rc = snprintf(ptr + offset, size - offset, "%02x", data[i] & 0xFF);
        offset += rc;
    }

    return ptr;
}

static int _tcloud_drive_fill_final(struct tcloud_request *req, const char *uri, struct tcloud_buffer *params) {
    char tmp[512] = {0};
    char *params_query = NULL;
    if (!req) return -1;

    char uuid[UUID_STR_LEN] = {0};
    tcloud_utils_generate_uuid(uuid, sizeof(uuid));

    char date[64] = {0};
    tcloud_utils_http_date_string(date, sizeof(date));

    req->set_header(req, "Accept", "application/json;charset=UTF-8");
    req->set_header(req, "Date", date);
    req->set_header(req, "SessionKey", session_key);
    req->set_header(req, "X-Request-ID", uuid);

    char *signature_data = NULL;
    if (params) {
        struct tcloud_buffer r;
        tcloud_buffer_alloc(&r, 512);
        printf("raw params:%s\n", params->data);
        int rc = tcloud_utils_aes_ecb_data((unsigned char *)secret, params->data, params->offset, &r);
        // int rc = tcloud_utils_rsa_encrypt(aes_public, params->data, params->offset, tmp, &rsa_len);
        printf("aes enc result:%d, result:%ld\n", rc, r.offset);

        params_query = hex_to_string(r.data, r.offset);
        printf("encryption text:%s\n", params_query);
        tcloud_buffer_free(&r);
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s&params=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date, params_query);
    } else {
        asprintf(&signature_data, "SessionKey=%s&Operate=%s&RequestURI=%s&Date=%s", session_key, req->method == TR_METHOD_GET ? "GET" : "POST", uri, date);
    }

    HR_LOGD("%s(%d): signature data:%s\n", __FUNCTION__, __LINE__, signature_data);
    char *signature = tcloud_utils_hmac_sha1(secret, (const unsigned char *)signature_data, strlen(signature_data));
    HR_LOGD("%s(%d): signature:%s\n", __FUNCTION__, __LINE__, signature);
    req->set_header(req, "Signature", signature);
    free(signature_data);
    free(signature);

    req->set_header(req, "Referer", "https://cloud.189.cn");

    req->set_query(req, "clientType", "TELEPC");
    req->set_query(req, "version", "6.2");
    req->set_query(req, "channelId", "web_cloud.189.cn");
    snprintf(tmp, sizeof(tmp), "%d_%d", rand(), rand());
    req->set_query(req, "rand", tmp);
    if (params_query) {
        req->set_query(req, "params", params_query);
        free(params_query);
    }

    return 0;
}
int init_multi_upload(const char *name, size_t size, uint64_t parent_id, struct init_multi_upload_data *data) {
    struct tcloud_buffer b;
    struct tcloud_request *req = tcloud_request_new();

    const char *url = "http://upload.cloud.189.cn/person/initMultiUpload";

    const char *action = "/person/initMultiUpload";

    char tmp[256] = {0};

    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "parentFolderId=%ld", parent_id);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileName=");
    // care that you should encode filename when it contains zh
    char *escape_name = curl_easy_escape(NULL, name, strlen(name));
    tcloud_buffer_append_string(&b, escape_name);
    curl_free(escape_name);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "fileSize=");
    snprintf(tmp, sizeof(tmp), "%ld", size);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "sliceSize=");
    snprintf(tmp, sizeof(tmp), "%ld", (size_t)CHUNK_10M);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    tcloud_buffer_append_string(&b, "lazyCheck=1");

    req->method = TR_METHOD_GET;
    _tcloud_drive_fill_final(req, action, &b);

    tcloud_buffer_reset(&b);
    req->request(req, url, &b, NULL);

    printf("result:(%ld)%s\n", b.offset, b.data);

    tcloud_request_free(req);

    if (!data) {
        return 0;
    }
    struct json_object *root = NULL, *code = NULL, *json_data = NULL;
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "code", &code);
    if (!code || strcmp("SUCCESS", json_object_get_string(code)) != 0) {
        json_object_put(root);
        printf(" can not parse json or request failed.....\n");
        return -1;
    }
    json_object_object_get_ex(root, "data", &json_data);
    if (!json_data) {
        json_object_put(root);
        return -1;
    }

    struct json_object *json_upload_type = NULL, *json_upload_host = NULL, *json_upload_file_id = NULL, *json_file_data_exists = NULL;
    json_object_object_get_ex(json_data, "uploadType", &json_upload_type);
    json_object_object_get_ex(json_data, "uploadHost", &json_upload_host);
    json_object_object_get_ex(json_data, "uploadFileId", &json_upload_file_id);
    json_object_object_get_ex(json_data, "fileDataExists", &json_file_data_exists);

    data->type = json_object_get_int(json_upload_type);
    data->host = strdup(json_object_get_string(json_upload_host));
    data->id = strdup(json_object_get_string(json_upload_file_id));
    data->exists = json_object_get_int(json_file_data_exists);

    HR_LOGD("%s(%d): .uploadType:%d, uploadHost:%s, uploadFileId:%s, fileDataExists:%d...\n", __FUNCTION__, __LINE__,
            json_object_get_int(json_upload_type),
            json_object_get_string(json_upload_host),
            json_object_get_string(json_upload_file_id),
            json_object_get_int(json_file_data_exists));
    json_object_put(root);
    return 0;
}

int get_multi_upload_urls(const char *id, int part, const char *md5, struct multi_upload_urls_resp *res) {
    struct tcloud_buffer b;
    struct tcloud_request *req = tcloud_request_new();

    const char *url = "http://upload.cloud.189.cn/person/getMultiUploadUrls";

    const char *action = "/person/getMultiUploadUrls";

    char tmp[256] = {0};

    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "uploadFileId=%s", id);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "partInfo=%d-%s", part, md5);
    tcloud_buffer_append_string(&b, tmp);

    req->method = TR_METHOD_GET;
    _tcloud_drive_fill_final(req, action, &b);

    tcloud_buffer_reset(&b);
    req->request(req, url, &b, NULL);

    printf("result:(%ld)%s\n", b.offset, b.data);

    tcloud_request_free(req);

    struct json_object *root = NULL, *code = NULL, *result_data = NULL;
    root = json_tokener_parse(b.data);
    tcloud_buffer_free(&b);
    if (!root) {
        printf(" can not parse json .....\n");
        return -1;
    }
    json_object_object_get_ex(root, "code", &code);
    if (!code || strcmp("SUCCESS", json_object_get_string(code)) != 0) {
        json_object_put(root);
        printf(" can not parse json or request failed.....\n");
        return -1;
    }

    struct json_object *json_upload_urls = NULL;
    json_object_object_get_ex(root, "uploadUrls", &json_upload_urls);

    const char *part_number_prefix = "partNumber_";
    json_object_object_foreach(json_upload_urls, key, val) {
        printf("keys:%s\n", key);
        if (!strncmp(key, part_number_prefix, strlen(part_number_prefix))) {
            res->url = strdup(json_object_get_string(json_object_object_get(val, "requestURL")));
            res->header = strdup(json_object_get_string(json_object_object_get(val, "requestHeader")));
            break;
        }
    }
    json_object_put(root);

    return 0;
}

static size_t _read_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    int rs = 0;
    struct upload_queue *upload = (struct upload_queue *)userdata;
    // always return one chunk

    // HR_LOGD("%s(%d): read data :%ld\n", __FUNCTION__, __LINE__, size * nmemb);
    if (hr_list_empty(&upload->head)) {
        return 0;
    }

    struct write_chunk *ch = hr_list_first_entry(&upload->head, struct write_chunk, entry);
    rs = ch->size;

    // HR_LOGD("%s(%d): read data :%ld, current chunk:%ld\n", __FUNCTION__, __LINE__,  size * nmemb, ch->size);
    if (rs <= size * nmemb) {
        memcpy(ptr, ch->payload, rs);
        hr_list_del(&ch->entry);
        // free ch
        return rs;
    }
    rs = size * nmemb;
    memcpy(ptr, ch->payload, rs);
    ch->offset += rs;
    ch->size -= rs;
    memcpy(ch->payload, ch->payload + rs, ch->size);
    // HR_LOGD("%s(%d): split read data :%ld, current chunk:%ld, real read:%ld\n", __FUNCTION__, __LINE__,  size * nmemb, ch->size, rs);
    // leave it later delete
    return rs;
}

static int do_stream_upload(struct upload_queue *upload) {
    struct multi_upload_urls_resp res;

    struct tcloud_buffer b;
    struct tcloud_request *req = tcloud_request_new();

    tcloud_buffer_alloc(&b, 512);
    memset((void *)&res, 0, sizeof(res));
    HR_LOGD("%s(%d): upload id:%s, part:%d, md5sum:%s\n", __FUNCTION__, __LINE__, _queue.upload_id, upload->part, upload->md5sum);
    get_multi_upload_urls(_queue.upload_id, upload->part + 1, upload->md5sum, &res);

    HR_LOGD("%s(%d): response url:%s, header:%s\n", __FUNCTION__, __LINE__, res.url, res.header);

    char *saveptr, *saveptr2;
    char *token = strtok_r(res.header, "&", &saveptr);
    while (token) {
        char *name = strtok_r(token, "=", &saveptr2);
        char *value = saveptr2;//strtok_r(saveptr2, "=", &saveptr2);
        printf("name:%s, val:%s\n", name, value);

        req->set_header(req, name, value);

        token = strtok_r(saveptr, "&", &saveptr);
    }

    // const char* action = "";

    // char *murl = "http://media-sdqd-fy-person.sdoss.ctyunxs.cn/PERSONCLOUD/ed44c77a-bd6b-4626-b24b-ba7a9b9f0a32.bin?partNumber=4&uploadId=2~X_FmL_9DbnyshsAAhiWB5y3pJ3-tXDH";
    // murl = "https://media-sdqd-fy-person.sdoss.ctyunxs.cn/PERSONCLOUD/f26e5dfd-839f-4f5a-b972-17119dbb153b.bin?partNumber\u003d1\u0026uploadId\u003d2~SXhXmQoL_mMVAlbmM6DYbQB7fOWU13F";
    
    if (strncmp(res.url, "https://", 8)) {
        strcpy(res.url, res.url + 5);
    }
    HR_LOGD("%s(%d): response url:%s, header:%s\n", __FUNCTION__, __LINE__, res.url, res.header);
    char tmp[128] = {0};
    snprintf(tmp, sizeof(tmp), "%ld", upload->content_length);
    req->set_header(req, "Content-Length", tmp);
    req->put(req, res.url, &b, _read_callback, upload);

    HR_LOGD("%s(%d): response url:%s, header:%s\n", __FUNCTION__, __LINE__, res.url, res.header);
    printf("upload result:%s\n", b.data);

    if (res.url) {
        free(res.url);
    }
    if (res.header) {
        free(res.header);
    }
    tcloud_request_free(req);
    tcloud_buffer_free(&b);
    

    getchar();
    return 0;
}

static int do_commit_upload(struct write_queue *queue) {
    struct tcloud_buffer b;
    struct tcloud_request *req = tcloud_request_new();

    const char *url = "http://upload.cloud.189.cn/person/commitMultiUploadFile";

    const char *action = "/person/commitMultiUploadFile";

    char tmp[256] = {0};

    tcloud_buffer_alloc(&b, 512);
    snprintf(tmp, sizeof(tmp), "uploadFileId=%s", queue->upload_id);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "fileMd5=%s", queue->md5sum);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "sliceMd5=%s", queue->slice_md5sum);
    tcloud_buffer_append_string(&b, tmp);
    tcloud_buffer_append_string(&b, "&");
    snprintf(tmp, sizeof(tmp), "lazyCheck=%d", queue->slice_size == 1 ? 0 : 1);
    tcloud_buffer_append_string(&b, tmp);

    req->method = TR_METHOD_GET;
    _tcloud_drive_fill_final(req, action, &b);

    tcloud_buffer_reset(&b);
    req->request(req, url, &b, NULL);

    printf("result:(%ld)%s\n", b.offset, b.data);

    tcloud_request_free(req);
    tcloud_buffer_free(&b);
}
int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }

    HR_INIT_LIST_HEAD(&_queue.head);

    pthread_mutex_init(&_queue.mutex, NULL);
    pthread_cond_init(&_queue.cond, NULL);
    _queue.total_size = 0;
    _queue.processing_offset = 0;
    _queue.chunk_offset = 0;
    _queue.num = 0;
    tcloud_buffer_alloc(&_queue.slice_md5sum_data, 512);

    memset((void *)&_upload_queue, 0, sizeof(_upload_queue));
    _upload_queue.content_length = 0;
    _upload_queue.part = 0;
    HR_INIT_LIST_HEAD(&_upload_queue.head);

    _fd = open(argv[1], O_CREAT | O_RDWR, 0755);
    if (_fd < 0) {
        printf("can not open:%s\n", argv[1]);
        return -1;
    }

    struct stat sb;
    if (fstat(_fd, &sb) != 0) {
        close(_fd);
        return -1;
    }

    _queue.total_size = sb.st_size;

    struct init_multi_upload_data data;
    memset((void *)&data, 0, sizeof(data));

    init_multi_upload("upload_data.bin", sb.st_size, 724181136469568390L, &data);

    if (!data.id) {
        printf("can not get valid id\n");
        return -1;
    }

    _queue.upload_id = strdup(data.id);

    if (data.host) {
        free(data.host);
    }
    if (data.id) {
        free(data.id);
    }

    // start write routin thread
    pthread_create(&_tid, NULL, write_routin, NULL);

    usleep(500 * 1000);
    ssize_t rs = 0;
    char buf[1024 * 3] = {0};
    off_t off = 0;

    while ((rs = read(_fd, buf, sizeof(buf))) > 0) {
        printf("read %ld bytes\n", rs);
        do_write(buf, off, rs);
        off += rs;
        // getchar();
        //  usleep(500 * 1000);
    }

    printf("rs:%ld\n", rs);
    close(_fd);
    _queue.is_eof = 1;
    pthread_cond_broadcast(&_queue.cond);

    printf("waiting finished ...\n");
    pthread_join(_tid, NULL);
    printf("press any key finished ...\n");
    getchar();
    return 0;
}