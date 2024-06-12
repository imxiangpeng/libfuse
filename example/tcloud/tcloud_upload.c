#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <json-c/json.h>
#include <json-c/json_object.h>
#endif

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

    CURLM *multi;
    CURL *curl;  // opened handle
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int num;
    off_t processing_offset;
    off_t chunk_offset;
    struct hr_list_head head;
} _queue;

static pthread_t _tid = 0;

static int _dump_fd = -1;

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
        pthread_mutex_lock(&_queue.mutex);
        if (hr_list_empty(&_queue.head) || _queue.num == 0) {
            // we should wait
            HR_LOGD("%s(%d): now queue is empty ...\n", __FUNCTION__, __LINE__);
            pthread_cond_wait(&_queue.cond, &_queue.mutex);
        }

        struct write_chunk *ch = hr_list_first_entry(&_queue.head, struct write_chunk, entry);
        if (!ch) {
            pthread_mutex_unlock(&_queue.mutex);
            continue;
        }
        HR_LOGD("%s(%d): now request:%p -> %ld... num:%d\n", __FUNCTION__, __LINE__, ch, ch->offset, _queue.num);
        if (_queue.processing_offset == ch->offset) {
            HR_LOGD("%s(%d): found chunk at %ld ...\n", __FUNCTION__, __LINE__, ch->offset);
            // take off from queue

            if (_dump_fd == -1) {
                _dump_fd = open_chunk(_queue.seq);
            }
            // dump data every 10M
            if (_queue.chunk_offset + ch->size <= CHUNK_SIZE) {
                hr_list_del(&ch->entry);
                _queue.num--;
                // continue this chunk
                write(_dump_fd, ch->payload, ch->size);
                _queue.chunk_offset += ch->size;
                _queue.processing_offset = ch->offset + ch->size;
                chunk_free(ch);
            } else {
                //
                size_t ws = CHUNK_SIZE - _queue.chunk_offset;
                write(_dump_fd, ch->payload, ws);
                _queue.chunk_offset += ws;
                _queue.processing_offset = ch->offset + ws;

                close(_dump_fd);
                _dump_fd = -1;
                // open new chunk
                _queue.seq++;
                ch->offset += ws;
                memcpy(ch->payload, ch->payload + ws, ch->size - ws);
                ch->size -= ws;
                _queue.chunk_offset = 0;
            }

        } else {
            HR_LOGD("%s(%d): we should wait chunk at %ld but found:%ld...\n", __FUNCTION__, __LINE__, _queue.processing_offset, ch->offset);
            pthread_cond_wait(&_queue.cond, &_queue.mutex);
        }

        pthread_mutex_unlock(&_queue.mutex);
        pthread_cond_signal(&_queue.cond);

        // usleep(1000 * 1000);
    }
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

    HR_LOGD("%s(%d): do write in -> %d ...\n", __FUNCTION__, __LINE__, _queue.num);
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
        HR_LOGD("%s(%d): cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);

        // the last should always bigger
        if (c1->offset < ch->offset) {
            found = 1;
            HR_LOGD("%s(%d): found cur :%p, HEAD:%p...current:%ld\n", __FUNCTION__, __LINE__, p, &_queue.head, c1->offset);
            break;
        }
    }

    HR_LOGD("%s(%d): add request:%p -> %ld...\n", __FUNCTION__, __LINE__, ch, ch->offset);
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

int init_multi_upload(uint64_t parent_id, const char *name, size_t size) {
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
    tcloud_buffer_append_string(&b, name);
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
    json_object_object_get_ex(root, "data", &result_data);
    if (!result_data) {
        json_object_put(root);
        return -1;
    }

    struct json_object *json_upload_type = NULL, *json_upload_host = NULL, *json_upload_file_id = NULL, *json_file_data_exists = NULL;
    json_object_object_get_ex(result_data, "uploadType", &json_upload_type);
    json_object_object_get_ex(result_data, "uploadHost", &json_upload_host);
    json_object_object_get_ex(result_data, "uploadFileId", &json_upload_file_id);
    json_object_object_get_ex(result_data, "fileDataExists", &json_file_data_exists);

    HR_LOGD("%s(%d): .uploadType:%d, uploadHost:%s, uploadFileId:%s, fileDataExists:%d...\n", __FUNCTION__, __LINE__,
            json_object_get_int(json_upload_type),
            json_object_get_string(json_upload_host),
            json_object_get_string(json_upload_file_id),
            json_object_get_int(json_file_data_exists));
    json_object_put(root);

    return 0;
}

int get_multi_upload() {
}
int main(int argc, char **argv) {
    if (argc < 2) {
        return -1;
    }

    HR_INIT_LIST_HEAD(&_queue.head);

    pthread_mutex_init(&_queue.mutex, NULL);
    pthread_cond_init(&_queue.cond, NULL);
    _queue.processing_offset = 0;
    _queue.chunk_offset = 0;
    _queue.num = 0;
#if 0
    pthread_create(&_tid, NULL, write_routin, NULL);

    usleep(500 * 1000);
    _fd = open(argv[1], O_CREAT | O_RDWR, 0755);
    if (_fd < 0) {
        printf("can not open:%s\n", argv[1]);
        return -1;
    }
    ssize_t rs = 0;
    char buf[1024 * 18] = {0};
    off_t off = 0;

    off = 1024 * 2;

    lseek(_fd, off, SEEK_SET);
    while ((rs = read(_fd, buf, sizeof(buf))) > 0) {
        printf("read %ld bytes\n", rs);
        do_write(buf, off, rs);
        off += rs;
        int c = getchar();
        if (c == 'b') {
            break;
        }
        //  usleep(500 * 1000);
    }

    lseek(_fd, 0, SEEK_SET);
    read(_fd, buf, 1024);
    do_write(buf, 0, 1024);

    read(_fd, buf, 1024);
    do_write(buf, 1024, 1024);

    getchar();

    lseek(_fd, off, SEEK_SET);

    while ((rs = read(_fd, buf, sizeof(buf))) > 0) {
        printf("read %ld bytes\n", rs);
        do_write(buf, off, rs);
        off += rs;
        // getchar();
        //  usleep(500 * 1000);
    }

    printf("rs:%ld\n", rs);
    close(_fd);
#endif
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

    init_multi_upload(724181136469568390L, "upload_data.bin", sb.st_size);
    getchar();
    return 0;
}