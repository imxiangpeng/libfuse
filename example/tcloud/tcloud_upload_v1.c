#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <unistd.h>
#include "hr_log.h"
#include "tcloud/hr_list.h"
#include "tcloud/tcloud_utils.h"
#include "tcloud_buffer.h"
#include "tcloud_request.h"

const char *_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

#define CHUNK_SIZE (1024 * 1024 * 10)
#define MAX_QUEUE (30)

struct write_chunk {
    off_t offset;
    size_t size;
    void *payload;
    struct hr_list_head entry;
};

int _fd = -1;

struct write_queue {
    int seq;

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

    getchar();
    return 0;
}