
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/stat.h>
#endif

#define FUSE_USE_VERSION FUSE_VERSION

#include <errno.h>
#include <fuse_kernel.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hr_list.h"
#include "tcloud_buffer.h"
#include "tcloud_drive.h"

#define TCLOUDFS_DEFAULT_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
// default root directory is -11
#define TCLOUDFS_DEFAULT_ROOT_ID -11

struct tcloudfs_node {
    ino_t ino;  // --> id
    int32_t cloud_id;
    uint64_t refcount;
    char *name;
    off_t offset;
    size_t size;
    mode_t mode;
    struct timespec atime;  //
    struct timespec mtime;  //
    struct timespec ctime;  //
    time_t expire_time;
    struct tcloud_buffer *data;
    // struct j2sobject *dir;
    // directory child lists
    struct tcloudfs_node *parent;
    struct hr_list_head entry;
    struct hr_list_head childs;  // folder head
};
struct tcloudfs_priv {
    pthread_mutex_t mutex;

    // uint32_t default_root_id;
    /// struct tcloudfs_node root;
    struct hr_list_head head;
    // should be deleted nodes
    struct hr_list_head delete_pending_queue;
};

int timespec_from_date_string(struct timespec *ts, const char *date) {
    struct tm tm_time;

    if (!ts || !date) return -1;

    memset(&tm_time, 0, sizeof(struct tm));

    if (strptime(date, "%Y-%m-%d %H:%M:%S", &tm_time) == NULL) {
        fprintf(stderr, "Failed to parse time string\n");
        return 1;
    }

    time_t time_epoch = mktime(&tm_time);
    if (time_epoch == -1) {
        fprintf(stderr, "Failed to convert to time_t\n");
        return 1;
    }

    ts->tv_sec = time_epoch;
    ts->tv_nsec = 0;

    // 打印结果
    printf("Time: %ld seconds, %ld nanoseconds\n", ts->tv_sec, ts->tv_nsec);
    return 0;
}

static struct tcloudfs_node *allocate_node(int cloud_id, const char *name,
                                           struct tcloudfs_node *parent) {
    struct tcloudfs_node *node = NULL;

    if (!name)
        return NULL;

    node = (struct tcloudfs_node *)calloc(1, sizeof(struct tcloudfs_node));
    if (!node)
        return NULL;

    node->cloud_id = cloud_id;
    node->name = strdup(name);
    node->parent = parent;
    HR_INIT_LIST_HEAD(&node->entry);
    HR_INIT_LIST_HEAD(&node->childs);

    if (parent) {
        node->parent = parent;
        hr_list_add_tail(&node->entry, &parent->childs);
    }

    return node;
}

static void tcloudfs_init(void *userdata, struct fuse_conn_info *conn) {
    struct tcloudfs_priv *priv = (struct lo_data *)userdata;
    printf("%s(%d): .........priv:%p\n", __FUNCTION__, __LINE__, priv);
}

static void tcloudfs_lookup(fuse_req_t req, fuse_ino_t parent,
                            const char *name) {
    printf("%s(%d): .........priv:%p, parent ino:%" PRIu64 ", name:%s\n",
           __FUNCTION__, __LINE__, fuse_req_userdata(req), parent, name);

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL, *p = NULL;
    if (parent == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)parent;
    }

    if (!node || !S_ISDIR(node->mode)) {
        printf("no ........node:%p, node dir:%d........\n", node, S_ISDIR(node->mode));
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    // e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    hr_list_for_each_entry(p, &node->childs, entry) {
        printf("%s(%d): child: id:%d, name:%s, dir:%d\n", __FUNCTION__, __LINE__, p->cloud_id, p->name, S_ISDIR(p->mode));
        if (0 == strcmp(name, p->name)) {
            printf("got :%s\n", name);
            e.attr.st_mode = p->mode | 755;
            e.attr.st_ino = (fuse_ino_t)p;
            e.attr.st_nlink = S_ISDIR(p->mode) ? 1 : 2;
            e.attr.st_ctim = node->ctime;
            e.attr.st_mtim = node->mtime;
            if (S_ISREG(p->mode)) {
                e.attr.st_size = p->size;
                printf("%s -> %ld, mode:%o\n", p->name, e.attr.st_size, e.attr.st_mode);
            }

            e.ino = (fuse_ino_t)p;
            fuse_reply_entry(req, &e);
            return;
        }
    }
    printf("lookup can not got :%s\n", name);
#if 0
    e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    e.attr.st_mode = S_IFDIR | 0755;
    e.attr.st_nlink = 2;
#endif
    e.ino = 0;
    fuse_reply_entry(req, &e);
    // fuse_reply_err(req, -ENOENT);
}

static void tcloudfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", nlookup:%" PRIu64 "\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), ino, nlookup);
    if (ino == FUSE_ROOT_ID)
        return;

    // do_forget(req_fuse(req), ino, nlookup);
    struct tcloudfs_node *node = NULL, *p = NULL;
    node = (struct tcloudfs_node *)ino;

    printf("id: %d, name:%s, is dir:%d\n", node->cloud_id, node->name, S_ISDIR(node->mode));
    if (S_ISDIR(node->mode)) {
        pthread_mutex_lock(&priv->mutex);
        // move all childs and this node to delete pending queue
        if (!hr_list_empty(&node->childs)) {
            // new link last node -> origin link head (tail)
            node->childs.prev->next = &priv->delete_pending_queue;
            // origin link prev(origin tail) -> new link first node
            node->childs.next->prev = priv->delete_pending_queue.prev;

            priv->delete_pending_queue.prev->next = node->childs.next;
            priv->delete_pending_queue.prev = node->childs.prev;

            // keep this node later? only remove child node ?
            // hr_list_del(&node->entry);
            // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
        }
        pthread_mutex_unlock(&priv->mutex);
    }
    // hr_list_move_tail(&node->entry, &priv->delete_pending_queue);
    printf("%s(%d): pending delete queue ......\n", __FUNCTION__, __LINE__);
    hr_list_for_each_entry(p, &priv->delete_pending_queue, entry) {
        printf("%p -> %d -> %s\n", p, p->cloud_id, p->name);
    }
    printf("%s(%d): pending delete queue .end.....\n", __FUNCTION__, __LINE__);
    fuse_reply_none(req);
}
static void tcloudfs_getattr(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", fi:%p\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), ino, fi);
    struct stat st;

    (void)fi;

    memset(&st, 0, sizeof(st));
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == FUSE_ROOT_ID) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }

    printf("%s(%d): name:%s mode:%o\n", __FUNCTION__, __LINE__, node->name, node->mode);
    st.st_ino = (fuse_ino_t)node;
    st.st_mode = node->mode | 0755;
    st.st_nlink = 1;
    st.st_ctim = node->ctime;
    st.st_mtim = node->mtime;
    if (S_ISREG(node->mode)) {
        st.st_size = node->size;
        printf("%s -> %ld\n", node->name, st.st_size);
    } else {
        st.st_size = 4096;
    }

    st.st_gid = getgid();
    st.st_uid = getuid();
    fuse_reply_attr(req, &st, 1.0);
}

static void tcloudfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                             int valid, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
}

static void tcloudfs_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == FUSE_ROOT_ID) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }

    fuse_reply_err(req, 0);
}
static void tcloudfs_opendir(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
    if (ino == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }

    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);

    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d): can not open dir\n", __FUNCTION__, __LINE__);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
    if (fi) {
        fi->fh = (uint64_t)node;
    }

    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
    fuse_reply_open(req, fi);
    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
}

static void tcloudfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                             off_t offset, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64
           ", size:%ld, offset:%ld, fi:%p\n",
           __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi);

    time_t now = 0;
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d):  not support name:%s\n", __FUNCTION__, __LINE__, node->name);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    if (!node->data) {
        node->data =
            (struct tcloud_buffer *)calloc(1, sizeof(struct tcloud_buffer));
        tcloud_buffer_alloc(node->data, size);
        node->offset = 0;

        // cache timing ?
        now = time(NULL);

        printf("%s(%d): .........priv:%p, ino:%" PRIu64
               ", size:%ld, offset:%ld, fi:%p, time :%ld, expire:%ld\n",
               __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi, now, node->expire_time);

        if (node->expire_time < now) {
            node->expire_time = now + 5;  // expire after 5s
            // 1. free all cached object
            struct j2scloud_folder_resp *dir = NULL;
            struct stat st;
            st.st_mode = S_IFDIR;

            size_t entlen = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset), ".",
                                       &st, node->data->offset + entlen);
            node->data->offset += entlen;
            entlen = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset), "..",
                                       &st, node->data->offset + entlen);
            node->data->offset += entlen;

            struct tcloudfs_node *p = NULL, *n = NULL;

            hr_list_for_each_entry_safe(p, n, &node->childs, entry) {
                printf("remove expire nodes: %p -> %d -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
                hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
            }

            int ret = 0;
            printf("%s(%d): dir using %d\n", __FUNCTION__, __LINE__, node->cloud_id);
            ret =
                tcloud_drive_opendir(/*ino == 1 ? -11 : ino*/ node->cloud_id, &dir);

            ret = tcloud_drive_readdir(/*ino == 1 ? -11 : ino*/ node->cloud_id, dir);

            printf("json ret:%d\n", ret);
            if (ret == 0) {
                printf("%s(%d): dir using %d\n", __FUNCTION__, __LINE__, node->cloud_id);
                st.st_mode = S_IFDIR;

                struct j2scloud_folder_resp *object = dir;
                j2scloud_folder_t *t = NULL;
                printf("%s(%d): dir using %d\n", __FUNCTION__, __LINE__, node->cloud_id);

                for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
                     t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
                     t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
                    st.st_mode = S_IFDIR;

                    printf("%s(%d): dir name: %s\n", __FUNCTION__, __LINE__, t->name);
                    // timespec_from_date_string(&st.st_atim, t->lastOpTime);
                    // timespec_from_date_string(&st.st_mtim, t->lastOpTime);

                    entlen = fuse_add_direntry(req, NULL, 0, t->name, NULL, 0);
                    entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                               (node->data->size - node->data->offset),
                                               t->name, &st, node->data->offset + entlen);
                    node->data->offset += entlen;

                    struct tcloudfs_node *n = allocate_node(t->id, t->name, node);
                    n->mode = S_IFDIR;
                    timespec_from_date_string(&n->atime, t->createDate);
                    timespec_from_date_string(&n->ctime, t->lastOpTime);
                    timespec_from_date_string(&n->mtime, t->lastOpTime);
                    // assign fuse_ino_t as n?
                    st.st_ino = (fuse_ino_t)n;
                }

                j2scloud_file_t *f = NULL;
                for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
                     f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
                     f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
                    printf("%s(%d): file name: %s\n", __FUNCTION__, __LINE__, f->name);
                    st.st_mode = S_IFREG;
                    st.st_size = (long)f->size;
                    // timespec_from_date_string(&stbuf->st_ctim, f->createDate);
                    // timespec_from_date_string(&stbuf->st_atim, f->lastOpTime);
                    // timespec_from_date_string(&stbuf->st_mtim, f->lastOpTime);
                    entlen = fuse_add_direntry(req, NULL, 0, f->name, NULL, 0);
                    entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                               (node->data->size - node->data->offset),
                                               f->name, &st, node->data->offset + entlen);
                    node->data->offset += entlen;

                    struct tcloudfs_node *n = allocate_node(f->id, f->name, node);
                    n->mode = S_IFREG;
                    n->size = f->size;
                    timespec_from_date_string(&n->atime, f->createDate);
                    timespec_from_date_string(&n->ctime, f->lastOpTime);
                    timespec_from_date_string(&n->mtime, f->lastOpTime);
                    // assign fuse_ino_t as n?
                    st.st_ino = (fuse_ino_t)n;
                }
            }

            j2sobject_free(J2SOBJECT(dir));

            node->offset = 0;

        } else {
            // using cache
            struct tcloudfs_node *p = NULL;

            printf("%s(%d).....using cache.....\n", __FUNCTION__, __LINE__);
            struct stat st;
            st.st_mode = S_IFDIR;
            size_t entlen = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset), ".",
                                       &st, node->data->offset + entlen);
            node->data->offset += entlen;
            entlen = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset), "..",
                                       &st, node->data->offset + entlen);
            node->data->offset += entlen;

            hr_list_for_each_entry(p, &node->childs, entry) {
                printf("%p -> %d -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
                st.st_mode = p->mode /*S_IFDIR*/;
                st.st_ino = (fuse_ino_t)p;
                entlen = fuse_add_direntry(req, NULL, 0, p->name, NULL, 0);
                entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                           (node->data->size - node->data->offset),
                                           p->name, &st, node->data->offset + entlen);
                node->data->offset += entlen;
            }
        }
    }
    size_t total = node->data->offset;
    printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__,
           __LINE__, total, offset, size);
    if (offset >= total) {
        printf("%s(%d): end ..........\n", __FUNCTION__, __LINE__);
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (size > total - offset) {
        size = total - offset;
    }
    printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__,
           __LINE__, total, offset, size);
    fuse_reply_buf(req, node->data->data + offset, size);
    node->offset = offset + size;
    printf("%s(%d): now offset:%ld, buffer %ld vs %ld..........\n", __FUNCTION__,
           __LINE__, node->offset, node->data->offset, node->data->size);
}
static void lo_releasedir(fuse_req_t req, fuse_ino_t ino,
                          struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    if (node->data) {
        tcloud_buffer_free(node->data);
        free(node->data);
        node->data = NULL;
    }

    node->offset = 0;
    node->size = 0;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
}

static void lo_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, parent:%" PRIu64 "\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), parent);
	struct fuse_entry_param e;
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (parent == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)parent;
    }

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    struct tcloudfs_node *n = allocate_node(-11, name, node);
    n->mode = S_IFREG;

    e.ino = (fuse_ino_t)n;
    e.attr.st_mode = S_IFREG;
    e.attr.st_size = 0;
		fuse_reply_create(req, &e, fi);
    // fuse_reply_err(req, 0);
}
static void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
}
static void lo_release(fuse_req_t req, fuse_ino_t ino,
                       struct fuse_file_info *fi) {
    (void)ino;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
}
static void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
}
static void lo_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
                     struct fuse_file_info *fi) {
    off_t res = 0;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    (void)ino;
    fuse_reply_lseek(req, res);
    // fuse_reply_err(req, errno);
}

static void lo_statfs(fuse_req_t req, fuse_ino_t ino) {
    struct statvfs result;
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);

    result.f_bsize = 4096;
    result.f_blocks = 1024 * 1024;
    result.f_bfree = 1024;
    result.f_bavail = 1024;

    fuse_reply_statfs(req, &result);
}
static void lo_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset,
                         off_t length, struct fuse_file_info *fi) {
    int err = EOPNOTSUPP;
    (void)ino;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, err);
}

static const struct fuse_lowlevel_ops tcloudfs_ops = {
    .init = tcloudfs_init,
    .lookup = tcloudfs_lookup,
    .forget = tcloudfs_forget,
    .getattr = tcloudfs_getattr,
    .setattr = tcloudfs_setattr,
    .access = tcloudfs_access,
    .opendir = tcloudfs_opendir,
    .readdir = tcloudfs_readdir,
    .releasedir = lo_releasedir,

    .create = lo_create,
    .open = lo_open,
    .release = lo_release,
    .read = lo_read,
    .lseek = lo_lseek,
    .statfs = lo_statfs,
    .fallocate = lo_fallocate,
};
int main(int argc, char **argv) {
    int ret = 0;

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct tcloudfs_priv priv;
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *config;
    memset((void *)&priv, 0, sizeof(priv));

    pthread_mutex_init(&priv.mutex, NULL);

    // init empty link
    HR_INIT_LIST_HEAD(&priv.head);
    HR_INIT_LIST_HEAD(&priv.delete_pending_queue);

    struct tcloudfs_node *root = allocate_node(-11 /*FUSE_ROOT_ID*/, "/", NULL);
    root->mode = S_IFDIR;

    hr_list_add_tail(&root->entry, &priv.head);

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;

    se = fuse_session_new(&args, &tcloudfs_ops, sizeof(tcloudfs_ops), &priv);
    if (se == NULL)
        goto gone_1;

    if (fuse_set_signal_handlers(se) != 0)
        goto gone_2;

    if (fuse_session_mount(se, opts.mountpoint) != 0)
        goto gone_3;

    fuse_daemonize(opts.foreground);

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else {
        config = fuse_loop_cfg_create();
        fuse_loop_cfg_set_clone_fd(config, opts.clone_fd);
        fuse_loop_cfg_set_max_threads(config, opts.max_threads);
        ret = fuse_session_loop_mt(se, config);
        fuse_loop_cfg_destroy(config);
        config = NULL;
    }

    fuse_session_unmount(se);
gone_3:
    fuse_remove_signal_handlers(se);
gone_2:
    fuse_session_destroy(se);
gone_1:
    if (opts.mountpoint)
        free(opts.mountpoint);
    fuse_opt_free_args(&args);
    pthread_mutex_destroy(&priv.mutex);
    return 0;
}