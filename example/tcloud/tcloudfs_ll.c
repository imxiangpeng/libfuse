
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <asm-generic/errno-base.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#endif

#define FUSE_USE_VERSION FUSE_VERSION

#include <errno.h>
#include <fuse_kernel.h>
#include <fuse_lowlevel.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hr_list.h"
#include "hr_log.h"
#include "tcloud_buffer.h"
#include "tcloud_drive.h"
#include "uthash.h"

#define TCLOUDFS_DEFAULT_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
// default root directory is -11
#define TCLOUDFS_DEFAULT_ROOT_ID -11

#define TCLOUDFS_NODE_DEFAULT_EXPIRE_TIME 60  // 60s

#define TCLOUDFS_OPT(t, p, v) \
    { t, offsetof(struct tcloudfs_opt, p), v }

struct tcloudfs_node {
    ino_t ino;  // --> id
    int64_t cloud_id;
    uint64_t refcount;
    char *name;
    // off_t offset;
    size_t size;
    size_t truncate_size;
    mode_t mode;

    struct timespec atime;  // last access time
    struct timespec mtime;  // last modification
    struct timespec ctime;  // last status change time( create?)
    time_t expire_time;
    // struct tcloud_buffer *data;
    struct tcloudfs_node *hash_node;
    // struct j2sobject *dir;
    // directory child lists
    struct tcloudfs_node *parent;
    struct hr_list_head entry;
    struct hr_list_head childs;  // folder head
    UT_hash_handle hh;
};

struct tcloudfs_opt {
    int uid;
    int gid;
    double attr_timeout;
    double entry_timeout;
};

// directory handler
struct tcloudfs_dh {
    off_t offset;

    struct tcloud_buffer data;
};

struct tcloudfs_xattr {
    char *name;
    char *value;
    size_t size;
    struct hr_list_head entry;
};

struct tcloudfs_priv {
    pthread_mutex_t mutex;

    struct tcloudfs_opt opts;
    struct {
        time_t last_time;
        struct statvfs st;
    } st;

    struct hr_list_head xattrs;

    struct tcloudfs_node *hash_node_lists;  // verify node is valid ...
    // uint32_t default_root_id;
    /// struct tcloudfs_node root;
    struct hr_list_head head;
    // should be deleted nodes
    struct hr_list_head delete_pending_queue;
};

static struct tcloudfs_priv _priv;

static int timespec_from_date_string(struct timespec *ts, const char *date) {
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

    return 0;
}

static struct tcloudfs_node *allocate_node(uint64_t cloud_id, const char *name,
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

    // printf("%s(%d): hash node lists :%p, current node:%p\n", __FUNCTION__, __LINE__, _priv.hash_node_lists, node);
    node->hash_node = node;
    HASH_ADD_PTR(_priv.hash_node_lists, hash_node, node);

    return node;
}

static void deallocate_node(struct tcloudfs_node *node) {
    struct tcloudfs_node *p = NULL, *n = NULL;
    if (!node) return;

    printf("%s(%d): deleallocate node:%p, %s\n", __FUNCTION__, __LINE__, node, node->name);

    // 1. remove from hash table
    HASH_DEL(_priv.hash_node_lists, node);

    // 2. remove all childs
    hr_list_for_each_entry_safe(p, n, &node->childs, entry) {
        deallocate_node(p);
    }

    // 3. tear off from chain
    node->parent = NULL;
    free(node->name);
    hr_list_del(&node->entry);
#if 0
    if (node->data) {
        tcloud_buffer_free(node->data);
        free(node->data);
        node->data = NULL;
    }
#endif

    // 4. free self memory
    free(node);
}

static bool is_valid_node(struct tcloudfs_node *node) {
    struct tcloudfs_node *n = NULL;
    if (!node) return false;

    HASH_FIND_PTR(_priv.hash_node_lists, &node, n);

    // printf("%s(%d): find:%p, valid node :%p == %d\n", __FUNCTION__, __LINE__, node, n, node == n);

    return node == n;
}

static struct tcloudfs_node *find_node(fuse_req_t req, ino_t ino) {
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

    if (!node) {
        return NULL;
    }

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return NULL;
    }

    return node;
}

static int tcloudfs_update_directory(struct tcloudfs_node *node) {
    int ret = 0;
    HR_LIST_HEAD(remove_queue);
    HR_LIST_HEAD(add_queue);

    time_t now = time(NULL);

    if (!node) return -1;

    if (now < node->expire_time) {
        return 0;
    }

    HR_LOGD("%s(%d):  node:%s\n", __FUNCTION__, __LINE__, node->name);
    if (!S_ISDIR(node->mode)) {
        return -1;
    }

    struct tcloudfs_node *p = NULL, *n = NULL;

    // move all childs to remove list
    if (!hr_list_empty(&node->childs)) {
#if 0
        hr_list_for_each_entry_safe(p, n, &node->childs, entry) {
            printf("previous nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
            // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
        }
#endif
        node->childs.prev->next = &remove_queue;
        remove_queue.next = node->childs.next;
        node->childs.next->prev = &remove_queue;
        remove_queue.prev = node->childs.prev;
#if 0
        hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
            printf("remove expire nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
            // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
        }
#endif
        HR_INIT_LIST_HEAD(&node->childs);
    }

    struct j2scloud_folder_resp *dir = (struct j2scloud_folder_resp *)j2sobject_create(&j2scloud_folder_resp_prototype);
    HR_LOGD("%s(%d):  read node:%s (%ld)\n", __FUNCTION__, __LINE__, node->name, node->cloud_id);
    ret = tcloud_drive_readdir(node->cloud_id, dir);
    if (ret != 0) {
        HR_LOGD("%s(%d):  failed read node:%s (%ld)\n", __FUNCTION__, __LINE__, node->name, node->cloud_id);
        j2sobject_free(J2SOBJECT(dir));

        return -1;
    }

    struct j2scloud_folder_resp *object = dir;
    j2scloud_folder_t *d = NULL;

    if (object->folderList) {
        for (d = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
             d != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
             d = (j2scloud_folder_t *)J2SOBJECT(d)->next) {
            printf("%s(%d): dir name: %s, id:%ld\n", __FUNCTION__, __LINE__, d->name, (uint64_t)d->id);
            int use_cache = 0;

            hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
                // printf("find in remove expire nodes: %p -> %ld(vs %ld) -> %s, dir:%d\n", p, p->cloud_id, (uint64_t)d->id, p->name, S_ISDIR(p->mode));
                // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
                if (p->cloud_id == d->id) {
                    use_cache = 1;
                    // printf("found cache node:%p %ld :%s\n", p, p->cloud_id, p->name);
                    hr_list_move_tail(&p->entry, &node->childs);

                    // maybe rename
                    if (strcmp(p->name, d->name)) {
                        free(p->name);
                        p->name = strdup(d->name);
                    }

                    if (!S_ISDIR(p->mode)) {
                        p->mode = S_IFDIR | TCLOUDFS_DEFAULT_MODE;
                    }

                    break;
                }
            }
            if (use_cache == 0) {
                p = allocate_node(d->id, d->name, node);
                p->mode = S_IFDIR | TCLOUDFS_DEFAULT_MODE;
                timespec_from_date_string(&p->ctime, d->createDate);
                timespec_from_date_string(&p->atime, d->lastOpTime);
                timespec_from_date_string(&p->mtime, d->lastOpTime);

                // printf("%s(%d): %s ctime:%ld, mtime:%ld, atime:%ld\n", __FUNCTION__, __LINE__, p->name, p->ctime.tv_sec, p->mtime.tv_sec, p->atime.tv_sec);
            }
        }
    }
    if (object->fileList) {
        j2scloud_file_t *f = NULL;
        for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
             f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
             f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
            int use_cache = 0;
            printf("%s(%d): file name: %s\n", __FUNCTION__, __LINE__, f->name);
            hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
                // printf("find in remove expire nodes: %p -> %ld(vs %ld) -> %s, dir:%d\n", p, p->cloud_id, (uint64_t)f->id, p->name, S_ISDIR(p->mode));
                // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
                if (p->cloud_id == f->id) {
                    use_cache = 1;
                    // printf("found cache node:%p %ld :%s\n", p, p->cloud_id, p->name);
                    hr_list_move_tail(&p->entry, &node->childs);

                    // maybe rename
                    if (strcmp(p->name, f->name)) {
                        free(p->name);
                        p->name = strdup(f->name);
                    }

                    if (!S_ISREG(p->mode)) {
                        p->mode = S_IFREG | TCLOUDFS_DEFAULT_MODE;
                    }

                    break;
                }

                // verify it's uploading files
                if (p->cloud_id == TCLOUD_DRIVE_RESERVE_ID) {
                    if (!strcmp(p->name, f->name)) {
                        HR_LOGD("find uploading file .......%s\n", f->name);

                        p->cloud_id = f->id;
                        use_cache = 1;
                        // printf("found cache node:%p %ld :%s\n", p, p->cloud_id, p->name);
                        hr_list_move_tail(&p->entry, &node->childs);
                        break;
                    }
                }
            }
            if (use_cache == 0) {
                // printf("add new file :%s\n", f->name);
                p = allocate_node((uint64_t)f->id, f->name, node);
                p->mode = S_IFREG | TCLOUDFS_DEFAULT_MODE;
                p->size = f->size;
                timespec_from_date_string(&p->ctime, f->createDate);
                timespec_from_date_string(&p->atime, f->lastOpTime);
                timespec_from_date_string(&p->mtime, f->lastOpTime);
            }
        }
    }

#if 0
    hr_list_for_each_entry_safe(p, n, &node->childs, entry) {
        printf("now nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
    }

    printf("%s(%d): .....................\n", __FUNCTION__, __LINE__);
    hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
        printf("now remove nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
        // hr_list_move_tail(&p->entry, &priv->delete_pending_queue);
    }
    printf("%s(%d): .....................\n", __FUNCTION__, __LINE__);
#endif
    // cache only when folder or file is empty
    if (dir->folderList || dir->fileList) {
        node->expire_time = now + TCLOUDFS_NODE_DEFAULT_EXPIRE_TIME;
    }

    j2sobject_free(J2SOBJECT(dir));
    hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
        printf("remove expire nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
        // this is new added node, keep it
        if (p->cloud_id == TCLOUD_DRIVE_RESERVE_ID) {
            HR_LOGD("@@@@@@@@@@@@@@@@@@@ uploading keep it  nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
            hr_list_move_tail(&p->entry, &node->childs);
            continue;
        }
        deallocate_node(p);
    }

#if 0
    if (node->data) {
        tcloud_buffer_free(node->data);
        free(node->data);
        node->data = NULL;
    }
#endif
    return ret;
}

static void tcloudfs_init(void *userdata, struct fuse_conn_info *conn) {
    struct tcloudfs_priv *priv = (struct tcloudfs_priv *)userdata;

    // tcloud_drive_init();

    printf("%s(%d): .........priv:%p,   conn:%p, capab:0x%X\n", __FUNCTION__, __LINE__, priv, conn, conn->capable);
    // conn->max_read = 1024 *1024 * 2;
    printf("%s(%d): .........priv:%p,   conn:%p\n", __FUNCTION__, __LINE__, priv, conn);

    if (conn->capable & FUSE_CAP_ASYNC_READ) {
        printf("drop : FUSE_CAP_ASYNC_READ\n");
        // conn->capable &= ~FUSE_CAP_ASYNC_READ;
    }
#if 0
    conn->want &= ~FUSE_CAP_ASYNC_READ;
    conn->want &= ~FUSE_CAP_SPLICE_READ;
    conn->want &= ~FUSE_CAP_SPLICE_WRITE;
    conn->want &= ~FUSE_CAP_SPLICE_MOVE;
    conn->want &= ~FUSE_CAP_EXPORT_SUPPORT;
    conn->want &= ~FUSE_CAP_IOCTL_DIR;

    conn->want &= ~FUSE_CAP_ASYNC_DIO;

    conn->want &= ~FUSE_CAP_SETXATTR_EXT;
#endif
}

static void tcloudfs_lookup(fuse_req_t req, fuse_ino_t parent,
                            const char *name) {
    HR_LOGD("%s(%d): .........priv:%p, parent ino:%" PRIu64 ", name:%s\n",
            __FUNCTION__, __LINE__, fuse_req_userdata(req), parent, name);

    struct tcloudfs_node *node = NULL, *p = NULL;
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    node = find_node(req, parent);

    if (!node || !S_ISDIR(node->mode)) {
        printf("no ........node:%p, node dir:%d........\n", node, S_ISDIR(node->mode));
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    HR_LOGD("%s(%d): lookup %s under node:%s\n", __FUNCTION__, __LINE__, name, node->name);

    // using large timeout, which can reduce lookup callback
    e.attr_timeout = _priv.opts.attr_timeout;
    e.entry_timeout = _priv.opts.entry_timeout;

    // only update directory when readdir for better performance
    if (node->expire_time == 0 || hr_list_empty(&node->childs)) {
        tcloudfs_update_directory(node);
    }

    hr_list_for_each_entry(p, &node->childs, entry) {
        printf("%s(%d): node:%p,  child: id:%ld, name:%s( vs %s), dir:%d\n", __FUNCTION__, __LINE__, p, p->cloud_id, p->name, name, S_ISDIR(p->mode));
        if (0 == strcmp(name, p->name)) {
            printf("got :%s\n", name);
            e.attr.st_mode = p->mode /* | TCLOUDFS_DEFAULT_MODE*/;
            e.attr.st_ino = (fuse_ino_t)p;
            e.attr.st_nlink = S_ISDIR(p->mode) ? 1 : 2;
            e.attr.st_ctim = p->ctime;
            e.attr.st_mtim = p->mtime;
            e.attr.st_atim = p->atime;
            printf("got :%s, create time:%ld\n", name, e.attr.st_ctim.tv_sec);
            printf("got :%s, create time:%ld\n", name, p->ctime.tv_sec);
            printf("got :%s, m time:%ld\n", name, p->mtime.tv_sec);

            printf("%s(%d): %s ctime:%ld, mtime:%ld, atime:%ld\n", __FUNCTION__, __LINE__, p->name, p->ctime.tv_sec, p->mtime.tv_sec, p->atime.tv_sec);
            e.attr.st_size = p->size;

            e.attr.st_uid = _priv.opts.uid;
            e.attr.st_gid = _priv.opts.gid;
            printf("%s -> %ld, mode:%o, file size:%ld(%ld)\n", p->name, e.attr.st_size, e.attr.st_mode, p->size, p->truncate_size);

            e.ino = (fuse_ino_t)p;
            fuse_reply_entry(req, &e);
            return;
        }
    }
    HR_LOGD("lookup can not got :%s\n", name);

    fuse_reply_err(req, ENOENT);
}

static void tcloudfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup) {
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    HR_LOGD("%s(%d): .........priv:%p, ino:%" PRIu64 ", nlookup:%" PRIu64 "\n", __FUNCTION__,
            __LINE__, fuse_req_userdata(req), ino, nlookup);
    if (ino == FUSE_ROOT_ID) {
        fuse_reply_none(req);
        return;
    }

    // do_forget(req_fuse(req), ino, nlookup);
    struct tcloudfs_node *node = NULL, *p = NULL;
    node = (struct tcloudfs_node *)ino;
    if (!is_valid_node(node)) {
        fuse_reply_none(req);
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    if (!is_valid_node(node)) {
        fuse_reply_none(req);
        return;
    }

    HR_LOGD("%s(%d): forge %p, %s, nlookup:%ld\n", __FUNCTION__, __LINE__, node, node->name, nlookup);
#if 0
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
#endif
    fuse_reply_none(req);
}

static void tcloudfs_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets) {
    printf("%s(%d): .........priv:%p\n", __FUNCTION__, __LINE__, fuse_req_userdata(req));
    size_t i = 0;

    // forgets is not null
    for (i = 0; i < count; i++) {
        HR_LOGD("%s(%d): i:%d -> ino:%ld -> nlookup:%ld\n", __FUNCTION__, __LINE__, i, forgets[i].ino, forgets[i].nlookup);
    }

    fuse_reply_none(req);
}
static void tcloudfs_getattr(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", fi:%p\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), ino, fi);
    (void)fi;
    struct stat st;

    struct tcloudfs_node *node = find_node(req, ino);

    if (!node) {
        HR_LOGD("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        fuse_reply_err(req, ENONET);
        return;
    }

    memset(&st, 0, sizeof(st));
    st.st_ino = (fuse_ino_t)node;
    st.st_mode = node->mode /*| TCLOUDFS_DEFAULT_MODE*/;
    st.st_nlink = 1;
    st.st_atim = node->atime;  // last access time
    st.st_ctim = node->ctime;  // last status change time( create?)
    st.st_mtim = node->mtime;  // last modification
    if (S_ISREG(node->mode)) {
        st.st_size = node->size;
        // printf("%s -> %ld\n", node->name, st.st_size);
    } else {
        st.st_size = 4096;
    }

    st.st_blksize = 512;
    st.st_blocks = node->size / st.st_blksize;

    st.st_gid = _priv.opts.gid;
    st.st_uid = _priv.opts.uid;

    HR_LOGD("%s(%d): %s mode: %o, & IFMT:%o\n", __FUNCTION__, __LINE__, node->name, st.st_mode, st.st_mode & S_IFMT);
    fuse_reply_attr(req, &st, _priv.opts.attr_timeout);
}

static void tcloudfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                             int valid, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", valid:0x%X\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino, valid);
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node) {
        fuse_reply_err(req, ENONET);
        return;
    }

    if (valid & FUSE_SET_ATTR_MODE) {
        HR_LOGD("%s(%d)  set attr mode %s ...mode:%o, old: %o.\n", __FUNCTION__, __LINE__, node->name, attr->st_mode, node->mode);
        node->mode = attr->st_mode;
    }
    if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        printf("set gid:%d / gid:%d\n", attr->st_gid, attr->st_uid);
    }
    if (valid & FUSE_SET_ATTR_SIZE) {
        struct tcloud_drive_fd *fd = (struct tcloud_drive_fd *)fi->fh;
        HR_LOGD("%s(%d) set size %p...:%ld, old:%ld\n", __FUNCTION__, __LINE__, fi->fh, attr->st_size, node->size);
        node->truncate_size = attr->st_size;
        node->size = attr->st_size;
        if (fd) {
            tcloud_drive_truncate(fd, node->truncate_size);
        }
    }
#if 0
    if (valid & FUSE_SET_ATTR_ATIME) {
        HR_LOGD("%s(%d): set %s atime\n", __FUNCTION__, __LINE__, node->name);
        node->atime = attr->st_atim;
    }

    if (valid & FUSE_SET_ATTR_MTIME) {
        HR_LOGD("%s(%d): set %s ctime\n", __FUNCTION__, __LINE__, node->name);
        node->mtime = attr->st_mtim;
    }
#endif

    if (valid & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
        struct timespec tv[2];

        tv[0].tv_sec = 0;
        tv[1].tv_sec = 0;
        tv[0].tv_nsec = UTIME_OMIT;
        tv[1].tv_nsec = UTIME_OMIT;

        if (valid & FUSE_SET_ATTR_ATIME_NOW)
            tv[0].tv_nsec = UTIME_NOW;
        else if (valid & FUSE_SET_ATTR_ATIME)
            tv[0] = attr->st_atim;

        if (valid & FUSE_SET_ATTR_MTIME_NOW)
            tv[1].tv_nsec = UTIME_NOW;
        else if (valid & FUSE_SET_ATTR_MTIME)
            tv[1] = attr->st_mtim;

        node->atime = tv[0];
        node->mtime = tv[1];
    }

    return tcloudfs_getattr(req, ino, fi);
}

static void tcloudfs_access(fuse_req_t req, fuse_ino_t ino, int mask) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node) {
        fuse_reply_err(req, ENONET);
        return;
    }

    fuse_reply_err(req, 0);
}

static void tcloudfs_opendir(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_dh *dh = NULL;
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d): can not open dir\n", __FUNCTION__, __LINE__);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    // force update
    if (node->expire_time == 0)
        tcloudfs_update_directory(node);

    dh = (struct tcloudfs_dh *)calloc(1, sizeof(struct tcloudfs_dh));
    tcloud_buffer_alloc(&dh->data, 512);

    fi->fh = (uintptr_t)dh;

    HR_LOGD("%s(%d): open :%s\n", __FUNCTION__, __LINE__, node->name);
    fuse_reply_open(req, fi);
}

#include <dirent.h>
static void tcloudfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                             off_t offset, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64
           ", size:%ld, offset:%ld, fi:%p\n",
           __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi);

    time_t now = 0;
    struct tcloudfs_dh *dh = NULL;
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d):  not support name:%s\n", __FUNCTION__, __LINE__, node->name);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    HR_LOGD("%s(%d): readdir :%s (%p)\n", __FUNCTION__, __LINE__, node->name, node);
    // node->expire_time = 0; // force expire only for tests
    // tcloudfs_update_directory(node);

#if 0
    if (!node->data) {
        node->data =
            (struct tcloud_buffer *)calloc(1, sizeof(struct tcloud_buffer));
        tcloud_buffer_alloc(node->data, 512);

        // cache timing ?
        now = time(NULL);

        printf("%s(%d): .........priv:%p, ino:%" PRIu64
               ", size:%ld, offset:%ld, fi:%p, time :%ld, expire:%ld\n",
               __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi, now, node->expire_time);
        // using cache
        struct tcloudfs_node *p = NULL;

        // printf("%s(%d).....using cache.....\n", __FUNCTION__, __LINE__)
        struct stat st;
        memset((void *)&st, 0, sizeof(st));
        // st.st_mode = S_IFDIR;

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
            HR_LOGD("%s(%d): read dir fill entry %p -> %ld -> %s, dir:%d, mode type:%o\n", __FUNCTION__, __LINE__, p, p->cloud_id, p->name, S_ISDIR(p->mode), p->mode & S_IFMT);
            st.st_mode = p->mode & S_IFMT /*S_IFDIR*/;
            st.st_ino = (fuse_ino_t)p;
            entlen = fuse_add_direntry(req, NULL, 0, p->name, NULL, 0);
            if (node->data->offset + entlen > node->data->size) {
                tcloud_buffer_realloc(node->data, node->data->size + entlen + 256);
            }
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset),
                                       p->name, &st, node->data->offset + entlen);
            node->data->offset += entlen;
        }
    }
    
    dh = (struct tcloudfs_dh*)fi->fh;

    if (!dh) {
        HR_LOGD("%s(%d): error .......................!\n", __FUNCTION__, __LINE__);

        fuse_reply_err(req, ENOMEM);
       return; 
    }
    
    if (dh->data.offset == 0) {
        HR_LOGD("%s(%d): init for read dir...:%s....................!\n", __FUNCTION__, __LINE__, node->name);
        // we should init data
        if (node->data->offset > dh->data.size) {
            tcloud_buffer_realloc(&dh->data, node->data->offset);
        }
        tcloud_buffer_reset(&dh->data);
        dh->offset = 0;
        tcloud_buffer_append(&dh->data, node->data->data, node->data->offset);
    }
#else

    dh = (struct tcloudfs_dh *)fi->fh;

    if (!dh) {
        HR_LOGD("%s(%d): error .......................!\n", __FUNCTION__, __LINE__);

        fuse_reply_err(req, ENOMEM);
        return;
    }

    if (offset == 0 /*dh->data.offset == 0*/) {
        node->expire_time = 0;  // force expire only for tests
        tcloudfs_update_directory(node);
        // cache timing ?
        now = time(NULL);

        printf("%s(%d): .........priv:%p, ino:%" PRIu64
               ", size:%ld, offset:%ld, fi:%p, time :%ld, expire:%ld\n",
               __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi, now, node->expire_time);
        // using cache
        struct tcloudfs_node *p = NULL;

        // printf("%s(%d).....using cache.....\n", __FUNCTION__, __LINE__)
        struct stat st;
        memset((void *)&st, 0, sizeof(st));
        // st.st_mode = S_IFDIR;
        dh->offset = 0;
        tcloud_buffer_reset(&dh->data);
        size_t entlen = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
        entlen = fuse_add_direntry(req, dh->data.data + dh->data.offset,
                                   (dh->data.size - dh->data.offset), ".",
                                   &st, dh->data.offset + entlen);
        dh->data.offset += entlen;
        entlen = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);
        entlen = fuse_add_direntry(req, dh->data.data + dh->data.offset,
                                   (dh->data.size - dh->data.offset), "..",
                                   &st, dh->data.offset + entlen);
        dh->data.offset += entlen;

        hr_list_for_each_entry(p, &node->childs, entry) {
            HR_LOGD("%s(%d): read dir fill entry %p -> %ld -> %s, dir:%d, mode type:%o\n", __FUNCTION__, __LINE__, p, p->cloud_id, p->name, S_ISDIR(p->mode), p->mode & S_IFMT);
            st.st_mode = p->mode;  // & S_IFMT /*S_IFDIR*/;
            st.st_ino = (fuse_ino_t)p;
            entlen = fuse_add_direntry(req, NULL, 0, p->name, NULL, 0);
            if (dh->data.offset + entlen > dh->data.size) {
                tcloud_buffer_realloc(&dh->data, dh->data.size + entlen + 256);
            }
            entlen = fuse_add_direntry(req, dh->data.data + dh->data.offset,
                                       (dh->data.size - dh->data.offset),
                                       p->name, &st, dh->data.offset + entlen);
            dh->data.offset += entlen;
        }
    }

#endif

    size_t total = dh->data.offset;
    printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__,
           __LINE__, total, dh->offset, size);
    if (offset >= total) {
        printf("%s(%d): end ..........\n", __FUNCTION__, __LINE__);
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (size > total - offset) {
        size = total - offset;
    }
    printf("%s(%d): total:%ld, offset:%ld, size:%ld.....buffer.size:%ld.....\n", __FUNCTION__,
           __LINE__, total, offset, size, dh->data.size);
    // we should allocate new memory to reply
    // void *mm = malloc(size);
    // memcpy(mm, node->data->data + offset, size);
    fuse_reply_buf(req, dh->data.data + offset, size);
    // fuse_reply_buf(req, mm, size);
    dh->offset = offset + size;
    printf("%s(%d): now offset:%ld, buffer %ld vs %ld..........\n", __FUNCTION__,
           __LINE__, dh->offset, dh->data.offset, dh->data.size);
}
static void tcloudfs_releasedir(fuse_req_t req, fuse_ino_t ino,
                                struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_dh *dh = NULL;
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node) {
        fuse_reply_err(req, ENOENT);
        return;
    }
#if 0
    if (node->data) {
        tcloud_buffer_free(node->data);
        free(node->data);
        node->data = NULL;
    }
#endif
    dh = (struct tcloudfs_dh *)fi->fh;

    if (!dh) {
        HR_LOGD("%s(%d): error .......................!\n", __FUNCTION__, __LINE__);

        fuse_reply_err(req, ENOMEM);
        return;
    }

    tcloud_buffer_free(&dh->data);
    dh->offset = 0;
    free(dh);

    fi->fh = (intptr_t)NULL;

    HR_LOGD("%s(%d): release dir :%s\n", __FUNCTION__, __LINE__, node->name);
    fuse_reply_err(req, 0);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
}

static void tcloudfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                           mode_t mode) {
    printf("%s(%d): .........priv:%p, parent:%" PRIu64 ", name:%s, mode:%o\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), parent, name, mode);
    struct tcloudfs_node *node = find_node(req, parent);

    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): mkdir :%s\n", __FUNCTION__, __LINE__, node->name);
    struct fuse_entry_param e;
    int64_t id = tcloud_drive_mkdir(node->cloud_id, name);
    if (id < 0) {
        // it's invalid id
        printf("can not create dir\n");
        // fuse_reply_err(req, -EIO);
    }
    struct tcloudfs_node *n = allocate_node(id, name, node);
    n->mode = S_IFDIR | mode;
    n->size = 4096;

    n->ctime.tv_sec = time(NULL);
    n->atime.tv_sec = time(NULL);
    n->mtime.tv_sec = time(NULL);

    e.ino = (fuse_ino_t)n;
    e.attr.st_mode = n->mode;
    e.attr.st_size = n->size;
    e.generation = e.ino;

    // using large timeout, which can reduce lookup callback
    e.attr_timeout = _priv.opts.attr_timeout;
    e.entry_timeout = _priv.opts.entry_timeout;
    fuse_reply_entry(req, &e);
}

static void tcloudfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name) {
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    struct tcloudfs_node *p = NULL;
    if (parent == 1) {
        node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
        HR_LOGD("%s(%d): root not allowed!\n");
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    } else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)parent;
    }

    if (!node || !is_valid_node(node)) {
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (hr_list_empty(&node->childs)) {
        tcloudfs_update_directory(node);
    }

    hr_list_for_each_entry(p, &node->childs, entry) {
        if (0 == strcmp(name, p->name)) {
            HR_LOGD("%s(%d): found node:%p\n", __FUNCTION__, __LINE__, p);
            if (!S_ISDIR(p->mode)) {
                HR_LOGD("%s(%d): not dir!\n");
                fuse_reply_err(req, EREMOTEIO);
                return;
            }

            tcloud_drive_rmdir(p->cloud_id, name);
            deallocate_node(p);

            // parent expire immediately
            // node->expire_time = 0;
#if 0
            if (node->data) {
                tcloud_buffer_free(node->data);
                node->data = 0;
            }
#endif

            fuse_reply_err(req, 0);
            return;
        }
    }

    fuse_reply_err(req, ENOENT);
}

static void tcloudfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name) {
    struct tcloudfs_node *node = NULL;
    struct tcloudfs_node *p = NULL;

    node = find_node(req, parent);
    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    if (hr_list_empty(&node->childs)) {
        tcloudfs_update_directory(node);
    }

    hr_list_for_each_entry(p, &node->childs, entry) {
        if (0 == strcmp(name, p->name)) {
            tcloud_drive_unlink(p->cloud_id, name);
            // maybe we should delete in forget
            deallocate_node(p);
            // expire immediately
            // node->expire_time = 0;
            // do not expire immediately, because server maybe slow ...
#if 0
            if (node->data) {
                tcloud_buffer_free(node->data);
                free(node->data);
                node->data = NULL;
            }
#endif
            fuse_reply_err(req, 0);
            return;
        }
    }

    fuse_reply_err(req, ENOENT);
}

static void tcloudfs_rename(fuse_req_t req, fuse_ino_t olddir, const char *oldname, fuse_ino_t newdir, const char *newname, unsigned int flags) {
    printf("%s(%d): .........priv:%p, old:%" PRIu64 "new:%" PRIu64 ", name:%s -> %s\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), olddir, newdir, oldname, newname);

    // struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node_old_dir = NULL, *node_new_dir = NULL;
    struct tcloudfs_node *node = NULL, *p = NULL;

    node_old_dir = find_node(req, olddir);
    node_new_dir = find_node(req, newdir);
    if (!node_old_dir || !node_new_dir) {
        fuse_reply_err(req, ENOENT);
        return;
    }

#if 0
    // only support rename at current directory!
    if (node_old_dir != node_new_dir) {
        // HR_LOGD("%s(%d): do not support rename crossing directory !\n", __FUNCTION__, __LINE__);
        node_old_dir->expire_time = 0;
        node_new_dir->expire_time = 0;

        // fuse_reply_err(req, EPERM);
        fuse_reply_err(req, 0);
        return;
    }
#endif

    if (hr_list_empty(&node_old_dir->childs)) {
        tcloudfs_update_directory(node_old_dir);
    }

    hr_list_for_each_entry(p, &node_old_dir->childs, entry) {
        if (0 == strcmp(oldname, p->name)) {
            HR_LOGD("%s(%d): found node:%p\n", __FUNCTION__, __LINE__, p);
            if (node_old_dir == node_new_dir) {
                tcloud_drive_rename(p->cloud_id, newname, S_ISDIR(p->mode) ? 1 : 0);
                // only rename
                // no need do anythings, because we do not move directory
                free(p->name);
                p->name = strdup(newname);
                // we should not deallocate_node(p), because getattr will be called after rename
            } else {
                // only move, not rename
                HR_LOGD("%s(%d): rename crossing directory, keep old name !\n", __FUNCTION__, __LINE__);
                tcloud_drive_move(p->cloud_id, p->name, node_new_dir->cloud_id, S_ISDIR(p->mode) ? 1 : 0);
            }
            // delete will leading error!
            // expire immediately
            node_old_dir->expire_time = 0;
            node_new_dir->expire_time = 0;

            fuse_reply_err(req, 0);
            return;
        }
    }

    fuse_reply_err(req, ENONET);
}

static void tcloudfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                            mode_t mode, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, parent:%" PRIu64 ", name:%s\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), parent, name);
    struct fuse_entry_param e;
    struct tcloudfs_node *node = find_node(req, parent);

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node) {
        HR_LOGD("%s(%d): can not create %s in %ld\n", __FUNCTION__, __LINE__, name, parent);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    HR_LOGD("%s(%d): create  %s at %s, with mode:%o\n", __FUNCTION__, __LINE__, name, node->name, mode);
    // we should get file id, maybe we should give it an invalid no, here
    struct tcloudfs_node *n = allocate_node(TCLOUD_DRIVE_RESERVE_ID, name, node);
    // n->mode = S_IFREG | mode;
    n->mode = S_IFREG | TCLOUDFS_DEFAULT_MODE;

    fi->direct_io = 1;
    fi->noflush = 1;
    // fi->fh = 0x808123456;

    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
    fi->fh = (uint64_t)tcloud_drive_create(name, node->cloud_id);

    printf("%s(%d): create fi->fh:%ld\n", __FUNCTION__, __LINE__, fi->fh);
    n->ctime.tv_sec = time(NULL);
    n->atime.tv_sec = time(NULL);
    n->mtime.tv_sec = time(NULL);

    e.ino = (fuse_ino_t)n;
    e.attr.st_mode = S_IFREG | mode;
    e.attr.st_size = 0;
    e.attr.st_ctim.tv_sec = n->ctime.tv_sec;
    e.attr.st_atim.tv_sec = n->atime.tv_sec;
    e.attr.st_mtim.tv_sec = n->mtime.tv_sec;

    e.attr.st_blksize = 4096;
    e.attr.st_blocks = node->size / e.attr.st_blksize;

    e.attr.st_gid = _priv.opts.gid;
    e.attr.st_uid = _priv.opts.uid;

    e.generation = e.ino;
    // mxp, 20240607, use large timeout, fixed samba copy error!
    // using large timeout, which can reduce lookup callback
    e.attr_timeout = 3.0f + _priv.opts.attr_timeout;
    e.entry_timeout = 3.0f + _priv.opts.entry_timeout;
    fuse_reply_create(req, &e, fi);
}
static void tcloudfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_node *node = find_node(req, ino);

    HR_LOGD("open node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    if (!node) {
        // not found, but this create operation
        if (fi->flags & O_CREAT) {
        }
        fuse_reply_err(req, ENOENT);
        return;
    }

    HR_LOGD("%s(%d): open %s with create?:%d, with trunc:%d, all flags:%o\n", __FUNCTION__, __LINE__, node->name, fi->flags & O_CREAT, fi->flags & O_TRUNC, fi->flags);
    if (!S_ISREG(node->mode)) {
        fuse_reply_err(req, EPERM);
        return;
    }

    fi->direct_io = 1;
    fi->noflush = 1;

    if (fi->flags & O_TRUNC) {
        HR_LOGD("%s(%d): @@@@@@@@@@@@@@@@ using trunc write:%s @@@@@@@@@@@@@@@@@@@@@@@\n", __FUNCTION__, __LINE__, node->name);
        node->size = 0;
        node->truncate_size = 0;
        fi->fh = (uint64_t)tcloud_drive_create(node->name, node->parent->cloud_id);
        fuse_reply_open(req, fi);
        return;
    }

    fi->fh = (uint64_t)tcloud_drive_open(node->cloud_id);
    fuse_reply_open(req, fi);
}

static void tcloudfs_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    int64_t id = -1;
    struct tcloudfs_node *node = find_node(req, ino);
    if (!node) {
        fuse_reply_err(req, -ENOENT);
        return;
    }

    node->mtime.tv_sec = time(NULL);
    HR_LOGD("%s(%d): release %s\n", __FUNCTION__, __LINE__, node->name);
    tcloud_drive_release((struct tcloud_drive_fd *)fi->fh, &id);

    // force release, so we can update cloud id
    if (node->cloud_id == TCLOUD_DRIVE_RESERVE_ID) {
        HR_LOGD("%s(%d): release %s, force flush parent ...\n", __FUNCTION__, __LINE__, node->name);
        node->atime.tv_sec = time(NULL);
        node->mtime.tv_sec = time(NULL);
        node->cloud_id = id;
        HR_LOGD("%s(%d): release %s, got id:%ld ...\n", __FUNCTION__, __LINE__, node->name, node->cloud_id);
        // if (node->parent) {
        //     node->parent->expire_time = 0;
        // }
    }

    if (id == TCLOUD_DRIVE_RESERVE_ID) {
        // upload failed, mxp , tests
        HR_LOGD("%s(%d): release %s, -> :%ld upload failed delete auto .....\n", __FUNCTION__, __LINE__, node->name, node->cloud_id);
        deallocate_node(node);
    }
    fuse_reply_err(req, 0);
}

#if 0
static void tcloudfs_ioctl(fuse_req_t req, fuse_ino_t ino, unsigned int cmd,
                           void *arg, struct fuse_file_info *llfi,
                           unsigned int flags, const void *in_buf,
                           size_t in_bufsz, size_t out_bufsz) {
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
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): cmd :0x%X\n", __FUNCTION__, __LINE__, cmd);

    fuse_reply_err(req, 0);
}
#endif

static void tcloudfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    struct tcloudfs_node *node = find_node(req, ino);

    if (!node) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        fuse_reply_err(req, ENONET);
        return;
    }

    if (!fi->fh) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        fuse_reply_err(req, EBADF);
        return;
    }
#if 0
    struct fuse_bufvec *b = NULL;

    void *mem;

    b = malloc(sizeof(struct fuse_bufvec));
    if (b == NULL) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        fuse_reply_err(req, -ENOMEM);
        return;
    }

    mem = malloc(size);
    if (mem == NULL) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        free(b);
        fuse_reply_err(req, -ENOMEM);
        return;
    }
    *b = FUSE_BUFVEC_INIT(size);

    size_t rs = tcloud_drive_read((struct tcloud_drive_fd *)fi->fh, mem, size, off);
    b->buf[0].mem = mem;
    b->buf[0].size = rs;

    printf("%s(%d):  .............read:%ld\n", __FUNCTION__, __LINE__, rs);
    if (rs >= 0) {
        fuse_reply_data(req, b, FUSE_BUF_SPLICE_MOVE);
    } else {
        fuse_reply_err(req, rs);
    }
#else
    HR_LOGD("read node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    char *ptr = malloc(size /*+ off*/);
    size = tcloud_drive_read((struct tcloud_drive_fd *)fi->fh, ptr, size, off);
    // HR_LOGD("read node :%p -> %s,  vs fi->fh:%p, return size:%ld\n", node, node->name, (void *)fi->fh, size);
    if (size < 0) {
        fuse_reply_err(req, -size);
        free(ptr);
        return;
    }
#if 0    
    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);
    buf.buf[0].flags = static_cast<fuse_buf_flags>(
        FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK);
    buf.buf[0].mem = ptr + off;
    buf.buf[0].size = size;

    fuse_reply_data(req, &buf, FUSE_BUF_COPY_FLAGS)
#endif
    // *ptr = 'm';
    // *(ptr + 1) = 'x';
    // *(ptr + 2) = 'x';
    fuse_reply_buf(req, ptr /*+ off*/, size);
    free(ptr);
#endif
}

static void tcloudfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                           size_t size, off_t off, struct fuse_file_info *fi) {
    struct tcloud_drive_fd *fd = NULL;  // fi->fh
    struct tcloudfs_node *node = find_node(req, ino);
    //
    if (!node) {
        HR_LOGD("%s(%d): can not found this file........\n", __FUNCTION__, __LINE__);
        fuse_reply_err(req, ENOENT);
        return;
    }

    fd = (struct tcloud_drive_fd *)fi->fh;
    if (!fd) {
        printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
        fuse_reply_err(req, EBADF);
        return;
    }

    HR_LOGD("%s(%d): write file:%s, offset:%ld, size:%ld .....\n", __FUNCTION__, __LINE__, node->name, off, size);

    // if size is 0, we should call truncate
    if (fd->size == 0 && node->truncate_size != 0) {
        tcloud_drive_truncate(fd, node->truncate_size);
    }

    int rc = tcloud_drive_write(fd, buf, size, off);

    HR_LOGD("%s(%d): write file:%s, offset:%ld, real size:%ld .....\n", __FUNCTION__, __LINE__, node->name, off, size);

    if (rc >= 0) {
        node->size += rc;
        fuse_reply_write(req, size);
    } else {
        fuse_reply_err(req, -rc);
    }
}

#if 0
static void tcloudfs_write_buf(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *in_buf,
                               off_t off, struct fuse_file_info *fi) {
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
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    if (!S_ISREG(node->mode)) {
    }

    HR_LOGD("%s(%d): write file:%s, offset:%ld .....\n", __FUNCTION__, __LINE__, node->name, off);
    if (node->cloud_id == 0xFF0000001) {
        HR_LOGD("we should create the file first .................new upload .....\n", __FUNCTION__);
        node->atime.tv_sec = time(NULL);
        node->ctime.tv_sec = time(NULL);
        node->mtime.tv_sec = time(NULL);
    }

    size_t size = fuse_buf_size(in_buf);

    struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT(size);
    out_buf.buf[0].flags = FUSE_BUF_FD_SEEK;
    // out_buf.buf[0].fd = fi->fh;
    out_buf.buf[0].mem = malloc(size);
    out_buf.buf[0].pos = off;

    ssize_t res = fuse_buf_copy(&out_buf, in_buf, 0);
    if (res < 0)
        fuse_reply_err(req, -res);
    else
        fuse_reply_write(req, (size_t)res);

    free(out_buf.buf[0].mem);
}
#endif

static void tcloudfs_flush(fuse_req_t req, fuse_ino_t ino,
                           struct fuse_file_info *fi) {
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): node:%p -> %s\n", __FUNCTION__, __LINE__, node, node->name);

    fuse_reply_err(req, 0);
}

static void tcloudfs_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
                           struct fuse_file_info *fi) {
    off_t res = 0;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    (void)ino;
    fuse_reply_lseek(req, res);
    // fuse_reply_err(req, errno);
}

static void tcloudfs_statfs(fuse_req_t req, fuse_ino_t ino) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    // if (ino == FUSE_ROOT_ID) {
    node = hr_list_first_entry(&priv->head, struct tcloudfs_node, entry);
    // }
#if 0    
     else {
        // we can directly use parent ino, because it's node pointer
        // but we should verify it
        // struct tcloudfs_node *p = NULL;
        // hr_list_for_each_entry(p, &priv->head, entry) {
        //
        // }
        node = (struct tcloudfs_node *)ino;
    }
#endif
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): node:%p -> %s\n", __FUNCTION__, __LINE__, node, node->name);

    time_t now = time(NULL);

    if (now > priv->st.last_time + 60) {
        if (0 == tcloud_drive_storage_statfs(&priv->st.st)) {
            priv->st.last_time = now;
        }
    }

    fuse_reply_statfs(req, &priv->st.st);
}

static void tcloudfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset,
                               off_t length, struct fuse_file_info *fi) {
    (void)ino;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
}

static void tcloudfs_listxattr(fuse_req_t req, fuse_ino_t ino, size_t size) {
}
static void tcloudfs_getxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                              size_t size) {
    (void)size;
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    struct tcloudfs_xattr *p = NULL;
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): node:%p -> %s\n", __FUNCTION__, __LINE__, node, node->name);
    HR_LOGD("%s(%d): node:%p -> %s, name:%s\n", __FUNCTION__, __LINE__, node, node->name, name);

    hr_list_for_each_entry(p, &priv->xattrs, entry) {
        HR_LOGD("%s(%d): node:%p -> %s, name:%s -> %s\n", __FUNCTION__, __LINE__, node, node->name, name, p->name);
        if (!strcmp(p->name, name)) {
            if (size == 0) {
                fuse_reply_xattr(req, p->size);
                return;
            }

            fuse_reply_buf(req, p->value, p->size);
            return;
        }
    }
    HR_LOGD("%s(%d): NODATA node:%p -> %s, name:%s\n", __FUNCTION__, __LINE__, node, node->name, name);
    fuse_reply_err(req, ENODATA);
}
static void tcloudfs_setxattr(fuse_req_t req, fuse_ino_t ino, const char *name,
                              const char *value, size_t size, int flags) {
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    struct tcloudfs_xattr *p = NULL;
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    HR_LOGD("%s(%d): node:%p -> %s\n", __FUNCTION__, __LINE__, node, node->name);
    HR_LOGD("%s(%d): node:%p -> %s, name:%s, value:%s\n", __FUNCTION__, __LINE__, node, node->name, name, value);
#if 0
    hr_list_for_each_entry(p, &priv->xattrs, entry) {
        HR_LOGD("%s(%d): node:%p -> %s, name:%s -> %s\n", __FUNCTION__, __LINE__, node, node->name, name, p->name);
        if (!strcmp(p->name, name)) {
            if (flags & XATTR_CREATE) {
                fuse_reply_err(req, EEXIST);
                return;
            }
            if (p->value) {
                free(p->value);
                p->value = NULL;
            }

            p->value = calloc(1, size);
            memcpy(p->value, value, size);

            fuse_reply_err(req, 0);
            return;
        }

        // fuse_reply_err(req, ENOSYS);
        fuse_reply_err(req, ENODATA);
        return;
    }

    if (flags & XATTR_REPLACE) {
        fuse_reply_err(req, ENODATA);
        return;
    }

    struct tcloudfs_xattr *attr = (struct tcloudfs_xattr*)calloc(1, sizeof(struct tcloudfs_xattr));
    HR_INIT_LIST_HEAD(&attr->entry);
    hr_list_add_tail(&priv->xattrs, &attr->entry);
    p->name = strdup(name);
    p->value = calloc(1, size);
    memcpy(p->value, value, size);
#endif
    fuse_reply_err(req, 0);
}

static void tcloudfs_copy_file_range(fuse_req_t req, fuse_ino_t nodeid_in,
                                     off_t off_in, struct fuse_file_info *fi_in,
                                     fuse_ino_t nodeid_out, off_t off_out,
                                     struct fuse_file_info *fi_out, size_t len,
                                     int flags) {
#if 0
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }


    HR_LOGD("%s(%d): node:%p -> %s\n", __FUNCTION__, __LINE__, node, node->name);

#endif

    HR_LOGD("%s(%d): ................\n", __FUNCTION__, __LINE__);

    fuse_reply_err(req, ENOSYS);
}
static const struct fuse_lowlevel_ops tcloudfs_ops = {
    .init = tcloudfs_init,
    .lookup = tcloudfs_lookup,
    .forget = tcloudfs_forget,
    .forget_multi = tcloudfs_forget_multi,
    .getattr = tcloudfs_getattr,
    .setattr = tcloudfs_setattr,
    .access = tcloudfs_access,
    .opendir = tcloudfs_opendir,
    .readdir = tcloudfs_readdir,
    .releasedir = tcloudfs_releasedir,
    .mkdir = tcloudfs_mkdir,
    .rmdir = tcloudfs_rmdir,
    .unlink = tcloudfs_unlink,
    .rename = tcloudfs_rename,
    .create = tcloudfs_create,
    .open = tcloudfs_open,
    // .ioctl = tcloudfs_ioctl,
    .write = tcloudfs_write,
    // .write_buf = tcloudfs_write_buf,  // not support
    .release = tcloudfs_release,
    .flush = tcloudfs_flush,
    .read = tcloudfs_read,
    .lseek = tcloudfs_lseek,
    .statfs = tcloudfs_statfs,
    .fallocate = tcloudfs_fallocate,
    //.getxattr = tcloudfs_getxattr,
    //.setxattr = tcloudfs_setxattr,
    //.listxattr = tcloudfs_listxattr,
    // .copy_file_range = tcloudfs_copy_file_range,
};

static const struct fuse_opt tcloudfs_opts[] = {
    TCLOUDFS_OPT("uid=%d", uid, 0),
    TCLOUDFS_OPT("gid=%d", gid, 0),
    TCLOUDFS_OPT("attr_timeout=%lf", attr_timeout, 0),
    TCLOUDFS_OPT("entry_timeout=%lf", entry_timeout, 0),
    FUSE_OPT_END};

static int tcloudfs_opt_proc(void *data, const char *arg, int key,
                             struct fuse_args *outargs) {
    (void)arg;
    (void)outargs;
    (void)data;
    (void)key;

    /* Pass through unknown options */
    return 1;
}

int main(int argc, char **argv) {
    int ret = 0;

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *config;
    memset((void *)&_priv, 0, sizeof(_priv));

    pthread_mutex_init(&_priv.mutex, NULL);

    // init empty link
    HR_INIT_LIST_HEAD(&_priv.head);
    HR_INIT_LIST_HEAD(&_priv.delete_pending_queue);

    HR_INIT_LIST_HEAD(&_priv.xattrs);

    tcloud_drive_init();

    struct tcloudfs_node *root = allocate_node(-11 /*FUSE_ROOT_ID*/, "/", NULL);
    root->mode = S_IFDIR | TCLOUDFS_DEFAULT_MODE;

    tcloud_drive_getattr(root->cloud_id, 0 /*folder*/, &root->atime, &root->ctime);

    root->mtime = root->atime;
    hr_list_add_tail(&root->entry, &_priv.head);

    _priv.opts.uid = getuid();
    _priv.opts.gid = getgid();

    _priv.opts.attr_timeout = 1.0f;
    _priv.opts.entry_timeout = 1.0f;

    if (fuse_opt_parse(&args, &_priv.opts, tcloudfs_opts, tcloudfs_opt_proc) == -1) {
        printf("%s(%d): argument parse failed ...\n", __FUNCTION__, __LINE__);
        return -1;
    }

    printf("uid:%d(%d), gid:%d(%d)\n", _priv.opts.uid, getuid(), _priv.opts.gid, getgid());

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;

    se = fuse_session_new(&args, &tcloudfs_ops, sizeof(tcloudfs_ops), &_priv);
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

    printf("%s(%d) unmount .....\n", __FUNCTION__, __LINE__);
    fuse_session_unmount(se);
gone_3:
    fuse_remove_signal_handlers(se);
gone_2:
    fuse_session_destroy(se);
gone_1:
    deallocate_node(root);
    tcloud_drive_destroy();

    if (opts.mountpoint)
        free(opts.mountpoint);
    fuse_opt_free_args(&args);
    pthread_mutex_destroy(&_priv.mutex);

    return 0;
}
