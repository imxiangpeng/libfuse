
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#include <sys/stat.h>
#endif

#define FUSE_USE_VERSION FUSE_VERSION

#include <stdbool.h>
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

#include "uthash.h"
#include "hr_log.h"

#define TCLOUDFS_DEFAULT_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
// default root directory is -11
#define TCLOUDFS_DEFAULT_ROOT_ID -11

#define TCLOUDFS_NODE_DEFAULT_EXPIRE_TIME 60  // 5s

struct tcloudfs_node {
    ino_t ino;  // --> id
    int64_t cloud_id;
    uint64_t refcount;
    char *name;
    off_t offset;
    size_t size;
    mode_t mode;
    void *tcloud_drive_handle;

    struct timespec atime;  // last access time
    struct timespec mtime;  // last modification
    struct timespec ctime;  // last status change time( create?)
    time_t expire_time;
    struct tcloud_buffer *data;
    struct tcloudfs_node *hash_node;
    // struct j2sobject *dir;
    // directory child lists
    struct tcloudfs_node *parent;
    struct hr_list_head entry;
    struct hr_list_head childs;  // folder head
    UT_hash_handle hh;
};

struct tcloudfs_priv {
    pthread_mutex_t mutex;

    struct {
        time_t last_time;
        struct statvfs st;
    } st;
    struct tcloudfs_node *hash_node_lists;  // verify node is valid ...
    // uint32_t default_root_id;
    /// struct tcloudfs_node root;
    struct hr_list_head head;
    // should be deleted nodes
    struct hr_list_head delete_pending_queue;
};

static struct tcloudfs_priv _priv;
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

static int tcloudfs_update_directory(struct tcloudfs_node *node) {
    int ret = 0;
    HR_LIST_HEAD(remove_queue);
    HR_LIST_HEAD(add_queue);

    time_t now = time(NULL);
    if (now < node->expire_time) {
        return 0;
    }

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
    ret = tcloud_drive_readdir(node->cloud_id, dir);
    if (ret != 0) {
        j2sobject_free(J2SOBJECT(dir));

        return -1;
    }

    struct j2scloud_folder_resp *object = dir;
    j2scloud_folder_t *d = NULL;

    if (object->folderList) {
        for (d = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
             d != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
             d = (j2scloud_folder_t *)J2SOBJECT(d)->next) {
            // printf("%s(%d): dir name: %s, id:%ld\n", __FUNCTION__, __LINE__, d->name, (uint64_t)d->id);
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

                printf("%s(%d): %s ctime:%ld, mtime:%ld, atime:%ld\n", __FUNCTION__, __LINE__, p->name, p->ctime.tv_sec, p->mtime.tv_sec, p->atime.tv_sec);
            }
        }
    }
    if (object->fileList) {
        j2scloud_file_t *f = NULL;
        for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
             f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
             f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
            int use_cache = 0;
            // printf("%s(%d): file name: %s\n", __FUNCTION__, __LINE__, f->name);
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
            }
            if (use_cache == 0) {
                // printf("add new file :%s\n", f->name);
                p = allocate_node((uint64_t)f->id, f->name, node);
                p->mode = S_IFREG | TCLOUDFS_DEFAULT_MODE;
                p->size = f->size;
                timespec_from_date_string(&p->ctime, f->createDate);
                timespec_from_date_string(&p->atime, f->lastOpTime);
                timespec_from_date_string(&p->mtime, f->lastOpTime);
                printf("%s(%d): %s ctime:%ld, mtime:%ld, atime:%ld\n", __FUNCTION__, __LINE__, p->name, p->ctime.tv_sec, p->mtime.tv_sec, p->atime.tv_sec);
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
    node->offset = 0;

    j2sobject_free(J2SOBJECT(dir));
    hr_list_for_each_entry_safe(p, n, &remove_queue, entry) {
        printf("remove expire nodes: %p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
        deallocate_node(p);
    }
    return ret;
}
static void tcloudfs_init(void *userdata, struct fuse_conn_info *conn) {
    struct tcloudfs_priv *priv = (struct tcloudfs_data *)userdata;

    // tcloud_drive_init();

    printf("%s(%d): .........priv:%p,   conn:%p, capab:0x%X\n", __FUNCTION__, __LINE__, priv, conn, conn->capable);
    conn->max_read = 1024 *1024 * 2;
    printf("%s(%d): .........priv:%p,   conn:%p\n", __FUNCTION__, __LINE__, priv, conn);
    
    if (conn->capable & FUSE_CAP_ASYNC_READ) {
        printf("drop : FUSE_CAP_ASYNC_READ\n");
        // conn->capable &= ~FUSE_CAP_ASYNC_READ;
    }
    
    conn->want &= ~FUSE_CAP_ASYNC_READ;
    conn->want &= ~FUSE_CAP_SPLICE_READ;   
    conn->want &= ~FUSE_CAP_SPLICE_WRITE;
    conn->want &= ~FUSE_CAP_SPLICE_MOVE;
    conn->want &= ~FUSE_CAP_EXPORT_SUPPORT;
    conn->want &= ~FUSE_CAP_IOCTL_DIR;

   conn->want &= ~FUSE_CAP_ASYNC_DIO; 
    
    conn->want &= ~FUSE_CAP_SETXATTR_EXT;
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    if (!node || !S_ISDIR(node->mode)) {
        printf("no ........node:%p, node dir:%d........\n", node, S_ISDIR(node->mode));
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    // e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    // only update directory when readdir for better performance
    if (hr_list_empty(&node->childs)) {
        tcloudfs_update_directory(node);
    }

    hr_list_for_each_entry(p, &node->childs, entry) {
        printf("%s(%d): node:%p,  child: id:%ld, name:%s, dir:%d\n", __FUNCTION__, __LINE__, p, p->cloud_id, p->name, S_ISDIR(p->mode));
        if (0 == strcmp(name, p->name)) {
            printf("got :%s\n", name);
            e.attr.st_mode = p->mode | TCLOUDFS_DEFAULT_MODE;
            e.attr.st_ino = (fuse_ino_t)p;
            e.attr.st_nlink = S_ISDIR(p->mode) ? 1 : 2;
            e.attr.st_ctim = p->ctime;
            e.attr.st_mtim = p->mtime;
            e.attr.st_atim = p->atime;
            printf("got :%s, create time:%ld\n", name, e.attr.st_ctim.tv_sec);
            printf("got :%s, create time:%ld\n", name, p->ctime.tv_sec);
            printf("got :%s, m time:%ld\n", name, p->mtime.tv_sec);

            printf("%s(%d): %s ctime:%ld, mtime:%ld, atime:%ld\n", __FUNCTION__, __LINE__, p->name, p->ctime.tv_sec, p->mtime.tv_sec, p->atime.tv_sec);
            // if (S_ISREG(p->mode)) {
            e.attr.st_size = p->size;

            e.attr.st_uid = 1000;
            e.attr.st_gid = 1000;
            // printf("%s -> %ld, mode:%o, file size:%ld\n", p->name, e.attr.st_size, e.attr.st_mode, p->size);
            // }

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
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    if (!is_valid_node(node)) {
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

    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    st.st_ino = (fuse_ino_t)node;
    st.st_mode = node->mode | TCLOUDFS_DEFAULT_MODE;
    st.st_nlink = 1;
    st.st_atim = node->atime;  // last access time
    st.st_ctim = node->ctime;  // last status change time( create?)
    st.st_mtim = node->mtime;  // last modification
    if (S_ISREG(node->mode)) {
        st.st_size = node->size;
        printf("%s -> %ld\n", node->name, st.st_size);
    } else {
        st.st_size = 4096;
    }

    printf("%s(%d): name:%s last time:%ld, modification time:%ld\n", __FUNCTION__, __LINE__, node->name, node->mtime.tv_sec, node->mtime.tv_sec);
    // st.st_gid = 1000;
    // st.st_uid = 1000;
    fuse_reply_attr(req, &st, 1.0);
}

static void tcloudfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                             int valid, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", valid:0x%X\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino, valid);
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

    if (valid & FUSE_SET_ATTR_MODE) {
        printf("set attr mode ...mode:%o.\n", attr->st_mode);
    }
    if (valid & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {
        printf("set gid:%d / gid:%d\n", attr->st_gid, attr->st_uid);
    }
    if (valid & FUSE_SET_ATTR_SIZE) {
        printf("set size ...:%ld\n", attr->st_size);
    }
    fuse_reply_attr(req, attr, 1.0);
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
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    fuse_reply_err(req, 0);
}
static void tcloudfs_opendir(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    // printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
    //       fuse_req_userdata(req), ino);
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

    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d): can not open dir\n", __FUNCTION__, __LINE__);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    fuse_reply_open(req, fi);
}

static void tcloudfs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
                             off_t offset, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64
           ", size:%ld, offset:%ld, fi:%p\n",
           __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi);

    time_t now = 0;
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

    // printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node || !S_ISDIR(node->mode)) {
        printf("%s(%d):  not support name:%s\n", __FUNCTION__, __LINE__, node->name);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    tcloudfs_update_directory(node);

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
        // using cache
        struct tcloudfs_node *p = NULL;

        // printf("%s(%d).....using cache.....\n", __FUNCTION__, __LINE__);
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
            // printf("%p -> %ld -> %s, dir:%d\n", p, p->cloud_id, p->name, S_ISDIR(p->mode));
            st.st_mode = p->mode /*S_IFDIR*/;
            st.st_ino = (fuse_ino_t)p;
            entlen = fuse_add_direntry(req, NULL, 0, p->name, NULL, 0);
            entlen = fuse_add_direntry(req, node->data->data + node->data->offset,
                                       (node->data->size - node->data->offset),
                                       p->name, &st, node->data->offset + entlen);
            node->data->offset += entlen;
        }
    }

    size_t total = node->data->offset;
    // printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__,
    //       __LINE__, total, offset, size);
    if (offset >= total) {
        printf("%s(%d): end ..........\n", __FUNCTION__, __LINE__);
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (size > total - offset) {
        size = total - offset;
    }
    // printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__,
    //       __LINE__, total, offset, size);
    fuse_reply_buf(req, node->data->data + offset, size);
    node->offset = offset + size;
    // printf("%s(%d): now offset:%ld, buffer %ld vs %ld..........\n", __FUNCTION__,
    //        __LINE__, node->offset, node->data->offset, node->data->size);
}
static void tcloudfs_releasedir(fuse_req_t req, fuse_ino_t ino,
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

static void tcloudfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
                           mode_t mode) {
    printf("%s(%d): .........priv:%p, parent:%" PRIu64 ", name:%s, mode:%o\n", __FUNCTION__,
           __LINE__, fuse_req_userdata(req), parent, name, mode);
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

    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    struct fuse_entry_param e;
    int64_t id = tcloud_drive_mkdir(node->cloud_id, name);
    if (id < 0) {
        // it's invalid id
        printf("can not create dir\n");
        fuse_reply_err(req, -EIO);
    }
    struct tcloudfs_node *n = allocate_node(id, name, node);
    n->mode = S_IFDIR | mode;

    e.ino = (fuse_ino_t)n;
    e.attr.st_mode = n->mode;
    e.attr.st_size = 0;
    e.generation = e.ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    fuse_reply_entry(req, &e);
}
static void tcloudfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
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
    if (!is_valid_node(node)) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    struct tcloudfs_node *n = allocate_node(-11, name, node);
    n->mode = S_IFREG | mode;

    e.ino = (fuse_ino_t)n;
    e.attr.st_mode = S_IFREG | mode;
    e.attr.st_size = 0;
    e.generation = e.ino;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    fuse_reply_create(req, &e, fi);
}
static void tcloudfs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
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

    printf("open node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    if (!node) {
        fuse_reply_err(req, -ENOENT);
        return;
    }
    if (!is_valid_node(node)) {
        fuse_reply_err(req, -ENOENT);
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    fi->direct_io = 1;
    fi->noflush = 1;

    HR_LOGD("%s(%d): open with create?:%d, all flags:%o\n", __FUNCTION__, __LINE__, fi->flags & O_CREAT, fi->flags);

    fi->fh = (uint64_t)tcloud_drive_open(node->cloud_id);
    // printf("opened node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    fuse_reply_open(req, fi);
}

static void tcloudfs_release(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    (void)ino;

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

    // printf("node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    if (!node) {
        fuse_reply_err(req, -ENOENT);
        return;
    }
    if (!is_valid_node(node)) {
        fuse_reply_err(req, -ENOENT);
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        return;
    }

    tcloud_drive_release((struct tcloud_drive_fd *)fi->fh);
    fuse_reply_err(req, 0);
}

void tcloudfs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
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

    if (!fi->fh) {
        printf("%s(%d): not invalid node:%p\n", __FUNCTION__, __LINE__, node);
        fuse_reply_err(req, -EBADF);
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
    // HR_LOGD("read node :%p -> %s,  vs fi->fh:%p\n", node, node->name, (void *)fi->fh);
    char *ptr = malloc(size /*+ off*/);
    size = tcloud_drive_read((struct tcloud_drive_fd *)fi->fh, ptr, size, off);
    // HR_LOGD("read node :%p -> %s,  vs fi->fh:%p, return size:%ld\n", node, node->name, (void *)fi->fh, size);
    if (size < 0) {
        fuse_reply_err(req, size);
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
    if (size + off <= node->size) {
        fuse_reply_buf(req, ptr /*+ off*/, size);
    } else {
        fuse_reply_err(req, 0);
    }
    free(ptr);
#endif
}

void tcloudfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
                    size_t size, off_t off, struct fuse_file_info *fi) {
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
#if 0
    // size_t length =fuse_buf_size(buf);
    // do_write_buf(req, size, off, in_buf, fi);
    char *path = NULL;
    asprintf(&path, "/tmp/%s", node->name);
    int fd = open(path, O_CREAT|O_APPEND, 0755);
    free(path);
    lseek(fd, off, SEEK_SET);
    write(fd, buf, size);
    close(fd);
#endif
    node->size = off + size;
    fuse_reply_write(req, size);
}
static void tcloudfs_flush(fuse_req_t req, fuse_ino_t ino,
                           struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__,
           fuse_req_userdata(req), ino);
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
    struct statvfs st;
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

    memset((void *)&st, 0, sizeof(st));
    st.f_namemax = 255;
    st.f_bsize = 4096;
    time_t now = time(NULL);
    if (now < priv->st.last_time + 60) {
        if (0 == tcloud_drive_storage_statfs(&priv->st.st)) {
            priv->st.last_time = now;
        }
    }

    fuse_reply_statfs(req, &st);
}
static void tcloudfs_fallocate(fuse_req_t req, fuse_ino_t ino, int mode, off_t offset,
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
    .releasedir = tcloudfs_releasedir,
    .mkdir = tcloudfs_mkdir,
    .create = tcloudfs_create,
    .open = tcloudfs_open,
    .write = tcloudfs_write,
    .release = tcloudfs_release,
    .flush = tcloudfs_flush,
    .read = tcloudfs_read,
    .lseek = tcloudfs_lseek,
    .statfs = tcloudfs_statfs,
    .fallocate = tcloudfs_fallocate,
};
int main(int argc, char **argv) {
    int ret = 0;

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *config;
    memset((void *)&_priv, 0, sizeof(_priv));
#if 0
    printf("%s(%d): ....args->argv:%p....argc:%d, allacate:%d....\n", __FUNCTION__, __LINE__, args.argv, args.argc, args.allocated);
    fuse_opt_add_arg(&args, "-s");
    printf("%s(%d): ....args->argv:%p....argc:%d, allacate:%d....\n", __FUNCTION__, __LINE__, args.argv, args.argc, args.allocated);
    printf("%s(%d): ............\n", __FUNCTION__, __LINE__);
    fuse_opt_add_arg(&args, "-o");
    printf("%s(%d): ....args->argv:%p....argc:%d, allacate:%d....\n", __FUNCTION__, __LINE__, args.argv, args.argc, args.allocated);
    printf("%s(%d): ............\n", __FUNCTION__, __LINE__);
    fuse_opt_add_arg(&args, "default_permissions");
    printf("%s(%d): ............\n", __FUNCTION__, __LINE__);
    fuse_opt_add_arg(&args, "-o");
    printf("%s(%d): ............\n", __FUNCTION__, __LINE__);
    fuse_opt_add_arg(&args, "max_read=4194304");
    printf("%s(%d): ............\n", __FUNCTION__, __LINE__);
#endif
    // return 0;
    pthread_mutex_init(&_priv.mutex, NULL);

    // init empty link
    HR_INIT_LIST_HEAD(&_priv.head);
    HR_INIT_LIST_HEAD(&_priv.delete_pending_queue);

    tcloud_drive_init();

    struct tcloudfs_node *root = allocate_node(-11 /*FUSE_ROOT_ID*/, "/", NULL);
    root->mode = S_IFDIR | TCLOUDFS_DEFAULT_MODE;

    tcloud_drive_getattr(root->cloud_id, 0 /*folder*/, &root->atime, &root->ctime);
    

    root->mtime = root->atime;
    hr_list_add_tail(&root->entry, &_priv.head);

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

    fuse_session_unmount(se);
gone_3:
    fuse_remove_signal_handlers(se);
gone_2:
    fuse_session_destroy(se);
gone_1:
    if (opts.mountpoint)
        free(opts.mountpoint);
    fuse_opt_free_args(&args);
    pthread_mutex_destroy(&_priv.mutex);
    return 0;
}