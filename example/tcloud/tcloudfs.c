
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <stdint.h>
#endif

#define FUSE_USE_VERSION FUSE_VERSION

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <fuse_lowlevel.h>
#include <fuse_kernel.h>

#include "tcloud_buffer.h"
#include "tcloud_drive.h"

#define TCLOUDFS_DEFAULT_MODE (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
// default root directory is -11
#define TCLOUDFS_DEFAULT_ROOT_ID -11

struct tcloudfs_node {
    ino_t ino;  // --> id
    uint32_t cloud_id;
    uint64_t refcount;

    off_t offset;
    size_t size;
    mode_t mode;
    struct tcloud_buffer *data;
    struct j2sobject *dir;
    struct tcloudfs_node *next, *prev;
};
struct tcloudfs_priv {
    pthread_mutex_t mutex;

    // uint32_t default_root_id;
    struct tcloudfs_node root;
};

static void tcloudfs_init(void *userdata, struct fuse_conn_info *conn) {
    struct tcloudfs_priv *priv = (struct lo_data *)userdata;
    printf("%s(%d): .........priv:%p\n", __FUNCTION__, __LINE__, priv);
}

static void tcloudfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    printf("%s(%d): .........priv:%p, parent ino:%" PRIu64 ", name:%s\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), parent, name);

    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (parent == 1) {
        node = &priv->root;
    } else {
        struct tcloudfs_node *next = priv->root.next;
        while (next != &priv->root) {
            if (next->ino == parent) {
                node = next;
                break;
            }
            next = next->next;
        }
    }

    if (!node || !node->dir) {
        printf("no ........node:%p, node dir:%p........\n", node, node->dir);
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
    // e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;

    struct j2scloud_folder_resp *object = (struct j2scloud_folder_resp *)node->dir;
    j2scloud_folder_t *t = NULL;

    for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
         t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
         t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
        if (0 == strcmp(name, t->name)) {
            printf("got :%s\n", name);
            e.attr.st_mode = S_IFDIR | 755;
            e.attr.st_ino = t->id;
            e.ino = (fuse_ino_t)t->id;

            struct tcloudfs_node *n = (struct tcloudfs_node *)calloc(1, sizeof(struct tcloudfs_node));
            n->ino = t->id;
            n->cloud_id = t->id;
            n->mode = S_IFDIR;
            // e.ino = (fuse_ino_t)n;

            n->next = &priv->root;
            n->prev = priv->root.prev;
            priv->root.prev->next = n;
            priv->root.prev = n;
            fuse_reply_entry(req, &e);
            return;
        }

        // timespec_from_date_string(&st.st_atim, t->lastOpTime);
        // timespec_from_date_string(&st.st_mtim, t->lastOpTime);
    }

    j2scloud_file_t *f = NULL;
    for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
         f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
         f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
        if (0 == strcmp(name, f->name)) {
            printf("got :%s\n", name);
            e.attr.st_mode = S_IFREG | 755;
            e.attr.st_ino = f->id;
            e.ino = (fuse_ino_t)f->id;

            struct tcloudfs_node *n = (struct tcloudfs_node *)calloc(1, sizeof(struct tcloudfs_node));
            n->ino = f->id;
            n->cloud_id = f->id;
            n->mode = S_IFREG;

            n->next = &priv->root;
            n->prev = priv->root.prev;
            priv->root.prev->next = n;
            priv->root.prev = n;
            fuse_reply_entry(req, &e);
            return;
        }
    }
#if 0
    e.ino = 2;
    e.attr_timeout = 1.0;
    e.entry_timeout = 1.0;
    e.attr.st_mode = S_IFDIR | 0755;
    e.attr.st_nlink = 2;
#endif
    fuse_reply_err(req, ENOSYS);
}

static void tcloudfs_getattr(fuse_req_t req, fuse_ino_t ino,
                             struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", fi:%p\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, fi);
    struct stat st;

    (void)fi;

    memset(&st, 0, sizeof(st));
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == 1) {
        node = &priv->root;
    }

    st.st_mode = S_IFDIR | 0755;
    fuse_reply_attr(req, &st, 1.0);
}

static void tcloudfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
                             int valid, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
}

static void tcloudfs_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
    if (ino == 1) {
        node = &priv->root;
    } else {
    printf("%s(%d): .....\n", __FUNCTION__, __LINE__);
        struct tcloudfs_node *next = priv->root.next;
        while (next != &priv->root) {
            if (next->ino == ino) {
                node = next;
                break;
            }
            next = next->next;
        }
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
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 ", size:%ld, offset:%ld, fi:%p\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino, size, offset, fi);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == 1) {
        node = &priv->root;
    } else {
        struct tcloudfs_node *next = priv->root.next;
        while (next != &priv->root) {
            if (next->ino == ino) {
                node = next;
                break;
            }
        }
    }

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node || !S_ISDIR(node->mode)) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }

    if (!node->data) {
        struct j2scloud_folder_resp *dir = NULL;
        node->data = (struct tcloud_buffer *)calloc(1, sizeof(struct tcloud_buffer));
        tcloud_buffer_alloc(node->data, size);

        struct stat st;
        st.st_mode = S_IFDIR;

        size_t entlen = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
        entlen = fuse_add_direntry(req, node->data->data + node->data->offset, (node->data->size - node->data->offset), ".",
                                   &st, node->data->offset + entlen);
        node->data->offset += entlen;
        entlen = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);
        entlen = fuse_add_direntry(req, node->data->data + node->data->offset, (node->data->size - node->data->offset), "..",
                                   &st, node->data->offset + entlen);
        node->data->offset += entlen;

        int ret = 0;
        if (!node->dir) {
            printf("%s(%d): dir using %d\n", __FUNCTION__, __LINE__, node->cloud_id);
            int ret = tcloud_drive_opendir(/*ino == 1 ? -11 : ino*/ node->cloud_id, &dir);

            node->dir = J2SOBJECT(dir);
            ret = tcloud_drive_readdir(/*ino == 1 ? -11 : ino*/ node->cloud_id, dir);
        }

        dir = node->dir;
        if (ret == 0) {
            st.st_mode = S_IFDIR;

            struct j2scloud_folder_resp *object = dir;
            j2scloud_folder_t *t = NULL;

            for (t = (j2scloud_folder_t *)J2SOBJECT(object->folderList)->next;
                 t != (j2scloud_folder_t *)J2SOBJECT(object->folderList);
                 t = (j2scloud_folder_t *)J2SOBJECT(t)->next) {
                st.st_mode = S_IFDIR;
                st.st_ino = t->id;

                // timespec_from_date_string(&st.st_atim, t->lastOpTime);
                // timespec_from_date_string(&st.st_mtim, t->lastOpTime);

                entlen = fuse_add_direntry(req, NULL, 0, t->name, NULL, 0);
                entlen = fuse_add_direntry(req, node->data->data + node->data->offset, (node->data->size - node->data->offset), t->name,
                                           &st, node->data->offset + entlen);
                node->data->offset += entlen;
            }

            j2scloud_file_t *f = NULL;
            for (f = (j2scloud_file_t *)J2SOBJECT(object->fileList)->next;
                 f != (j2scloud_file_t *)J2SOBJECT(object->fileList);
                 f = (j2scloud_file_t *)J2SOBJECT(f)->next) {
                st.st_mode = S_IFREG;
                st.st_size = (long)f->size;
                st.st_ino = f->id;
                // timespec_from_date_string(&stbuf->st_ctim, f->createDate);
                // timespec_from_date_string(&stbuf->st_atim, f->lastOpTime);
                // timespec_from_date_string(&stbuf->st_mtim, f->lastOpTime);
                entlen = fuse_add_direntry(req, NULL, 0, f->name, NULL, 0);
                entlen = fuse_add_direntry(req, node->data->data + node->data->offset, (node->data->size - node->data->offset), f->name,
                                           &st, node->data->offset + entlen);
                node->data->offset += entlen;
            }
        }
        node->offset = 0;
    }

    size_t total = node->data->offset;
    printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__, __LINE__, total, offset, size);
    if (offset >= total) {
        printf("%s(%d): end ..........\n", __FUNCTION__, __LINE__);
        fuse_reply_buf(req, NULL, 0);
        return;
    }

    if (size > total - offset) {
        size = total - offset;
    }
    printf("%s(%d): total:%ld, offset:%ld, size:%ld..........\n", __FUNCTION__, __LINE__, total, offset, size);
    fuse_reply_buf(req, node->data->data + offset, size);
    node->offset = offset + size;
    printf("%s(%d): now offset:%ld, buffer %ld vs %ld..........\n", __FUNCTION__, __LINE__, node->offset, node->data->offset, node->data->size);
}
static void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    struct tcloudfs_priv *priv = fuse_req_userdata(req);
    struct tcloudfs_node *node = NULL;
    if (ino == 1) {
        node = &priv->root;
    }

    printf("node :%p  vs fi->fh:%p\n", node, (void *)fi->fh);
    if (!node) {
        fuse_reply_err(req, EOPNOTSUPP);
        return;
    }
#if 0
    if (node->dir) {
        j2sobject_free(node->dir);
        node->dir = NULL;
    }
#endif
    if (node->data) {
        tcloud_buffer_free(node->data);
        node->data = NULL;
    }

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
    printf("%s(%d): ........\n", __FUNCTION__, __LINE__);
}

static void lo_create(fuse_req_t req, fuse_ino_t parent, const char *name,
                      mode_t mode, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, parent:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), parent);
    fuse_reply_err(req, 0);
}
static void lo_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
}
static void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    (void)ino;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    fuse_reply_err(req, 0);
}
static void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size,
                    off_t offset, struct fuse_file_info *fi) {
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
}
static void lo_lseek(fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
                     struct fuse_file_info *fi) {
    off_t res = 0;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    (void)ino;
    fuse_reply_lseek(req, res);
    // fuse_reply_err(req, errno);
}

static void lo_statfs(fuse_req_t req, fuse_ino_t ino) {
    struct statvfs stbuf;
    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    fuse_reply_statfs(req, &stbuf);
}
static void lo_fallocate(fuse_req_t req, fuse_ino_t ino, int mode,
                         off_t offset, off_t length, struct fuse_file_info *fi) {
    int err = EOPNOTSUPP;
    (void)ino;

    printf("%s(%d): .........priv:%p, ino:%" PRIu64 "\n", __FUNCTION__, __LINE__, fuse_req_userdata(req), ino);
    fuse_reply_err(req, err);
}

static const struct fuse_lowlevel_ops tcloudfs_ops = {
    .init = tcloudfs_init,
    .lookup = tcloudfs_lookup,
    .getattr = tcloudfs_getattr,
    .setattr = tcloudfs_setattr,
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
    priv.root.next = priv.root.prev = &priv.root;
    priv.root.mode = S_IFDIR;
    priv.root.ino = 1;
    priv.root.cloud_id = -11;

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