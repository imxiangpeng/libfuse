#ifndef TCLOUD_DIRVE_H
#define TCLOUD_DIRVE_H

#include <stddef.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "j2sobject_cloud.h"

#define TCLOUD_DRIVE_RESERVE_ID -0xEF00000000000001

struct tcloud_drive_fd {
    int64_t id;  // cloud id
    int64_t parent;

    size_t size;  // total file size
    // size_t truncate_size;  // total file size
    // upload ...
    int is_eof;  // stream is end ?
    int /*enum tcloud_drive_fd_type*/ type;
};

int tcloud_drive_init(void);
int tcloud_drive_destroy(void);

int tcloud_drive_storage_statfs(struct statvfs *st);

int tcloud_drive_getattr(int64_t id, int type, struct timespec *atime, struct timespec *ctime);
int64_t tcloud_drive_mkdir(int64_t parent, const char* name);
int tcloud_drive_rmdir(int64_t id, const char* name);
int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp * dir);
struct tcloud_drive_fd *tcloud_drive_open(int64_t id);
int tcloud_drive_release(struct tcloud_drive_fd *fd);
size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset);
int tcloud_drive_write(struct tcloud_drive_fd *self, const char *data, size_t size, off_t offset);


struct tcloud_drive_fd *tcloud_drive_create(const char *name, int64_t parent);
int tcloud_drive_truncate(struct tcloud_drive_fd *self, size_t size);
int tcloud_drive_unlink(int64_t id, const char* name);
int tcloud_drive_rename(int64_t id, const char *name, unsigned int flags);
int tcloud_drive_move(int64_t id, const char *name, int64_t dst_parent, unsigned int flags);
#endif
