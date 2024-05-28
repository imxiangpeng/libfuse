#ifndef TCLOUD_DIRVE_H
#define TCLOUD_DIRVE_H

#include <stddef.h>

#include "j2sobject_cloud.h"

struct tcloud_drive_fd;

int tcloud_drive_init(void);
int tcloud_drive_destroy(void);

int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp * dir);
struct tcloud_drive_fd *tcloud_drive_open(int64_t id);
int tcloud_drive_release(struct tcloud_drive_fd *fd);
size_t tcloud_drive_read(struct tcloud_drive_fd *fd, char *rbuf, size_t size, off_t offset);
#endif
