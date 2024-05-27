#ifndef TCLOUD_DIRVE_H
#define TCLOUD_DIRVE_H

#include <stddef.h>

#include "j2sobject_cloud.h"


int tcloud_drive_init(void);
int tcloud_drive_destroy(void);

int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp * dir);
int tcloud_drive_open(int64_t id, char **path);
size_t tcloud_drive_read(int64_t id, char **real_url, char *rbuf, size_t size, off_t offset);
#endif
