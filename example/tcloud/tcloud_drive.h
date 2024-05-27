#ifndef TCLOUD_DIRVE_H
#define TCLOUD_DIRVE_H

#include <stddef.h>

#include "j2sobject_cloud.h"


int tcloud_drive_init(void);
int tcloud_drive_destroy(void);

int tcloud_drive_readdir(int64_t id, struct j2scloud_folder_resp * dir);
#endif
