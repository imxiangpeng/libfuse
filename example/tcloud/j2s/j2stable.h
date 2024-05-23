/*
 * Copyright (C) 2024 Inspur Group Co., Ltd. Unpublished
 *
 * Inspur Group Co., Ltd.
 * Proprietary & Confidential
 *
 * This source code and the algorithms implemented therein constitute
 * confidential information and may comprise trade secrets of Inspur
 * or its associates, and any use thereof is subject to the terms and
 * conditions of the Non-Disclosure Agreement pursuant to which this
 * source code was originally received.
 */


// mxp, a very simple json table manipulated using j2sobject

#ifndef _J2STABLE_H_
#define _J2STABLE_H_

#include "j2sobject.h"

#define J2STBL_DECLARE_OBJECT struct j2stbl_object __object__
#define J2STBL_OBJECT_SELF(self) ((struct j2stbl_object *)self)

#define J2STBL_OBJECT_PRIV_FIELDS \
    {.name = "__id__", .type = J2S_INT, .offset = offsetof(struct j2stbl_object, __id__), .offset_len = 0}

enum {
  J2STBL_OPBIT_INSERT = 0x1,
  J2STBL_OPBIT_UPDATE = 0x2,
  J2STBL_OPBIT_DELETE = 0x4
};
struct j2stbl_object {
  J2SOBJECT_DECLARE_OBJECT;
   // auto increase id, readonly, do not modify it!
  int __id__;
};
struct j2stable {
  char *path;

  int state;

  struct j2sobject* priv;
  struct j2stbl_trigger *trigger;
};

struct j2stbl_trigger {
  void (*on_load)(struct j2stbl_object *head);
  void (*on_unload)(struct j2stbl_object *head);
  void (*on_insert)(struct j2stbl_object *item);
  void (*on_update)(struct j2stbl_object *item);
  void (*on_delete)(struct j2stbl_object *item);
};

struct j2stable *j2stable_init(const char *table, struct j2sobject_prototype *proto);
struct j2stable *j2stable_init_trigger(const char *table, struct j2sobject_prototype *proto, struct j2stbl_trigger* trigger);
void j2stable_deinit(struct j2stable *tbl);

int j2stable_version(struct j2stable *tbl);
int j2stable_empty(struct j2stable *tbl);

struct j2stbl_object* j2stable_query_all(struct j2stable *tbl);
int j2stable_update(struct j2stable *tbl, struct j2stbl_object *self);
int j2stable_delete(struct j2stable *tbl, struct j2stbl_object *self);
// object.__id__ will auto increase ++
int j2stable_insert(struct j2stable *tbl, struct j2stbl_object *self);
#endif // _J2STABLE_H_
