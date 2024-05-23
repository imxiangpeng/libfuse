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

// mxp, a very simple json table based on j2sobject

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "j2stable.h"

#include <cjson/cJSON.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// default we directly store data as root object
// however someone may want to store extra metadata in table
// such as version which allow you do some compatibility task
// in this case, json root element is object not array
// real data is stored in "data" field of root object
#ifndef J2STBL_STORE_METADATA
#define J2STBL_STORE_METADATA 0
#endif

#ifndef J2STBL_BASE_DB_PATH
#define J2STBL_BASE_DB_PATH "./j2stbls"
#endif

#define J2STBL_DEFAULT_INDEX_ID (1)

#define J2STBL_PRIV_DATA_FIELD "data"

#define J2STBL_PRIV(o) ((struct j2stbl_priv *)o)

#if J2STBL_STORE_METADATA
struct j2stbl_priv {
    J2SOBJECT_DECLARE_OBJECT;
    int version;
    // some other metadata fields
    struct j2stbl_object *data;
};

static struct j2sobject_fields_prototype _j2stbl_priv_fields_prototype[] = {
    {.name = "version", .type = J2S_INT, .offset = offsetof(struct j2stbl_priv, version), .offset_len = 0},
    {.name = "data", .type = J2S_ARRAY, .offset = offsetof(struct j2stbl_priv, data), .offset_len = 0, .proto = NULL /*unknown now*/},
    {0}};

int j2stbl_priv_ctor(struct j2sobject *obj) {
    if (!obj)
        return -1;
    obj->name = "j2stbl";
    // data's proto should be auto adjust, so we using dynamic memory
    obj->field_protos = calloc(1, sizeof(_j2stbl_priv_fields_prototype));
    memcpy((void *)obj->field_protos, (void *)_j2stbl_priv_fields_prototype, sizeof(_j2stbl_priv_fields_prototype));
    return 0;
}

static int j2stbl_priv_dtor(struct j2sobject *obj) {
    if (!obj) return 0;

    if (obj->field_protos) {
        free((void *)obj->field_protos);
        obj->field_protos = NULL;
    }
    return 0;
}

static struct j2sobject_prototype _j2stbl_priv_prototype = {
    .name = "j2stbl",
    .type = J2S_OBJECT,
    .size = sizeof(struct j2stbl_priv),
    .ctor = j2stbl_priv_ctor,
    .dtor = j2stbl_priv_dtor};
#endif

static int _j2stable_init(struct j2stable *tbl) {
    int ret = 0;
    char *path = NULL;
    struct stat st;

    if (!tbl || !tbl->path)
        return -1;

    path = tbl->path;

    if (lstat(path, &st) == 0 && st.st_size == 0) {
        // not exist, directly return empty
        return 0;
    }

    ret = j2sobject_deserialize_file(J2SOBJECT(tbl->priv), tbl->path);
    if (0 != ret) {
    }

    return 0;
}

// db: database name
struct j2stable *j2stable_init(const char *name,
                               struct j2sobject_prototype *proto) {
    struct j2stable *tbl = NULL;
#if J2STBL_STORE_METADATA
    struct j2sobject_fields_prototype *pt = NULL;
#endif
    if (!name || !proto || !proto->ctor || 0 == proto->size) {
        return NULL;
    }

    tbl = (struct j2stable *)calloc(1, sizeof(struct j2stable));
    if (!tbl) {
        return NULL;
    }

#if J2STBL_STORE_METADATA
    tbl->priv = j2sobject_create(&_j2stbl_priv_prototype);
    if (!tbl->priv || !tbl->priv->field_protos) {
        free(tbl);
        return NULL;
    }

    // find data fields & update proto
    pt = (struct j2sobject_fields_prototype *)tbl->priv->field_protos;
    for (; pt && pt->name; pt++) {
        if (0 == strcmp(J2STBL_PRIV_DATA_FIELD, pt->name)) {
            pt->proto = proto;
            break;
        }
    }

    if (!pt->name) {
        // can not find data field!
        free(tbl);
        return NULL;
    }
#else
    // because proto must be j2stbl_object, so tbl->priv is also j2stbl_object(memory is equal)
    tbl->priv = j2sobject_create_array(proto);
    if (!tbl->priv) {
        free(tbl);
        return NULL;
    }
#endif

    if (asprintf(&tbl->path, "%s/%s.json", J2STBL_BASE_DB_PATH, name) < 0) {
        free(tbl);
        return NULL;
    }

    _j2stable_init(tbl);

#if J2STBL_STORE_METADATA
    if (!J2STBL_PRIV(tbl->priv)->data) {
        // must pre init data fields, because the table maybe empty or error
        J2STBL_PRIV(tbl->priv)->data = (struct j2stbl_object *)j2sobject_create_array(proto);
    }
#endif

    return tbl;
}

struct j2stable *j2stable_init_trigger(const char *table, struct j2sobject_prototype *proto, struct j2stbl_trigger *trigger) {
    struct j2stable *tbl = j2stable_init(table, proto);
    if (!tbl) {
        return NULL;
    }
    tbl->trigger = trigger;

    if (tbl->trigger && tbl->trigger->on_load) {
        tbl->trigger->on_load((struct j2stbl_object *)tbl->priv);
    }

    return tbl;
}
void j2stable_deinit(struct j2stable *tbl) {
    if (!tbl) return;

    if (tbl->trigger && tbl->trigger->on_unload) {
        tbl->trigger->on_unload((struct j2stbl_object *)tbl->priv);
    }

    j2sobject_free(tbl->priv);
    tbl->priv = NULL;

    if (tbl->path)
        free(tbl->path);

    memset((void *)tbl, 0, sizeof(struct j2stable));

    free(tbl);
}
int j2stable_version(struct j2stable *tbl) {
    (void)tbl;
#if J2STBL_STORE_METADATA
    if (!tbl || !tbl->priv) return -1;

    return J2STBL_PRIV(tbl->priv)->version;
#endif
    return -1;
}
int j2stable_empty(struct j2stable *tbl) {
    struct j2sobject *data = NULL;

    if (!tbl || !tbl->priv) return 0;

#if J2STBL_STORE_METADATA
    data = J2SOBJECT(J2STBL_PRIV(tbl->priv)->data);
#else
    data = tbl->priv;
#endif

    if (!data) return 0;
    // the object is array and next -> self
    if (data->next == data) return 1;

    return 0;
}

static int _j2stable_commit(struct j2stable *tbl) {
    if (!tbl)
        return -1;

    // do nothing when no changes
    if (tbl->state == 0) {
        return 0;
    }

    return j2sobject_serialize_file(tbl->priv, tbl->path);
}

struct j2stbl_object *j2stable_query_all(struct j2stable *tbl) {
    struct j2stbl_object *data = NULL;
    if (j2stable_empty(tbl)) {
        return NULL;
    }
#if J2STBL_STORE_METADATA
    data = J2STBL_PRIV(tbl->priv)->data;
#else
    data = (struct j2stbl_object *)tbl->priv;
#endif

    return data;
}
int j2stable_update(struct j2stable *tbl, struct j2stbl_object *self) {
    if (!tbl || !self)
        return -1;

    tbl->state |= J2STBL_OPBIT_UPDATE;
    _j2stable_commit(tbl);
    if (tbl->trigger && tbl->trigger->on_update) {
        tbl->trigger->on_update(self);
    }

    return 0;
}

int j2stable_delete(struct j2stable *tbl, struct j2stbl_object *self) {
    if (!tbl || !self)
        return -1;

    if (J2SOBJECT(self)->next == J2SOBJECT(self) || J2SOBJECT(self)->prev == J2SOBJECT(self)) {
        return -1;
    }

    if (tbl->trigger && tbl->trigger->on_delete) {
        tbl->trigger->on_delete(self);
    }
    // tick off from link
    J2SOBJECT(self)->prev->next = J2SOBJECT(self)->next;
    J2SOBJECT(self)->next->prev = J2SOBJECT(self)->prev;

    // reset link point
    J2SOBJECT(self)->next = J2SOBJECT(self);
    J2SOBJECT(self)->prev = J2SOBJECT(self);

    j2sobject_free(J2SOBJECT(self));

    tbl->state |= J2STBL_OPBIT_DELETE;
    _j2stable_commit(tbl);
    return 0;
}

// after insert you should not free it again, it will be auto free when posible
int j2stable_insert(struct j2stable *tbl, struct j2stbl_object *self) {
    struct j2sobject *data = NULL;
    if (!tbl || !self)
        return -1;

    // 1. target self is already on object list?
    // you should call update when it's exits!
    // or make sure current object is not on any link list
    if ((J2SOBJECT(self)->next != J2SOBJECT(self)) || (J2SOBJECT(self)->next != J2SOBJECT(self)->prev)) {
        printf("Insert: Error target maybe already exist!\n");
        return -1;
    }

    // 2. only access new self object
#if J2STBL_STORE_METADATA
    data = J2SOBJECT(J2STBL_PRIV(tbl->priv)->data);
#else
    data = tbl->priv;
#endif

    if (!data) return -1;

    data->prev->next = J2SOBJECT(self);
    J2SOBJECT(self)->prev = data->prev;
    J2SOBJECT(self)->next = data;
    data->prev = J2SOBJECT(self);

    // first element after head, care that head is struct j2sobject not j2stbl_object
    if (J2SOBJECT(self)->prev == data) {
        self->__id__ = J2STBL_DEFAULT_INDEX_ID;
    } else {
        self->__id__ = J2STBL_OBJECT_SELF(J2SOBJECT(self)->prev)->__id__ + 1;
    }

    tbl->state |= J2STBL_OPBIT_INSERT;

    // 3 schedule task to flush data to persist...
    _j2stable_commit(tbl);

    if (tbl->trigger && tbl->trigger->on_insert) {
        tbl->trigger->on_insert(self);
    }
    return 0;
}
