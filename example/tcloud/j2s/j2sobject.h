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

#ifndef _J2SOBJECT_H_
#define _J2SOBJECT_H_

#include <stdint.h>

#define USING_JSONC
#define J2SOBJECT_DECLARE_OBJECT struct j2sobject __object__
#define J2SOBJECT(self) ((struct j2sobject *)self)
#define J2SOBJECT_PROTOTYPE(self) J2SOBJECT(self)->prototype

#ifdef USING_JSONC
struct json_object;
#else
struct cJSON;
#endif

struct j2sobject;

enum j2stype {
    J2S_UNKNOWN = 0,
    J2S_INT = 1 << 1,
    J2S_DOUBLE = 1 << 2,
    J2S_LONG = 1 << 3,
    J2S_STRING = 1 << 4,
    J2S_OBJECT = 1 << 5,
    J2S_ARRAY = 1 << 6,
};

struct j2sobject_prototype {
    const char *name;
    enum j2stype type; // object type
    int size;
    // only used when it's object not normal basic type such int/string/...
    // so we can create new dynamic object
    int (*ctor)(struct j2sobject *);
    // when offset_len > 0 it means that it's not pointer, data have been allocated
    // you should directly setup proto and other fields
    // care that do not modify any other none j2cobject fields which maybe causing loss data
    //int (*init)(struct j2sobject *);
    int (*dtor)(struct j2sobject *);
};

struct j2sobject_fields_prototype {
    const char *name;
    int type; // object type
    uint32_t offset;
    uint32_t offset_len;

    // should not null when cur field is object
    struct j2sobject_prototype *proto;
};

struct j2sobject {
    int type;
    const char *name;

    struct j2sobject_prototype *proto;
    const struct j2sobject_fields_prototype *field_protos;  // point to object prototype table(arrary)

    // support array object
    struct j2sobject *prev, *next;
};

struct j2sobject *j2sobject_create(struct j2sobject_prototype *proto);
struct j2sobject *j2sobject_create_array(struct j2sobject_prototype *proto);
void j2sobject_free(struct j2sobject *self);

// clear all payload data memory
int j2sobject_reset(struct j2sobject *self);

int j2sobject_deserialize(struct j2sobject *self, const char *jstr);
int j2sobject_deserialize_json(struct j2sobject *self, void *jobj); // struct json_object * or struct cJSON *
int j2sobject_deserialize_file(struct j2sobject *self, const char *path);
int j2sobject_deserialize_target(struct j2sobject *self, const char *jstr, const char *target);
int j2sobject_deserialize_target_file(struct j2sobject *self, const char *path, const char *target);
// must be freed manually
const char *j2sobject_serialize(struct j2sobject *self);
int j2sobject_serialize_json(struct j2sobject *self, void *target); // struct json_object * or struct cJSON *
int j2sobject_serialize_file(struct j2sobject *self, const char *path);

#endif  //_J2SOBJECT_H_
