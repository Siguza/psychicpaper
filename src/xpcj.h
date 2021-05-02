/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef XPCJ_H
#define XPCJ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef const struct _xpc_type_s * xpc_type_t;
typedef void *xpc_object_t;
typedef bool (^xpc_dictionary_applier_t)(const char *key, xpc_object_t value);
typedef bool (^xpc_array_applier_t)(size_t index, xpc_object_t value);

#define XPC_TYPE(type) const struct _xpc_type_s type
#define XPC_TYPE_BOOL (&_xpc_type_bool)
extern XPC_TYPE(_xpc_type_bool);
#define XPC_TYPE_DOUBLE (&_xpc_type_double)
extern XPC_TYPE(_xpc_type_double);
#define XPC_TYPE_INT64 (&_xpc_type_int64)
extern XPC_TYPE(_xpc_type_int64);
#define XPC_TYPE_UINT64 (&_xpc_type_uint64)
extern XPC_TYPE(_xpc_type_uint64);
#define XPC_TYPE_DATA (&_xpc_type_data)
extern XPC_TYPE(_xpc_type_data);
#define XPC_TYPE_STRING (&_xpc_type_string)
extern XPC_TYPE(_xpc_type_string);
#define XPC_TYPE_DICTIONARY (&_xpc_type_dictionary)
extern XPC_TYPE(_xpc_type_dictionary);
#define XPC_TYPE_ARRAY (&_xpc_type_array)
extern XPC_TYPE(_xpc_type_array);

extern xpc_type_t xpc_get_type(xpc_object_t object);
extern bool xpc_bool_get_value(xpc_object_t xbool);
extern double xpc_double_get_value(xpc_object_t xdouble);
extern int64_t xpc_int64_get_value(xpc_object_t xint);
extern uint64_t xpc_uint64_get_value(xpc_object_t xuint);
extern size_t xpc_data_get_length(xpc_object_t xdata);
extern const void * xpc_data_get_bytes_ptr(xpc_object_t xdata);
extern const char * xpc_string_get_string_ptr(xpc_object_t xstring);
extern xpc_object_t xpc_dictionary_get_value(xpc_object_t xdict, const char *key);
extern bool xpc_dictionary_apply(xpc_object_t xdict, xpc_dictionary_applier_t applier);
extern xpc_object_t xpc_array_get_value(xpc_object_t xarray, size_t index);
extern bool xpc_array_apply(xpc_object_t xarray, xpc_array_applier_t applier);
extern void xpc_release(xpc_object_t object);
extern xpc_object_t xpc_create_from_plist(const void *buf, size_t len);

void xpcj_print(FILE *stream, xpc_object_t obj, bool true_json, bool bytes_raw);

#endif
