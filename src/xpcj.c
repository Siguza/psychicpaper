/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "xpcj.h"

typedef struct
{
    int lvl;
    FILE *stream;
} xpcj_ctx_t;

static void xpcj_print_internal(xpcj_ctx_t *ctx, xpc_object_t obj)
{
    xpc_type_t type = xpc_get_type(obj);
    if(type == XPC_TYPE_BOOL)
    {
        fprintf(ctx->stream, "%s", xpc_bool_get_value(obj) ? "true" : "false");
        return;
    }
    else if(type == XPC_TYPE_DOUBLE)
    {
        fprintf(ctx->stream, "%lf", xpc_double_get_value(obj));
        return;
    }
    else if(type == XPC_TYPE_INT64)
    {
        fprintf(ctx->stream, "0x%llx", xpc_int64_get_value(obj));
        return;
    }
    else if(type == XPC_TYPE_UINT64)
    {
        fprintf(ctx->stream, "0x%llx", xpc_uint64_get_value(obj));
        return;
    }
    else if(type == XPC_TYPE_STRING)
    {
        fprintf(ctx->stream, "\"%s\"", xpc_string_get_string_ptr(obj));
        return;
    }
    else if(type == XPC_TYPE_DATA)
    {
        size_t size = xpc_data_get_length(obj);
        if(size > 0)
        {
            int pad = (ctx->lvl + 1) * 4;
            fprintf(ctx->stream, "<\n%*s", pad, "");
            const uint8_t *data = xpc_data_get_bytes_ptr(obj);
            char cs[17] = {};
            int i;
            for(i = 0; i < size; i++)
            {
                if(i != 0 && i % 0x10 == 0)
                {
                    fprintf(ctx->stream, " |%s|\n%*s", cs, pad, "");
                    memset(cs, 0, 17);
                }
                else if(i != 0 && i % 0x8 == 0)
                {
                    fprintf(ctx->stream, " ");
                }
                fprintf(ctx->stream, "%02x ", data[i]);
                cs[(i % 0x10)] = (data[i] >= 0x20 && data[i] <= 0x7e) ? data[i] : '.';
            }
            i = i % 0x10;
            if(i != 0)
            {
                if(i <= 0x8)
                {
                    fprintf(ctx->stream, " ");
                }
                while(i++ < 0x10)
                {
                    fprintf(ctx->stream, "   ");
                }
            }
            fprintf(ctx->stream, " |%s|\n%*s>", cs, pad - 4, "");
        }
        return;
    }
    else if(type == XPC_TYPE_DICTIONARY)
    {
        fprintf(ctx->stream, "{\n");
        xpc_dictionary_apply(obj, ^bool(const char *key, xpc_object_t val)
        {
            xpcj_ctx_t newctx =
            {
                .lvl = ctx->lvl + 1,
                .stream = ctx->stream,
            };
            fprintf(newctx.stream, "%*s%s: ", newctx.lvl * 4, "", key);
            xpcj_print_internal(&newctx, val);
            fprintf(newctx.stream, ",\n");
            return true;
        });
        fprintf(ctx->stream, "%*s}", ctx->lvl * 4, "");
        return;
    }
    else if(type == XPC_TYPE_ARRAY)
    {
        fprintf(ctx->stream, "[\n");
        xpc_array_apply(obj, ^bool(size_t idx, xpc_object_t val)
        {
            xpcj_ctx_t newctx =
            {
                .lvl = ctx->lvl + 1,
                .stream = ctx->stream,
            };
            fprintf(newctx.stream, "%*s", newctx.lvl * 4, "");
            xpcj_print_internal(&newctx, val);
            fprintf(newctx.stream, ",\n");
            return true;
        });
        fprintf(ctx->stream, "%*s]", ctx->lvl * 4, "");
        return;
    }
    else
    {
        fprintf(ctx->stream, "<!-- ??? -->");
        return;
    }
    fprintf(ctx->stream, "<!-- error -->");
}

void xpcj_print(FILE *stream, xpc_object_t obj)
{
    xpcj_ctx_t ctx =
    {
        .lvl = 0,
        .stream = stream,
    };
    xpcj_print_internal(&ctx, obj);
    fprintf(stream, "\n");
}
