/* Copyright (c) 2019-2021 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdbool.h>
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

#include "common.h"
#include "cfj.h"

static void cfj_dict_cb(const void *key, const void *val, void *context);
static void cfj_arr_cb(const void *val, void *context);
static void cfj_print_str(common_ctx_t *ctx, const CFStringRef str);
static void cfj_print_internal(common_ctx_t *ctx, CFTypeRef obj);

static void cfj_dict_cb(const void *key, const void *val, void *context)
{
    common_ctx_t *ctx = context;
    if(ctx->first)
    {
        fprintf(ctx->stream, "\n");
        ctx->first = false;
    }
    else
    {
        fprintf(ctx->stream, ",\n");
    }
    fprintf(ctx->stream, "%*s", ctx->lvl * 4, "");
    cfj_print_str(ctx, key);
    fprintf(ctx->stream, ": ");
    cfj_print_internal(ctx, val);
}

static void cfj_arr_cb(const void *val, void *context)
{
    common_ctx_t *ctx = context;
    if(ctx->first)
    {
        fprintf(ctx->stream, "\n");
        ctx->first = false;
    }
    else
    {
        fprintf(ctx->stream, ",\n");
    }
    fprintf(ctx->stream, "%*s", ctx->lvl * 4, "");
    cfj_print_internal(ctx, val);
}

static void cfj_print_str(common_ctx_t *ctx, const CFStringRef str)
{
    fprintf(ctx->stream, "\"");
    char buf[0x100];
    for(CFIndex i = 0, len = CFStringGetLength(str); i < len; )
    {
        CFIndex max = len - i,
                out = 0;
        CFRange range = CFRangeMake(i, max);
        max = CFStringGetBytes(str, range, kCFStringEncodingUTF8, 0, false, (UInt8*)buf, sizeof(buf), &out);
        if(ctx->true_json)
        {
            for(size_t j = 0; j < out; ++j)
            {
                common_print_char(ctx, buf[j]);
            }
        }
        else
        {
            fwrite(buf, 1, out, ctx->stream);
        }
        i += max;
    }
    fprintf(ctx->stream, "\"");
}

static void cfj_print_internal(common_ctx_t *ctx, CFTypeRef obj)
{
    CFTypeID type = CFGetTypeID(obj);
    if(type == CFBooleanGetTypeID())
    {
        fprintf(ctx->stream, "%s", CFBooleanGetValue(obj) ? "true" : "false");
        return;
    }
    else if(type == CFNumberGetTypeID())
    {
        if(CFNumberIsFloatType(obj))
        {
            double val = 0;
            if(CFNumberGetValue(obj, kCFNumberDoubleType, &val))
            {
                fprintf(ctx->stream, "%lf", val);
                return;
            }
        }
        else
        {
            unsigned long long val = 0;
            if(CFNumberGetValue(obj, kCFNumberLongLongType, &val))
            {
                fprintf(ctx->stream, ctx->true_json ? "%llu" : "0x%llx", val);
                return;
            }
        }
    }
    else if(type == CFStringGetTypeID())
    {
        cfj_print_str(ctx, obj);
        return;
    }
    else if(type == CFDataGetTypeID())
    {
        CFIndex size = CFDataGetLength(obj);
        if(ctx->true_json)
        {
            common_print_bytes(ctx, CFDataGetBytePtr(obj), size);
        }
        else if(size > 0)
        {
            int pad = (ctx->lvl + 1) * 4;
            fprintf(ctx->stream, "<\n%*s", pad, "");
            const UInt8 *data = CFDataGetBytePtr(obj);
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
    else if(type == CFDictionaryGetTypeID())
    {
        common_ctx_t newctx =
        {
            .true_json = ctx->true_json,
            .bytes_raw = ctx->bytes_raw,
            .first = true,
            .lvl = ctx->lvl + 1,
            .stream = ctx->stream,
        };
        fprintf(ctx->stream, "{");
        CFDictionaryApplyFunction(obj, &cfj_dict_cb, &newctx);
        if(!newctx.first)
        {
            fprintf(ctx->stream, "\n%*s", ctx->lvl * 4, "");
        }
        fprintf(ctx->stream, "}");
        return;
    }
    else if(type == CFArrayGetTypeID())
    {
        common_ctx_t newctx =
        {
            .true_json = ctx->true_json,
            .bytes_raw = ctx->bytes_raw,
            .first = true,
            .lvl = ctx->lvl + 1,
            .stream = ctx->stream,
        };
        fprintf(ctx->stream, "[");
        CFArrayApplyFunction(obj, CFRangeMake(0, CFArrayGetCount(obj)), &cfj_arr_cb, &newctx);
        if(!newctx.first)
        {
            fprintf(ctx->stream, "\n%*s", ctx->lvl * 4, "");
        }
        fprintf(ctx->stream, "]");
        return;
    }
    else
    {
        fprintf(ctx->stream, "<!-- ??? -->");
        return;
    }
    fprintf(ctx->stream, "<!-- error -->");
}

void cfj_print(FILE *stream, CFTypeRef obj, bool true_json, bool bytes_raw)
{
    common_ctx_t ctx =
    {
        .true_json = true_json,
        .bytes_raw = bytes_raw,
        .first = false,
        .lvl = 0,
        .stream = stream,
    };
    cfj_print_internal(&ctx, obj);
    fprintf(stream, "\n");
}
