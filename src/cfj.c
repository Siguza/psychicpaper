/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

#include "cfj.h"

// The output differs from actual JSON in that:
// - Dict keys aren't string literals, but just plain text
// - Nothing is escaped inside string literals
// - The CFData format is entirely custom, since JSON
//   has no real concept of raw binary data.
// Due to the last point however, JSON conformance is not
// a goal at the moment, but rather just human-readability.

typedef struct
{
    int lvl;
    FILE *stream;
} cfj_ctx_t;

static void cfj_dict_cb(const void *key, const void *val, void *context);
static void cfj_arr_cb(const void *val, void *context);
static void cfj_print_str_raw(cfj_ctx_t *ctx, const CFStringRef str);
static void cfj_print_internal(cfj_ctx_t *ctx, CFTypeRef obj);

static void cfj_dict_cb(const void *key, const void *val, void *context)
{
    cfj_ctx_t *ctx = context;
    cfj_ctx_t newctx =
    {
        .lvl = ctx->lvl + 1,
        .stream = ctx->stream,
    };
    fprintf(newctx.stream, "%*s", newctx.lvl * 4, "");
    cfj_print_str_raw(&newctx, key);
    fprintf(newctx.stream, ": ");
    cfj_print_internal(&newctx, val);
    fprintf(newctx.stream, ",\n");
}

static void cfj_arr_cb(const void *val, void *context)
{
    cfj_ctx_t *ctx = context;
    cfj_ctx_t newctx =
    {
        .lvl = ctx->lvl + 1,
        .stream = ctx->stream,
    };
    fprintf(newctx.stream, "%*s", newctx.lvl * 4, "");
    cfj_print_internal(&newctx, val);
    fprintf(newctx.stream, ",\n");
}

static void cfj_print_str_raw(cfj_ctx_t *ctx, const CFStringRef str)
{
    char buf[0x100];
    for(CFIndex i = 0, len = CFStringGetLength(str); i < len; )
    {
        CFIndex max = len - i,
                out = 0;
        CFRange range = CFRangeMake(i, max);
        max = CFStringGetBytes(str, range, kCFStringEncodingUTF8, 0, false, (UInt8*)buf, sizeof(buf), &out);
        fwrite(buf, 1, out, ctx->stream);
        i += max;
    }
}

static void cfj_print_internal(cfj_ctx_t *ctx, CFTypeRef obj)
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
                fprintf(ctx->stream, "0x%llx", val);
                return;
            }
        }
    }
    else if(type == CFStringGetTypeID())
    {
        fprintf(ctx->stream, "\"");
        cfj_print_str_raw(ctx, obj);
        fprintf(ctx->stream, "\"");
        return;
    }
    else if(type == CFDataGetTypeID())
    {
        CFIndex size = CFDataGetLength(obj);
        if(size > 0)
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
        fprintf(ctx->stream, "{\n");
        CFDictionaryApplyFunction(obj, &cfj_dict_cb, ctx);
        fprintf(ctx->stream, "%*s}", ctx->lvl * 4, "");
        return;
    }
    else if(type == CFArrayGetTypeID())
    {
        fprintf(ctx->stream, "[\n");
        CFArrayApplyFunction(obj, CFRangeMake(0, CFArrayGetCount(obj)), &cfj_arr_cb, ctx);
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

void cfj_print(FILE *stream, CFTypeRef obj)
{
    cfj_ctx_t ctx =
    {
        .lvl = 0,
        .stream = stream,
    };
    cfj_print_internal(&ctx, obj);
    fprintf(stream, "\n");
}
