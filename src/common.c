/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common.h"

void common_print_bytes(common_ctx_t *ctx, const uint8_t *buf, size_t size)
{
    fprintf(ctx->stream, "\"");
    for(size_t i = 0; i < size; ++i)
    {
        common_print_char(ctx, (char)buf[i]);
    }
    fprintf(ctx->stream, "\"");
}

void common_print_char(common_ctx_t *ctx, char c)
{
    // This catches both <0x20 and >=0x80
    if(c < 0x20)
    {
        fprintf(ctx->stream, "\\u%04hx", (unsigned char)c);
        return;
    }
    switch(c)
    {
        case '\n':
            fputs("\\n", ctx->stream);
            return;
        case '\r':
            fputs("\\r", ctx->stream);
            return;
        case '\t':
            fputs("\\t", ctx->stream);
            return;
        case '\f':
            fputs("\\f", ctx->stream);
            return;
        case '\b':
            fputs("\\b", ctx->stream);
            return;
        case '\\':
        case '"':
            fputc('\\', ctx->stream);
            break;
    }
    fputc(c, ctx->stream);
}
