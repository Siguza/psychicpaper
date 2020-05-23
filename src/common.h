/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct
{
    bool true_json;
    bool first;
    int lvl;
    FILE *stream;
} common_ctx_t;

void common_print_bytes(common_ctx_t *ctx, const uint8_t *buf, size_t size);
void common_print_char(common_ctx_t *ctx, char c);

#endif
