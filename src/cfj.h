/* Copyright (c) 2019-2021 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#ifndef CFJ_H
#define CFJ_H

#include <stdbool.h>
#include <stdio.h>
#include <CoreFoundation/CoreFoundation.h>

void cfj_print(FILE *stream, CFTypeRef obj, bool true_json, bool bytes_raw);

#endif
