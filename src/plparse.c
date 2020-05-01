/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

#include <errno.h>
#include <fcntl.h>              // open
#include <stdbool.h>
#include <stdio.h>              // stdin, stdout, stderr, fprintf, printf, fseek, ftell
#include <string.h>             // strerror, strcmp
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstat
#include <CoreFoundation/CoreFoundation.h>

#include "cfj.h"
#include "iokit.h"
#include "xpcj.h"

#define WRN(str, args...) do { fprintf(stderr, "\x1b[1;93m" str "\x1b[0m\n", ##args); } while(0)

static CFTypeRef cf_get(CFTypeRef obj, int argc, const char **argv)
{
    for(size_t i = 0; obj && i < argc; ++i)
    {
        CFTypeID type = CFGetTypeID(obj);
        if(type == CFDictionaryGetTypeID())
        {
            CFStringRef key = CFStringCreateWithCStringNoCopy(NULL, argv[i], kCFStringEncodingUTF8, kCFAllocatorNull);
            if(!key)
            {
                obj = NULL;
            }
            else
            {
                obj = CFDictionaryGetValue(obj, key);
                CFRelease(key);
            }
        }
        else if(type == CFArrayGetTypeID())
        {
            char *end = NULL;
            unsigned long long idx = strtoull(argv[i], &end, 0);
            if(argv[i][0] == '\0' || end[0] != '\0')
            {
                obj = NULL;
            }
            else
            {
                obj = CFArrayGetValueAtIndex(obj, idx);
            }
        }
        else
        {
            obj = NULL;
        }
    }
    return obj;
}

static xpc_object_t xpc_get(xpc_object_t obj, int argc, const char **argv)
{
    for(size_t i = 0; obj && i < argc; ++i)
    {
        xpc_type_t type = xpc_get_type(obj);
        if(type == XPC_TYPE_DICTIONARY)
        {
            obj = xpc_dictionary_get_value(obj, argv[i]);
        }
        else if(type == XPC_TYPE_ARRAY)
        {
            char *end = NULL;
            unsigned long long idx = strtoull(argv[i], &end, 0);
            if(argv[i][0] == '\0' || end[0] != '\0')
            {
                obj = NULL;
            }
            else
            {
                obj = xpc_array_get_value(obj, idx);
            }
        }
        else
        {
            obj = NULL;
        }
    }
    return obj;
}

int main(int argc, const char **argv)
{
    bool cf  = false,
         io  = false,
         xpc = false;
    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-') break;
        if(strcmp(argv[aoff], "--") == 0)
        {
            ++aoff;
            break;
        }
        for(size_t i = 1; argv[aoff][i] != '\0'; ++i)
        {
            switch(argv[aoff][i])
            {
                case 'c': cf  = true; break;
                case 'i': io  = true; break;
                case 'x': xpc = true; break;
                default:
                    WRN("Bad flag: -%c", argv[aoff][i]);
                    break;
            }
        }
    }
    if(argc - aoff < 1)
    {
        WRN("Usage: %s -[cix] file [selector...]", argv[0]);
        return -1;
    }

    int retval = -1,
        r = 0,
        fd = -1;
    size_t len = 0;
    void *addr = NULL;

    const char *ifile = argv[aoff++];
    if(strcmp(ifile, "-") == 0)
    {
        if(fseek(stdin, 0, SEEK_END) != 0)
        {
            WRN("fseek(end): %s", strerror(errno));
            goto out;
        }
        len = ftell(stdin);
        if(fseek(stdin, 0, SEEK_SET) != 0)
        {
            WRN("fseek(set): %s", strerror(errno));
            goto out;
        }
        addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if(addr == MAP_FAILED)
        {
            WRN("mmap: %s", strerror(errno));
            goto out;
        }
        fread(addr, 1, len, stdin);
    }
    else
    {
        struct stat s = {};
        fd = open(ifile, O_RDONLY);
        if(fd < 0)
        {
            WRN("open: %s", strerror(errno));
            goto out;
        }
        r = fstat(fd, &s);
        if(r != 0)
        {
            WRN("fstat: %s", strerror(errno));
            goto out;
        }
        len = s.st_size;
        addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
        if(addr == MAP_FAILED)
        {
            WRN("mmap: %s", strerror(errno));
            goto out;
        }
    }
    if(cf)
    {
        CFPropertyListRef cfplist = NULL;
        CFDataRef cfdata = CFDataCreateWithBytesNoCopy(NULL, addr, len, kCFAllocatorNull);
        if(cfdata)
        {
            cfplist = CFPropertyListCreateWithData(NULL, cfdata, 0, NULL, NULL);
            CFRelease(cfdata);
        }
        if(cfplist)
        {
            CFTypeRef obj = cf_get(cfplist, argc - aoff, &argv[aoff]);
            if(obj)
            {
                cfj_print(stdout, obj);
            }
            else
            {
                WRN("CF: bad key");
            }
            CFRelease(cfplist);
        }
        else
        {
            WRN("CF says nooo");
        }
    }
    if(io)
    {
        CFTypeRef ioplist = IOCFUnserializeWithSize(addr, len, NULL, 0, NULL);
        if(ioplist)
        {
            CFTypeRef obj = cf_get(ioplist, argc - aoff, &argv[aoff]);
            if(obj)
            {
                cfj_print(stdout, obj);
            }
            else
            {
                WRN("IOKit: bad key");
            }
            CFRelease(ioplist);
        }
        else
        {
            WRN("IOKit says nooo");
        }
    }
    if(xpc)
    {
        xpc_object_t xobj = xpc_create_from_plist(addr, len);
        if(xobj)
        {
            xpc_object_t obj = xpc_get(xobj, argc - aoff, &argv[aoff]);
            if(obj)
            {
                xpcj_print(stdout, obj);
            }
            else
            {
                WRN("XPC: bad key");
            }
            xpc_release(xobj);
        }
        else
        {
            WRN("XPC says nooo");
        }
    }

    retval = 0;
out:;
    if(addr) munmap(addr, len);
    if(fd >= 0) close(fd);
    return retval;
}
