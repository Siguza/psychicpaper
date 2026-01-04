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
#include <stdlib.h>             // realloc, free
#include <string.h>             // strerror, strcmp
#include <unistd.h>             // close
#include <sys/mman.h>           // mmap, munmap
#include <sys/stat.h>           // fstat
#include <CoreFoundation/CoreFoundation.h>

#include "cfj.h"
#ifdef __APPLE__
#include "xpcj.h"
#endif

extern CFTypeRef IOCFUnserializeWithSize(const char *buffer, size_t bufferSize, CFAllocatorRef allocator, CFOptionFlags options, CFStringRef *errorString);

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

#ifdef __APPLE__
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
#endif

int main(int argc, const char **argv)
{
    bool io   = false,
#ifdef __APPLE__
         cf   = false,
         xpc  = false,
#endif
         json = false,
         raw  = false;
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
                case 'i': io   = true; break;
#ifdef __APPLE__
                case 'c': cf   = true; break;
                case 'x': xpc  = true; break;
#endif
                case 'j': json = true; break;
                case 'r': raw  = true; break;
                default:
                    WRN("Bad flag: -%c", argv[aoff][i]);
                    break;
            }
        }
    }
    if(argc - aoff < 1)
    {
#ifdef __APPLE__
        WRN("Usage: %s -[cix] [-j] [-r] file [selector...]", argv[0]);
#else
        WRN("Usage: %s -[i] [-j] [-r] file [selector...]", argv[0]);
#endif
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
        size_t sz = 0x8000;
        while(1)
        {
            sz *= 2;
            addr = realloc(addr, sz);
            if(!addr)
            {
                WRN("realloc: %s", strerror(errno));
                goto out;
            }
            size_t want = sz - len;
            size_t have = fread((char*)addr + len, 1, sz - len, stdin);
            len += have;
            if(have < want)
            {
                if(feof(stdin))
                {
                    break;
                }
                WRN("fread: %s", strerror(errno));
                goto out;
            }
        }
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
    retval = 0;
#ifdef __APPLE__
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
                cfj_print(stdout, obj, json, raw);
            }
            else
            {
                WRN("CF: bad key");
                retval = -1;
            }
            CFRelease(cfplist);
        }
        else
        {
            WRN("CF says nooo");
            retval = -1;
        }
    }
#endif
    if(io)
    {
        CFTypeRef ioplist = IOCFUnserializeWithSize(addr, len, NULL, 0, NULL);
        if(ioplist)
        {
            CFTypeRef obj = cf_get(ioplist, argc - aoff, &argv[aoff]);
            if(obj)
            {
                cfj_print(stdout, obj, json, raw);
            }
            else
            {
                WRN("IOKit: bad key");
                retval = -1;
            }
            CFRelease(ioplist);
        }
        else
        {
            WRN("IOKit says nooo");
            retval = -1;
        }
    }
#ifdef __APPLE__
    if(xpc)
    {
        xpc_object_t xobj = xpc_create_from_plist(addr, len);
        if(xobj)
        {
            xpc_object_t obj = xpc_get(xobj, argc - aoff, &argv[aoff]);
            if(obj)
            {
                xpcj_print(stdout, obj, json, raw);
            }
            else
            {
                WRN("XPC: bad key");
                retval = -1;
            }
            xpc_release(xobj);
        }
        else
        {
            WRN("XPC says nooo");
            retval = -1;
        }
    }
#endif

out:;
    if(fd >= 0)
    {
        if(addr) munmap(addr, len);
        close(fd);
    }
    else if(addr)
    {
        free(addr);
    }
    return retval;
}
