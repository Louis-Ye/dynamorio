/* **********************************************************
 * Copyright (c) 2015-2018 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* A simple but lock-free module for inserting function hooks */

#include "func_wrap.h"
#include "drmgr.h"
#include "hashtable.h"
#include "drvector.h"
#include "../ext_utils.h"
#include "../common/options.h"
#include <string.h>
#include <stddef.h> /* offsetof */
#include <limits.h> /* USHRT_MAX */

#define NOTIFY(level, ...)                     \
    do {                                       \
        if (op_verbose.get_value() >= (level)) \
            dr_fprintf(STDERR, __VA_ARGS__);   \
    } while (0)

static int func_wrap_init_count;
#define WRAP_TABLE_HASH_BITS 6
static hashtable_t fwrap_table;
static int tls_idx;

typedef struct {
    hashtable_t *post_fwrap_table_p;
} per_thread_t;

typedef struct {
    app_pc func;
    void (*pre_cb)(void *, void *);
    void (*post_cb)(void *, void *);
    void *user_data;
    int wrap_level;
} fwrap_entry_t;

static void
fwrap_entry_free(void *e)
{
    if (e != NULL) {
        dr_global_free((fwrap_entry_t *)e, sizeof(fwrap_entry_t));
    }
}

static void*
fwrap_entry_create(app_pc func, void (*pre_cb)(void *, void *),
                   void (*post_cb)(void *, void *), void *user_data)
{
    fwrap_entry_t *e = (fwrap_entry_t *)dr_global_alloc(sizeof(*e));
    if (e == NULL)
        return NULL;
    e->func = func;
    e->pre_cb = pre_cb;
    e->post_cb = post_cb;
    e->user_data = user_data;
    e->wrap_level = 0;
    return e;
}

////////////////////////////////////////////////////////////////////////////////
// platform specifics
typedef enum {
    /** The AMD64 ABI calling convention. */
    DRWRAP_CALLCONV_AMD64 = 0x01000000,
    /** The Microsoft x64 calling convention. */
    DRWRAP_CALLCONV_MICROSOFT_X64 = 0x02000000,
    /** The ARM calling convention. */
    DRWRAP_CALLCONV_ARM = 0x03000000,
    /** The IA-32 cdecl calling convention. */
    DRWRAP_CALLCONV_CDECL = 0x04000000,
    /* For the purposes of drwrap, stdcall is an alias to cdecl, since the
     * only difference is whether the caller or callee cleans up the stack.
     */
    /** The Microsoft IA-32 stdcall calling convention. */
    DRWRAP_CALLCONV_STDCALL = DRWRAP_CALLCONV_CDECL,
    /** The IA-32 fastcall calling convention. */
    DRWRAP_CALLCONV_FASTCALL = 0x05000000,
    /** The Microsoft IA-32 thiscall calling convention. */
    DRWRAP_CALLCONV_THISCALL = 0x06000000,
    /** The ARM AArch64 calling convention. */
    DRWRAP_CALLCONV_AARCH64 = 0x07000000,
#ifdef X64
#    ifdef AARCH64
    /** Default calling convention for the platform. */
    DRWRAP_CALLCONV_DEFAULT = DRWRAP_CALLCONV_AARCH64,
#    elif defined(UNIX) /* x64 */
    /** Default calling convention for the platform. */
    DRWRAP_CALLCONV_DEFAULT = DRWRAP_CALLCONV_AMD64,
#    else               /* WINDOWS x64 */
    /** Default calling convention for the platform. */
    DRWRAP_CALLCONV_DEFAULT = DRWRAP_CALLCONV_MICROSOFT_X64,
#    endif
#else /* 32-bit */
#    ifdef ARM
    /** Default calling convention for the platform. */
    DRWRAP_CALLCONV_DEFAULT = DRWRAP_CALLCONV_ARM,
#    else /* x86: UNIX or WINDOWS */
    /** Default calling convention for the platform. */
    DRWRAP_CALLCONV_DEFAULT = DRWRAP_CALLCONV_CDECL,
#    endif
#endif
    /** The platform-specific calling convention for a vararg function. */
    DRWRAP_CALLCONV_VARARG = DRWRAP_CALLCONV_DEFAULT,
    DRWRAP_CALLCONV_MASK = 0xff000000
} drwrap_callconv_t;

static inline reg_t *
drwrap_stack_arg_addr(func_wrap_context_t *fwrapcxt, uint arg, uint reg_arg_count,
                      uint stack_arg_offset)
{
    return (reg_t *)(fwrapcxt->mc->xsp +
                     (arg - reg_arg_count + stack_arg_offset) * sizeof(reg_t));
}

static inline reg_t *
drwrap_arg_addr(func_wrap_context_t *wrapcxt, int arg)
{
    if (wrapcxt == NULL || wrapcxt->mc == NULL)
        return NULL;

    switch (DRWRAP_CALLCONV_DEFAULT) {
#if defined(ARM)
    case DRWRAP_CALLCONV_ARM:
        switch (arg) {
        case 0: return &wrapcxt->mc->r0;
        case 1: return &wrapcxt->mc->r1;
        case 2: return &wrapcxt->mc->r2;
        case 3: return &wrapcxt->mc->r3;
        default: return drwrap_stack_arg_addr(wrapcxt, arg, 4, 0);
        }
#elif defined(AARCH64)
    case DRWRAP_CALLCONV_AARCH64:
        switch (arg) {
        case 0: return &wrapcxt->mc->r0;
        case 1: return &wrapcxt->mc->r1;
        case 2: return &wrapcxt->mc->r2;
        case 3: return &wrapcxt->mc->r3;
        case 4: return &wrapcxt->mc->r4;
        case 5: return &wrapcxt->mc->r5;
        case 6: return &wrapcxt->mc->r6;
        case 7: return &wrapcxt->mc->r7;
        default: return drwrap_stack_arg_addr(wrapcxt, arg, 8, 0);
        }
#else          /* Intel x86 or x64 */
#    ifdef X64 /* registers are platform-exclusive */
    case DRWRAP_CALLCONV_AMD64:
        switch (arg) {
        case 0: return &wrapcxt->mc->rdi;
        case 1: return &wrapcxt->mc->rsi;
        case 2: return &wrapcxt->mc->rdx;
        case 3: return &wrapcxt->mc->rcx;
        case 4: return &wrapcxt->mc->r8;
        case 5: return &wrapcxt->mc->r9;
        default: return drwrap_stack_arg_addr(wrapcxt, arg, 6, 1 /*retaddr*/);
        }
    case DRWRAP_CALLCONV_MICROSOFT_X64:
        switch (arg) {
        case 0: return &wrapcxt->mc->rcx;
        case 1: return &wrapcxt->mc->rdx;
        case 2: return &wrapcxt->mc->r8;
        case 3: return &wrapcxt->mc->r9;
        default:
            return drwrap_stack_arg_addr(wrapcxt, arg, 4, 1 /*retaddr*/ + 4 /*reserved*/);
        }
#    endif
    case DRWRAP_CALLCONV_CDECL:
        return drwrap_stack_arg_addr(wrapcxt, arg, 0, 1 /*retaddr*/);
    case DRWRAP_CALLCONV_FASTCALL:
        switch (arg) {
        case 0: return &wrapcxt->mc->xcx;
        case 1: return &wrapcxt->mc->xdx;
        default: return drwrap_stack_arg_addr(wrapcxt, arg, 2, 1 /*retaddr*/);
        }
    case DRWRAP_CALLCONV_THISCALL:
        if (arg == 0)
            return &wrapcxt->mc->xcx;
        else
            return drwrap_stack_arg_addr(wrapcxt, arg, 1, 1 /*retaddr*/);
#endif
    default:
        DR_ASSERT_MSG(false, "unknown or unsupported calling convention");
        return NULL;
    }
}
////////////////////////////////////////////////////////////////////////////////

/* called via clean call at the top of callee */
static void
func_wrap_in_callee(void *arg1, reg_t xsp _IF_NOT_X86(reg_t lr))
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext; // machine context
    dr_get_mcontext(drcontext, &mcontext);
    mcontext.size = sizeof(mcontext);
    mcontext.xsp = xsp;
    mcontext.flags = (dr_mcontext_flags_t)0;
#ifdef AARCHXX
    mcontext.lr = lr;
#endif

    fwrap_entry_t *e = (fwrap_entry_t *)arg1;
    app_pc retaddr = (app_pc)IF_X86_ELSE(xsp, (app_pc)lr);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    fwrap_entry_t *post_e =
        (fwrap_entry_t *)hashtable_lookup(pt->post_fwrap_table_p, (void *)retaddr);
    if (post_e == NULL) {
        post_e = (fwrap_entry_t *)
            fwrap_entry_create(retaddr, e->pre_cb, e->post_cb, e->user_data);
        hashtable_add(pt->post_fwrap_table_p, (void *)retaddr, (void *)post_e);
    }
    post_e->wrap_level++;
    func_wrap_context_t fwrapcxt{drcontext, &mcontext, retaddr};
    post_e->pre_cb(&fwrapcxt, post_e->user_data);
}

/* called via clean call at return address(es) of callee */
static void
func_wrap_after_callee(app_pc retaddr, reg_t xsp)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mcontext; // machine context
    dr_get_mcontext(drcontext, &mcontext);
    mcontext.size = sizeof(mcontext);
    mcontext.xsp = xsp;
    mcontext.flags = (dr_mcontext_flags_t)0;

    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    fwrap_entry_t *post_e =
        (fwrap_entry_t *)hashtable_lookup(pt->post_fwrap_table_p, (void *)retaddr);
    if (post_e == NULL || post_e->wrap_level <= 0)
        return;
    post_e->wrap_level--;
    func_wrap_context_t fwrapcxt{drcontext, &mcontext, retaddr};
    post_e->post_cb(&fwrapcxt, post_e->user_data);
}

static dr_emit_flags_t
func_wrap_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                            bool translating, OUT void **user_data)
{
  return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
func_wrap_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                          bool for_trace, bool translating, void *user_data)
{
    app_pc pc =
        dr_app_pc_as_jump_target(instr_get_isa_mode(inst), instr_get_app_pc(inst));
    fwrap_entry_t *e = (fwrap_entry_t *)hashtable_lookup(&fwrap_table, (void *)pc);
    if (e != NULL) {
        dr_cleancall_save_t flags = (dr_cleancall_save_t)
            (DR_CLEANCALL_NOSAVE_FLAGS | DR_CLEANCALL_NOSAVE_XMM_NONPARAM);
        dr_insert_clean_call_ex(drcontext, bb, inst, (void *)func_wrap_in_callee, flags,
                                IF_X86_ELSE(2, 3), OPND_CREATE_INTPTR((ptr_int_t)e),
                                opnd_create_reg(DR_REG_XSP)
                                    _IF_NOT_X86(opnd_create_reg(DR_REG_LR)));
    }

    app_pc retaddr = instr_get_app_pc(inst);
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    fwrap_entry_t *post_e =
          (fwrap_entry_t *)hashtable_lookup(pt->post_fwrap_table_p, (void *)retaddr);
    if (post_e != NULL) {
        NOTIFY(2, "post_e=%p!\n", post_e);
        dr_insert_clean_call_ex(drcontext, bb, inst, (void *)func_wrap_after_callee,
                                (dr_cleancall_save_t)0, 2,
                                OPND_CREATE_INTPTR((ptr_int_t)pc),
                                opnd_create_reg(DR_REG_XSP));
    }

    return DR_EMIT_DEFAULT;
}

static void
event_thread_init(void *drcontext)
{
    NOTIFY(2, "thread_init!\n");

    per_thread_t *pt;
    pt = (per_thread_t *)dr_thread_alloc(drcontext, sizeof(*pt));
    DR_ASSERT(pt != NULL);
    memset(pt, 0, sizeof(*pt));
    pt->post_fwrap_table_p = (hashtable_t *)
        dr_thread_alloc(drcontext, sizeof(*pt->post_fwrap_table_p));
    DR_ASSERT(pt->post_fwrap_table_p != NULL);
    hashtable_init_ex(pt->post_fwrap_table_p, WRAP_TABLE_HASH_BITS, HASH_INTPTR,
                      false /*!str_dup*/, false /*!synch*/, fwrap_entry_free, NULL, NULL);
    drmgr_set_tls_field(drcontext, tls_idx, pt);

    NOTIFY(2, "pt->post_fwrap_table_p=%p!\n", pt->post_fwrap_table_p);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *pt = (per_thread_t *)drmgr_get_tls_field(drcontext, tls_idx);
    hashtable_delete(pt->post_fwrap_table_p);
    dr_thread_free(drcontext, pt->post_fwrap_table_p, sizeof(*pt->post_fwrap_table_p));
    dr_thread_free(drcontext, pt, sizeof(*pt));
}

bool
func_wrap_init()
{
    int count = dr_atomic_add32_return_sum(&func_wrap_init_count, 1);
    if (count > 1)
        return true;
    drmgr_priority_t pri_insert = { sizeof(pri_insert), DRMGR_PRIORITY_NAME_FUNC_WRAP,
                                    NULL, NULL, DRMGR_PRIORITY_INSERT_FUNC_WRAP };
    if (!drmgr_init())
        return false;
    if (!drmgr_register_bb_instrumentation_event(func_wrap_event_bb_analysis,
                                                 func_wrap_event_bb_insert,
                                                 &pri_insert))
        return false;
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit))
        return false;

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    hashtable_init_ex(&fwrap_table, WRAP_TABLE_HASH_BITS, HASH_INTPTR, false /*!str_dup*/,
                      false /*!synch*/, fwrap_entry_free, NULL, NULL);

    return true;
}

void
func_wrap_exit()
{
    int count = dr_atomic_add32_return_sum(&func_wrap_init_count, -1);
    if (count != 0)
        return;

    if (!drmgr_unregister_bb_instrumentation_event(func_wrap_event_bb_analysis) ||
        !drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit))
        DR_ASSERT(false);

    hashtable_delete(&fwrap_table);
}

bool
func_wrap_wrap(app_pc func, void (*pre_func_cb)(void *fwrapcxt, void *user_data),
               void (*post_func_cb)(void *fwrapcxt, void *user_data), void *user_data)
{
    void *new_e = fwrap_entry_create(func, pre_func_cb, post_func_cb, user_data);
    if (new_e == NULL)
        return false;
    // replace the previous entry
    void *prev_e = hashtable_add_replace(&fwrap_table, (void *)func, new_e);
    if (prev_e != NULL) {
        fwrap_entry_free(prev_e);
    }
    return true;
}

app_pc func_wrap_get_retaddr(void *fwrapcxt)
{
    if (fwrapcxt == NULL)
        return NULL;
    return ((func_wrap_context_t *)fwrapcxt)->retaddr;
}

void * func_wrap_get_arg(void *fwrapcxt, int arg_i)
{
    reg_t *arg_addr = drwrap_arg_addr((func_wrap_context_t *)fwrapcxt, arg_i);
    if (arg_addr == NULL)
        return NULL;
    return (void *)*arg_addr;
}

void * func_wrap_get_retval(void *fwrapcxt)
{
    if (fwrapcxt == NULL)
        return NULL;
    return (void *)((func_wrap_context_t *)fwrapcxt)->mc->IF_X86_ELSE(xax, r0);
}

void * func_wrap_get_drcontext(void *fwrapcxt)
{
    if (fwrapcxt == NULL)
        return NULL;
    return ((func_wrap_context_t *)fwrapcxt)->drcontext;
}
