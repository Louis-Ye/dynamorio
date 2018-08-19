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

#ifndef _FUNC_WRAP_H_
#define _FUNC_WRAP_H_ 1

#include "drext.h"
#include "dr_api.h"

typedef struct {
    void *drcontext;
    dr_mcontext_t *mc; // machine context
    app_pc retaddr;
} func_wrap_context_t;

enum {
    DRMGR_PRIORITY_INSERT_FUNC_WRAP = 500
};
#define DRMGR_PRIORITY_NAME_FUNC_WRAP "func_wrap"

bool
func_wrap_init(void);

void
func_wrap_exit(void);

// Should not be called during the instrumentation stage
bool
func_wrap_wrap(app_pc func, void (*pre_func_cb)(void *fwrapcxt, void *user_data),
               void (*post_func_cb)(void *fwrapcxt, void *user_data), void *user_data);

app_pc func_wrap_get_retaddr(void *fwrapcxt);
void * func_wrap_get_arg(void *fwrapcxt, int arg_i);
void * func_wrap_get_retval(void *fwrapcxt);
void * func_wrap_get_drcontext(void *fwrapcxt);

#endif  // _FUNC_WRAP_H_
