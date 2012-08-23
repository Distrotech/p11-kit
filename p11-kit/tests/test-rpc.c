/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2012 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "CuTest.h"

#include "debug.h"
#include "library.h"
#include "message.h"
#include "mock.h"
#include "p11-kit.h"
#include "private.h"
#include "rpc.h"
#include "rpc-message.h"
#include "virtual.h"

#include <sys/types.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void
test_new_free (CuTest *tc)
{
	p11_buffer *buf;

	buf = p11_rpc_buffer_new (0);

	CuAssertPtrNotNull (tc, buf->data);
	CuAssertIntEquals (tc, 0, buf->len);
	CuAssertIntEquals (tc, 0, buf->flags);
	CuAssertTrue (tc, buf->size == 0);
	CuAssertPtrNotNull (tc, buf->ffree);
	CuAssertPtrNotNull (tc, buf->frealloc);

	p11_rpc_buffer_free (buf);
}

static void
test_uint16 (CuTest *tc)
{
	p11_buffer buffer;
	uint16_t val = 0xFFFF;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint16 (&buffer, &next, &val);
	CuAssertIntEquals (tc, false, ret);
	CuAssertIntEquals (tc, 0, next);
	CuAssertIntEquals (tc, 0xFFFF, val);

	p11_buffer_reset (&buffer, 0);

	ret = p11_rpc_buffer_set_uint16 (&buffer, 0, 0x6789);
	CuAssertIntEquals (tc, false, ret);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint16 (&buffer, 0x6789);
	CuAssertIntEquals (tc, 9, buffer.len);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint16 (&buffer, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 9, next);
	CuAssertIntEquals (tc, 0x6789, val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint16_static (CuTest *tc)
{
	p11_buffer buf = { (unsigned char *)"pad0\x67\x89", 6, };
	uint16_t val = 0xFFFF;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint16 (&buf, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 6, next);
	CuAssertIntEquals (tc, 0x6789, val);
}

static void
test_uint32 (CuTest *tc)
{
	p11_buffer buffer;
	uint32_t val = 0xFFFFFFFF;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint32 (&buffer, &next, &val);
	CuAssertIntEquals (tc, false, ret);
	CuAssertIntEquals (tc, 0, next);
	CuAssertIntEquals (tc, 0xFFFFFFFF, val);

	p11_buffer_reset (&buffer, 0);

	ret = p11_rpc_buffer_set_uint32 (&buffer, 0, 0x12345678);
	CuAssertIntEquals (tc, false, ret);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint32 (&buffer, 0x12345678);
	CuAssertIntEquals (tc, 11, buffer.len);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint32 (&buffer, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 11, next);
	CuAssertIntEquals (tc, 0x12345678, val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint32_static (CuTest *tc)
{
	p11_buffer buf = { (unsigned char *)"pad0\x23\x45\x67\x89", 8, };
	uint32_t val = 0xFFFFFFFF;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint32 (&buf, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 8, next);
	CuAssertIntEquals (tc, 0x23456789, val);
}

static void
test_uint64 (CuTest *tc)
{
	p11_buffer buffer;
	uint64_t val = 0xFFFFFFFFFFFFFFFF;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	next = 0;
	ret = p11_rpc_buffer_get_uint64 (&buffer, &next, &val);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, 0, next);
	CuAssertTrue (tc, 0xFFFFFFFFFFFFFFFF == val);

	p11_buffer_reset (&buffer, 0);

	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_uint64 (&buffer, 0x0123456708ABCDEF);
	CuAssertIntEquals (tc, 15, buffer.len);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_uint64 (&buffer, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 15, next);
	CuAssertTrue (tc, 0x0123456708ABCDEF == val);

	p11_buffer_uninit (&buffer);
}

static void
test_uint64_static (CuTest *tc)
{
	p11_buffer buf = { (unsigned char *)"pad0\x89\x67\x45\x23\x11\x22\x33\x44", 12, };
	uint64_t val = 0xFFFFFFFFFFFFFFFF;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_uint64 (&buf, &next, &val);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 12, next);
	CuAssertTrue (tc, 0x8967452311223344 == val);
}

static void
test_byte_array (CuTest *tc)
{
	p11_buffer buffer;
	unsigned char bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	/* Invalid read */

	next = 0;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	CuAssertIntEquals (tc, false, ret);
	CuAssertIntEquals (tc, 0, next);
	CuAssertIntEquals (tc, ~0, length);

	/* Test full array */

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_byte_array (&buffer, bytes, 32);
	CuAssertIntEquals (tc, 43, buffer.len);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 43, next);
	CuAssertIntEquals (tc, 32, length);
	CuAssertTrue (tc, memcmp (val, bytes, 32) == 0);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_null (CuTest *tc)
{
	p11_buffer buffer;
	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);

	p11_rpc_buffer_add_byte_array (&buffer, NULL, 0);
	CuAssertIntEquals (tc, 11, buffer.len);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	next = 7;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 11, next);
	CuAssertIntEquals (tc, 0, length);
	CuAssertPtrEquals (tc, NULL, (void*)val);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_too_long (CuTest *tc)
{
	p11_buffer buffer;
	const unsigned char *val = NULL;
	size_t length = ~0;
	size_t next;
	bool ret;

	p11_buffer_init (&buffer, 0);

	p11_buffer_reset (&buffer, 0);
	p11_buffer_add (&buffer, (unsigned char *)"padding", 7);
	CuAssertTrue (tc, !p11_buffer_failed (&buffer));

	/* Passing a too short buffer here shouldn't matter, as length is checked for sanity */
	p11_rpc_buffer_add_byte_array (&buffer, (unsigned char *)"", 0x9fffffff);
	CuAssertTrue (tc, p11_buffer_failed (&buffer));

	/* Force write a too long byte arary to buffer */
	p11_buffer_reset (&buffer, 0);
	p11_rpc_buffer_add_uint32 (&buffer, 0x9fffffff);

	next = 0;
	ret = p11_rpc_buffer_get_byte_array (&buffer, &next, &val, &length);
	CuAssertIntEquals (tc, false, ret);
	CuAssertIntEquals (tc, 0, next);
	CuAssertIntEquals (tc, ~0, length);
	CuAssertPtrEquals (tc, NULL, (void*)val);

	p11_buffer_uninit (&buffer);
}

static void
test_byte_array_static (CuTest *tc)
{
	unsigned char data[] = { 'p', 'a', 'd', 0x00, 0x00, 0x00, 0x00, 0x20,
	                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	p11_buffer buf = { data, 0x40, };
	const unsigned char *val;
	size_t length = ~0;
	size_t next;
	bool ret;

	next = 4;
	ret = p11_rpc_buffer_get_byte_array (&buf, &next, &val, &length);
	CuAssertIntEquals (tc, true, ret);
	CuAssertIntEquals (tc, 40, next);
	CuAssertIntEquals (tc, 32, length);
	CuAssertTrue (tc, memcmp (data + 8, val, 32) == 0);
}

static p11_virtual base;
static bool rpc_initialized = false;

static CK_RV
rpc_initialize (p11_rpc_client_vtable *vtable,
                void *init_reserved)
{
	CuTest *tc = vtable->data;

	CuAssertIntEquals (tc, false, rpc_initialized);
	rpc_initialized = true;

	return CKR_OK;
}

static CK_RV
rpc_initialize_fails (p11_rpc_client_vtable *vtable,
                      void *init_reserved)
{
	CuTest *tc = vtable->data;

	CuAssertIntEquals (tc, false, rpc_initialized);
	return CKR_FUNCTION_FAILED;
}

static CK_RV
rpc_initialize_device_removed (p11_rpc_client_vtable *vtable,
                               void *init_reserved)
{
	CuTest *tc = vtable->data;

	CuAssertIntEquals (tc, false, rpc_initialized);
	return CKR_DEVICE_REMOVED;
}

static CK_RV
rpc_transport (p11_rpc_client_vtable *vtable,
               p11_buffer *request,
               p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int ret;

	/* Just pass directly to the server code */
	ret = p11_rpc_server_handle (&base.funcs, request, response);
	CuAssertTrue (tc, ret >= 0);

	return CKR_OK;
}

static void
rpc_finalize (p11_rpc_client_vtable *vtable,
              void *fini_reserved)
{
	CuTest *tc = vtable->data;

	CuAssertIntEquals (tc, true, rpc_initialized);
	rpc_initialized = false;
}

static void
test_initialize (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = false;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	rv = mixin.funcs.C_Initialize (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, true, rpc_initialized);

	rv = mixin.funcs.C_Finalize (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, false, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_not_initialized (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	CK_INFO info;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = false;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	rv = (mixin.funcs.C_GetInfo) (&mixin.funcs, &info);
	CuAssertTrue (tc, rv == CKR_CRYPTOKI_NOT_INITIALIZED);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_client (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize_fails, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = false;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_FUNCTION_FAILED);
	CuAssertIntEquals (tc, false, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_fails (p11_rpc_client_vtable *vtable,
                     p11_buffer *request,
                     p11_buffer *response)
{
	return CKR_FUNCTION_REJECTED;
}

static void
test_transport_fails (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_fails, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = false;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_FUNCTION_REJECTED);
	CuAssertIntEquals (tc, false, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static void
test_initialize_fails_on_server (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);
	base.funcs.C_Initialize = mock_X_Initialize__fails;

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_FUNCTION_FAILED);
	CuAssertIntEquals (tc, false, rpc_initialized);

	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_parse (p11_rpc_client_vtable *vtable,
                         p11_buffer *request,
                         p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int rc;

	/* Just zero bytes is an invalid message */
	rc = p11_buffer_reset (response, 2);
	CuAssertTrue (tc, rc >= 0);

	memset (response->data, 0, 2);
	response->len = 2;
	return CKR_OK;
}

static void
test_transport_bad_parse (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_bad_parse, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	rpc_initialized = false;
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);
	CuAssertIntEquals (tc, 0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_short_error (p11_rpc_client_vtable *vtable,
                           p11_buffer *request,
                           p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x01,                   /* short error */
	};

	rc = p11_buffer_reset (response, sizeof (data));
	CuAssertTrue (tc, rc >= 0);

	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_short_error (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_short_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);
	CuAssertIntEquals (tc, 0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_invalid_error (p11_rpc_client_vtable *vtable,
                             p11_buffer *request,
                             p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x00,       /* RPC_CALL_ERROR */
		0x00, 0x00, 0x00, 0x01, 0x75, /* signature 'u' */
		0x00, 0x00, 0x00, 0x00,       /* a CKR_OK error*/
		0x00, 0x00, 0x00, 0x00,
	};

	rc = p11_buffer_reset (response, sizeof (data));
	CuAssertTrue (tc, rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_invalid_error (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_invalid_error, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);
	CuAssertIntEquals (tc, 0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_wrong_response (p11_rpc_client_vtable *vtable,
                              p11_buffer *request,
                              p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_Finalize */
		0x00, 0x00, 0x00, 0x00,       /* signature '' */
	};

	rc = p11_buffer_reset (response, sizeof (data));
	CuAssertTrue (tc, rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_wrong_response (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_wrong_response, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);
	CuAssertIntEquals (tc, 0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static CK_RV
rpc_transport_bad_contents (p11_rpc_client_vtable *vtable,
                            p11_buffer *request,
                            p11_buffer *response)
{
	CuTest *tc = vtable->data;
	int rc;

	unsigned char data[] = {
		0x00, 0x00, 0x00, 0x02,       /* RPC_CALL_C_GetInfo */
		0x00, 0x00, 0x00, 0x05,       /* signature 'vsusv' */
		'v', 's', 'u', 's', 'v',
		0x00, 0x00, 0x00, 0x00,       /* invalid data */
	};

	rc = p11_buffer_reset (response, sizeof (data));
	CuAssertTrue (tc, rc >= 0);
	memcpy (response->data, data, sizeof (data));
	response->len = sizeof (data);
	return CKR_OK;
}

static void
test_transport_bad_contents (CuTest *tc)
{
	p11_rpc_client_vtable vtable = { tc, rpc_initialize, rpc_transport_bad_contents, rpc_finalize };
	p11_virtual mixin;
	bool ret;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, &mock_module_no_slots, NULL);

	ret = p11_rpc_client_init (&mixin, &vtable);
	CuAssertIntEquals (tc, true, ret);

	p11_kit_be_quiet ();

	rv = (mixin.funcs.C_Initialize) (&mixin.funcs, NULL);
	CuAssertTrue (tc, rv == CKR_DEVICE_ERROR);
	CuAssertIntEquals (tc, 0, rpc_initialized);

	p11_message_loud ();
	p11_virtual_uninit (&mixin);
}

static p11_rpc_client_vtable test_normal_vtable = {
	NULL,
	rpc_initialize,
	rpc_transport,
	rpc_finalize,
};

static p11_rpc_client_vtable test_device_removed_vtable = {
	NULL,
	rpc_initialize_device_removed,
	rpc_transport,
	rpc_finalize,
};

static void
mixin_free (void *data)
{
	p11_virtual *mixin = data;
	p11_virtual_uninit (mixin);
	free (mixin);
}

static CK_FUNCTION_LIST_PTR
setup_test_rpc_module (CuTest *tc,
                       p11_rpc_client_vtable *vtable,
                       CK_FUNCTION_LIST *module_template,
                       CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST *rpc_module;
	p11_virtual *mixin;
	CK_RV rv;

	/* Build up our own function list */
	p11_virtual_init (&base, &p11_virtual_base, module_template, NULL);

	mixin = calloc (1, sizeof (p11_virtual));
	assert (mixin != NULL);

	vtable->data = tc;
	if (!p11_rpc_client_init (mixin, vtable))
		assert_not_reached ();

	rpc_module = p11_virtual_wrap (mixin, mixin_free);
	CuAssertPtrNotNull (tc, rpc_module);

	rv = p11_kit_module_initialize (rpc_module);
	CuAssertTrue (tc, rv == CKR_OK);

	if (session) {
		rv = (rpc_module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                                  NULL, NULL, session);
		CuAssertTrue (tc, rv == CKR_OK);
	}

	return rpc_module;
}

static CK_FUNCTION_LIST *
setup_mock_module (CuTest *tc,
                   CK_SESSION_HANDLE *session)
{
	return setup_test_rpc_module (tc, &test_normal_vtable, &mock_module, session);
}

static void
teardown_mock_module (CuTest *tc,
                      CK_FUNCTION_LIST *rpc_module)
{
	p11_kit_module_finalize (rpc_module);
	p11_virtual_unwrap (rpc_module);
}

static void
test_get_info_stand_in (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_INFO info;
	CK_RV rv;
	char *string;

	rpc_module = setup_test_rpc_module (tc, &test_device_removed_vtable,
	                                    &mock_module_no_slots, NULL);

	rv = (rpc_module->C_GetInfo) (&info);
	CuAssertTrue (tc, rv == CKR_OK);

	CuAssertIntEquals (tc, CRYPTOKI_VERSION_MAJOR, info.cryptokiVersion.major);
	CuAssertIntEquals (tc, CRYPTOKI_VERSION_MINOR, info.cryptokiVersion.minor);
	string = p11_kit_space_strdup (info.manufacturerID, sizeof (info.manufacturerID));
	CuAssertStrEquals (tc, "p11-kit", string);
	free (string);
	string = p11_kit_space_strdup (info.libraryDescription, sizeof (info.libraryDescription));
	CuAssertStrEquals (tc, "p11-kit (no connection)", string);
	free (string);
	CuAssertIntEquals (tc, 0, info.flags);
	CuAssertIntEquals (tc, 1, info.libraryVersion.major);
	CuAssertIntEquals (tc, 1, info.libraryVersion.minor);

	teardown_mock_module (tc, rpc_module);
}

static void
test_get_slot_list_no_device (CuTest *tc)
{
	CK_FUNCTION_LIST_PTR rpc_module;
	CK_SLOT_ID slot_list[8];
	CK_ULONG count;
	CK_RV rv;

	rpc_module = setup_test_rpc_module (tc, &test_device_removed_vtable,
	                                    &mock_module_no_slots, NULL);

	rv = (rpc_module->C_GetSlotList) (CK_TRUE, NULL, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 0, count);
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, NULL, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_TRUE, slot_list, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 0, count);

	count = 8;
	rv = (rpc_module->C_GetSlotList) (CK_FALSE, slot_list, &count);
	CuAssertTrue (tc, rv == CKR_OK);
	CuAssertIntEquals (tc, 0, count);

	teardown_mock_module (tc, rpc_module);
}

#include "test-mock.c"

int
main (void)
{
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_MOCK_CAPITALIZE,
		CKM_MOCK_PREFIX,
		CKM_MOCK_GENERATE,
		CKM_MOCK_WRAP,
		CKM_MOCK_DERIVE,
		CKM_MOCK_COUNT,
		0,
	};

	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	putenv ("P11_KIT_STRICT=1");
	mock_module_init ();
	p11_library_init ();

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	SUITE_ADD_TEST (suite, test_new_free);
	SUITE_ADD_TEST (suite, test_uint16);
	SUITE_ADD_TEST (suite, test_uint16_static);
	SUITE_ADD_TEST (suite, test_uint32);
	SUITE_ADD_TEST (suite, test_uint32_static);
	SUITE_ADD_TEST (suite, test_uint64);
	SUITE_ADD_TEST (suite, test_uint64_static);
	SUITE_ADD_TEST (suite, test_byte_array);
	SUITE_ADD_TEST (suite, test_byte_array_null);
	SUITE_ADD_TEST (suite, test_byte_array_too_long);
	SUITE_ADD_TEST (suite, test_byte_array_static);

	SUITE_ADD_TEST (suite, test_initialize_fails_on_client);
	SUITE_ADD_TEST (suite, test_initialize_fails_on_server);
	SUITE_ADD_TEST (suite, test_initialize);
	SUITE_ADD_TEST (suite, test_not_initialized);
	SUITE_ADD_TEST (suite, test_transport_fails);
	SUITE_ADD_TEST (suite, test_transport_bad_parse);
	SUITE_ADD_TEST (suite, test_transport_short_error);
	SUITE_ADD_TEST (suite, test_transport_invalid_error);
	SUITE_ADD_TEST (suite, test_transport_wrong_response);
	SUITE_ADD_TEST (suite, test_transport_bad_contents);
	SUITE_ADD_TEST (suite, test_get_info_stand_in);
	SUITE_ADD_TEST (suite, test_get_slot_list_no_device);

	test_mock_add_tests (suite);

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
