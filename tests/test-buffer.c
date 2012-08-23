/*
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "buffer.h"
#include "rpc.h"

static void
test_init_uninit (CuTest *tc)
{
	P11Output buffer;

	_p11_buffer_init (&buffer, 10);
	CuAssertPtrNotNull (tc, buffer.buf.data);
	CuAssertIntEquals (tc, 0, buffer.buf.length);
	CuAssertIntEquals (tc, 0, buffer.buf.flags);
	CuAssertTrue (tc, buffer.allocated >= 10);
	CuAssertPtrNotNull (tc, buffer.ffree);
	CuAssertPtrNotNull (tc, buffer.frealloc);

	CuAssertPtrEquals (tc, _p11_buffer_to_output (&buffer.buf), &buffer);

	_p11_buffer_uninit (&buffer);
}

static void
test_new_free (CuTest *tc)
{
	P11Buffer *buf;
	P11Output *buffer;

	buf = p11_buffer_new (0);
	buffer = _p11_buffer_to_output (buf);
	CuAssertPtrEquals (tc, buf, buffer);

	CuAssertPtrNotNull (tc, buf->data);
	CuAssertIntEquals (tc, 0, buf->length);
	CuAssertIntEquals (tc, 0, buf->flags);
	CuAssertTrue (tc, buffer->allocated == 0);
	CuAssertPtrNotNull (tc, buffer->ffree);
	CuAssertPtrNotNull (tc, buffer->frealloc);

	p11_buffer_free (buf);
}

static void
test_reserve (CuTest *tc)
{
	P11Output buffer;

	_p11_buffer_init (&buffer, 10);
	buffer.buf.length = 5;
	_p11_buffer_reserve (&buffer, 35);
	CuAssertIntEquals (tc, 5, buffer.buf.length);
	CuAssertTrue (tc, buffer.allocated >= 35);

	_p11_buffer_reserve (&buffer, 15);
	CuAssertIntEquals (tc, 5, buffer.buf.length);
	CuAssertTrue (tc, buffer.allocated >= 15);

	CuAssertPtrEquals (tc, _p11_buffer_to_output (&buffer.buf), &buffer);

	_p11_buffer_uninit (&buffer);
}

static int mock_realloced = 0;
static int mock_freed = 0;

static void *
mock_realloc (void *data,
              size_t size)
{
	mock_realloced++;
	return realloc (data, size);
}

static void
mock_free (void *data)
{
	mock_freed++;
	free (data);
}

static void
test_init_for_data (CuTest *tc)
{
	P11Output buffer;
	int ret;

	mock_realloced = 0;
	mock_freed = 0;

	_p11_buffer_init_full (&buffer, (unsigned char *)strdup ("blah"), 4,
	                       mock_realloc, mock_free);

	CuAssertPtrNotNull (tc, buffer.buf.data);
	CuAssertStrEquals (tc, "blah", (char *)buffer.buf.data);
	CuAssertIntEquals (tc, 4, buffer.buf.length);
	CuAssertIntEquals (tc, 0, buffer.buf.flags);
	CuAssertIntEquals (tc, 4, buffer.allocated);
	CuAssertPtrEquals (tc, mock_free, buffer.ffree);
	CuAssertPtrEquals (tc, mock_realloc, buffer.frealloc);

	CuAssertIntEquals (tc, 0, mock_realloced);
	CuAssertIntEquals (tc, 0, mock_freed);

	ret = _p11_buffer_reserve (&buffer, 1024);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 1, mock_realloced);

	_p11_buffer_uninit (&buffer);
	CuAssertIntEquals (tc, 1, mock_realloced);
	CuAssertIntEquals (tc, 1, mock_freed);
}

static void
test_reset (CuTest *tc)
{
	P11Output buffer;

	_p11_buffer_init (&buffer, 10);
	buffer.buf.length = 5;
	_p11_buffer_fail (&buffer);
	_p11_buffer_reset (&buffer);


	CuAssertIntEquals (tc, 0, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	_p11_buffer_uninit (&buffer);
}

static void
test_append (CuTest *tc)
{
	P11Output buffer;

	_p11_buffer_init (&buffer, 10);

	_p11_buffer_append (&buffer, (unsigned char *)"Planet Express", 15);
	CuAssertIntEquals (tc, 15, buffer.buf.length);
	CuAssertStrEquals (tc, "Planet Express", (char *)buffer.buf.data);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	_p11_buffer_uninit (&buffer);
}

static void
test_byte (CuTest *tc)
{
	P11Output buffer;
	unsigned char val = 0xFF;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	ret = _p11_buffer_get_byte (&buffer.buf, 0, &next, &val);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertIntEquals (tc, 0xFF, val);

	_p11_buffer_reset (&buffer);

	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_byte (&buffer, 0x77);
	CuAssertIntEquals (tc, 8, buffer.buf.length);
	CuAssertIntEquals (tc, 0x77, buffer.buf.data[7]);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_byte (&buffer.buf, 7, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 8, next);
	CuAssertIntEquals (tc, 0x77, val);

	_p11_buffer_uninit (&buffer);
}

static void
test_byte_static (CuTest *tc)
{
	P11Buffer buf = { (unsigned char *)"pad0w", 5, 0, NULL };
	unsigned char val = 0xFF;
	size_t next = ~0;
	int ret;

	ret = _p11_buffer_get_byte (&buf, 4, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 5, next);
	CuAssertIntEquals (tc, 0x77, val);
}

static void
test_uint16 (CuTest *tc)
{
	P11Output buffer;
	uint16_t val = 0xFFFF;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	ret = _p11_buffer_get_uint16 (&buffer.buf, 0, &next, &val);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertIntEquals (tc, 0xFFFF, val);

	_p11_buffer_reset (&buffer);

	ret = _p11_buffer_set_uint16 (&buffer, 0, 0x6789);
	CuAssertIntEquals (tc, 0, ret);

	_p11_buffer_reset (&buffer);

	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_uint16 (&buffer, 0x6789);
	CuAssertIntEquals (tc, 9, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_uint16 (&buffer.buf, 7, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 9, next);
	CuAssertIntEquals (tc, 0x6789, val);

	_p11_buffer_uninit (&buffer);
}

static void
test_uint16_static (CuTest *tc)
{
	P11Buffer buf = { (unsigned char *)"pad0\x67\x89", 6, 0, NULL };
	uint16_t val = 0xFFFF;
	size_t next = ~0;
	int ret;

	ret = _p11_buffer_get_uint16 (&buf, 4, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 6, next);
	CuAssertIntEquals (tc, 0x6789, val);
}

static void
test_uint32 (CuTest *tc)
{
	P11Output buffer;
	uint32_t val = 0xFFFFFFFF;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	ret = _p11_buffer_get_uint32 (&buffer.buf, 0, &next, &val);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertIntEquals (tc, 0xFFFFFFFF, val);

	_p11_buffer_reset (&buffer);

	ret = _p11_buffer_set_uint32 (&buffer, 0, 0x12345678);
	CuAssertIntEquals (tc, 0, ret);

	_p11_buffer_reset (&buffer);

	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_uint32 (&buffer, 0x12345678);
	CuAssertIntEquals (tc, 11, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_uint32 (&buffer.buf, 7, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 11, next);
	CuAssertIntEquals (tc, 0x12345678, val);

	_p11_buffer_uninit (&buffer);
}

static void
test_uint32_static (CuTest *tc)
{
	P11Buffer buf = { (unsigned char *)"pad0\x23\x45\x67\x89", 8, 0, NULL };
	uint32_t val = 0xFFFFFFFF;
	size_t next = ~0;
	int ret;

	ret = _p11_buffer_get_uint32 (&buf, 4, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 8, next);
	CuAssertIntEquals (tc, 0x23456789, val);
}

static void
test_uint64 (CuTest *tc)
{
	P11Output buffer;
	uint64_t val = 0xFFFFFFFFFFFFFFFF;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	ret = _p11_buffer_get_uint64 (&buffer.buf, 0, &next, &val);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertTrue (tc, 0xFFFFFFFFFFFFFFFF == val);

	_p11_buffer_reset (&buffer);

	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_uint64 (&buffer, 0x0123456708ABCDEF);
	CuAssertIntEquals (tc, 15, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_uint64 (&buffer.buf, 7, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 15, next);
	CuAssertTrue (tc, 0x0123456708ABCDEF == val);

	_p11_buffer_uninit (&buffer);
}

static void
test_uint64_static (CuTest *tc)
{
	P11Buffer buf = { (unsigned char *)"pad0\x89\x67\x45\x23\x11\x22\x33\x44", 12, 0, NULL };
	uint64_t val = 0xFFFFFFFFFFFFFFFF;
	size_t next = ~0;
	int ret;

	ret = _p11_buffer_get_uint64 (&buf, 4, &next, &val);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 12, next);
	CuAssertTrue (tc, 0x8967452311223344 == val);
}

static void
test_byte_array (CuTest *tc)
{
	P11Output buffer;
	unsigned char bytes[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                          0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

	const unsigned char *val;
	size_t length = ~0;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	/* Invalid read */

	ret = _p11_buffer_get_byte_array (&buffer.buf, 0, &next, &val, &length);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertIntEquals (tc, ~0, length);

	/* Test full array */

	_p11_buffer_reset (&buffer);
	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_byte_array (&buffer, bytes, 32);
	CuAssertIntEquals (tc, 43, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_byte_array (&buffer.buf, 7, &next, &val, &length);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 43, next);
	CuAssertIntEquals (tc, 32, length);
	CuAssertTrue (tc, memcmp (val, bytes, 32) == 0);

	_p11_buffer_uninit (&buffer);
}

static void
test_byte_array_null (CuTest *tc)
{
	P11Output buffer;
	const unsigned char *val;
	size_t length = ~0;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	_p11_buffer_reset (&buffer);
	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);

	_p11_buffer_add_byte_array (&buffer, NULL, 0);
	CuAssertIntEquals (tc, 11, buffer.buf.length);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	ret = _p11_buffer_get_byte_array (&buffer.buf, 7, &next, &val, &length);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 11, next);
	CuAssertIntEquals (tc, 0, length);
	CuAssertPtrEquals (tc, NULL, (void*)val);

	_p11_buffer_uninit (&buffer);
}

static void
test_byte_array_too_long (CuTest *tc)
{
	P11Output buffer;
	const unsigned char *val = NULL;
	size_t length = ~0;
	size_t next = ~0;
	int ret;

	_p11_buffer_init (&buffer, 0);

	_p11_buffer_reset (&buffer);
	_p11_buffer_append (&buffer, (unsigned char *)"padding", 7);
	CuAssertTrue (tc, !_p11_buffer_failed (&buffer));

	/* Passing a too short buffer here shouldn't matter, as length is checked for sanity */
	_p11_buffer_add_byte_array (&buffer, (unsigned char *)"", 0x9fffffff);
	CuAssertTrue (tc, _p11_buffer_failed (&buffer));

	/* Force write a too long byte arary to buffer */
	_p11_buffer_reset (&buffer);
	_p11_buffer_add_uint32 (&buffer, 0x9fffffff);

	ret = _p11_buffer_get_byte_array (&buffer.buf, 0, &next, &val, &length);
	CuAssertIntEquals (tc, 0, ret);
	CuAssertIntEquals (tc, ~0, next);
	CuAssertIntEquals (tc, ~0, length);
	CuAssertPtrEquals (tc, NULL, (void*)val);

	_p11_buffer_uninit (&buffer);
}

static void
test_byte_array_static (CuTest *tc)
{
	unsigned char data[] = { 'p', 'a', 'd', 0x00, 0x00, 0x00, 0x00, 0x20,
	                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	                         0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
	P11Buffer buf = { data, 0x40, 0, NULL };
	const unsigned char *val;
	size_t length = ~0;
	size_t next = ~0;
	int ret;

	ret = _p11_buffer_get_byte_array (&buf, 4, &next, &val, &length);
	CuAssertIntEquals (tc, 1, ret);
	CuAssertIntEquals (tc, 40, next);
	CuAssertIntEquals (tc, 32, length);
	CuAssertTrue (tc, memcmp (data + 8, val, 32) == 0);
}

int
main (void)
{
	CuString *output = CuStringNew ();
	CuSuite* suite = CuSuiteNew ();
	int ret;

	setenv ("P11_KIT_STRICT", "1", 1);
	_p11_debug_init ();

	SUITE_ADD_TEST (suite, test_init_uninit);
	SUITE_ADD_TEST (suite, test_init_for_data);
	SUITE_ADD_TEST (suite, test_reserve);
	SUITE_ADD_TEST (suite, test_new_free);
	SUITE_ADD_TEST (suite, test_reset);
	SUITE_ADD_TEST (suite, test_append);
	SUITE_ADD_TEST (suite, test_byte);
	SUITE_ADD_TEST (suite, test_byte_static);
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

	CuSuiteRun (suite);
	CuSuiteSummary (suite, output);
	CuSuiteDetails (suite, output);
	printf ("%s\n", output->buffer);
	ret = suite->failCount;
	CuSuiteDelete (suite);
	CuStringDelete (output);

	return ret;
}
