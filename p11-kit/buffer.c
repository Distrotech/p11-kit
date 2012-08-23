/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* buffer.c - Generic data buffer, used by openssh, gnome-keyring

   Copyright (C) 2007,2012 Stefan Walter

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stef@thewalter.net>
*/

#include "config.h"

#include "buffer.h"
#include "debug.h"

#include <assert.h>
#include <string.h>
#include <stdarg.h>

/**
 * P11Buffer:
 * @data: the buffer data
 * @length: the buffer length
 * @flags: additional flags
 * @private: reserved private data
 *
 * A buffer for reading and writing a block of data. These are used for use
 * with the RPC code.
 *
 * Read only buffers can be allocated on the stack or by the caller. The @flags
 * and @private variables must be initialized to zero and null respectively.
 *
 * Readable and writable buffers are allocated using p11_buffer_new(). It is
 * an error to pass a read only or caller allocated buffer to a function that
 * requires a writable buffer.
 */

/* Allocator for call session buffers */
static void *
log_allocator (void *pointer,
               size_t size)
{
	void *result = realloc (pointer, (size_t)size);
	if (!result && size)
		_p11_debug_precond ("memory allocation of %lu bytes failed", size);
	return result;
}

/**
 * p11_buffer_new:
 * @reserve: amount of preallocated data space in bytes
 *
 * Create a new readable and writable buffer. Readonly buffers can also
 * be allocated by the caller on stack.
 *
 * If @reserve is non-zero then that number of bytes will be allocated and
 * set in the data field of the resulting buffer. This can be used to reserve
 * space to write data into the buffer.
 *
 * The length field of the buffer will always be zero when returned from
 * this buffer.
 *
 * Returns: a newly allocated readable and writable buffer
 */
P11Buffer *
p11_buffer_new (size_t reserve)
{
	return p11_buffer_new_full (reserve, log_allocator, free);
}

P11Buffer *
p11_buffer_new_full (size_t reserve,
                     void * (* frealloc) (void *data, size_t size),
                     void (* ffree) (void *data))
{
	P11Output *buffer;

	buffer = calloc (1, sizeof (P11Output));
	return_val_if_fail (buffer != NULL, NULL);

	_p11_buffer_init_full (buffer, NULL, 0, frealloc, ffree);
	if (!_p11_buffer_reserve (buffer, reserve))
		return_val_if_reached (NULL);

	return &buffer->buf;
}

/**
 * p11_buffer_reset:
 * @buf: the buffer
 * @reserve: amount of preallocated data space in bytes
 *
 * Reset the buffer, and optionally reallocate the number of bytes in the
 * buffer. The length and flags fields of the buffer will be zet to zero.
 *
 * Returns: negative if failed
 */
int
p11_buffer_reset (P11Buffer *buf,
                  size_t reserve)
{
	P11Output *buffer;

	buffer = _p11_buffer_to_output (buf);
	if (buffer == NULL)
		return -1;
	return _p11_buffer_reserve (buffer, reserve) ? 0 : -1;
}

int
_p11_buffer_init (P11Output *buffer,
                  size_t reserve)
{
	_p11_buffer_init_full (buffer, NULL, 0, realloc, free);
	return _p11_buffer_reserve (buffer, reserve);
}

void
_p11_buffer_init_full (P11Output *buffer,
                       unsigned char *data,
                       size_t length,
                       void * (* frealloc) (void *data, size_t size),
                       void (* ffree) (void *data))
{
	memset (buffer, 0, sizeof (*buffer));

	buffer->buf.private = buffer;
	buffer->buf.data = data;
	buffer->buf.length = length;
	buffer->allocated = length;
	buffer->frealloc = frealloc;
	buffer->ffree = ffree;
}

void
_p11_buffer_uninit (P11Output *buffer)
{
	return_if_fail (buffer != NULL);

	if (buffer->buf.data && buffer->buf.length)
		memset (buffer->buf.data, 0, buffer->buf.length);
	if (buffer->ffree)
		(buffer->ffree) (buffer->buf.data);
	memset (buffer, 0, sizeof (*buffer));
}

/**
 * p11_buffer_free:
 * @buf: the buffer to free
 *
 * Free a buffer allocated with p11_buffer_new().
 *
 * If @buf is %NULL, then nothing happens.
 */
void
p11_buffer_free (P11Buffer *buf)
{
	P11Output *buffer;

	if (buf == NULL)
		return;

	buffer = _p11_buffer_to_output (buf);
	if (buffer) {
		_p11_buffer_uninit (buffer);
		free (buf);
	}
}

void
_p11_buffer_reset (P11Output *buffer)
{
	buffer->buf.flags &= ~P11_BUFFER_FAILED;
	buffer->buf.length = 0;
}

int
_p11_buffer_reserve (P11Output *buffer,
                     size_t reserve)
{
	unsigned char *newbuf;
	size_t newlen;

	return_val_if_fail (!_p11_buffer_failed (buffer), 0);

	if (reserve < buffer->allocated)
		return 1;

	/* Calculate a new length, minimize number of buffer allocations */
	newlen = buffer->allocated * 2;
	if (reserve > newlen)
		newlen += reserve;

	/* Memory owned elsewhere can't be reallocated */
	return_val_if_fail (buffer->frealloc != NULL, 0);

	/* Reallocate built in buffer using allocator */
	newbuf = (buffer->frealloc) (buffer->buf.data, newlen);
	if (!newbuf) {
		_p11_buffer_fail (buffer);
		return_val_if_reached (0);
	}

	buffer->buf.data = newbuf;
	buffer->allocated = newlen;
	return 1;
}

void
_p11_buffer_append (P11Output *buffer,
                    const unsigned char *data,
                    size_t length)
{
	if (!_p11_buffer_reserve (buffer, buffer->buf.length + length))
		return_if_reached ();
	memcpy (buffer->buf.data + buffer->buf.length, data, length);
	buffer->buf.length += length;
}

void
_p11_buffer_add_byte (P11Output *buffer,
                      unsigned char value)
{
	if (!_p11_buffer_reserve (buffer, buffer->buf.length + 1))
		return_if_reached();
	buffer->buf.data[buffer->buf.length] = value;
	buffer->buf.length++;
}

int
_p11_buffer_get_byte (P11Buffer *buf,
                      size_t offset,
                      size_t *next_offset,
                      unsigned char *val)
{
	unsigned char *ptr;
	if (buf->length < 1 || offset > buf->length - 1) {
		_p11_buffer_fail (buf);
		return 0;
	}
	ptr = (unsigned char *)buf->data + offset;
	if (val != NULL)
		*val = *ptr;
	if (next_offset != NULL)
		*next_offset = offset + 1;
	return 1;
}

void
_p11_buffer_encode_uint16 (unsigned char* data,
                           uint16_t value)
{
	data[0] = (value >> 8) & 0xff;
	data[1] = (value >> 0) & 0xff;
}

uint16_t
_p11_buffer_decode_uint16 (unsigned char* data)
{
	uint16_t value = data[0] << 8 | data[1];
	return value;
}

void
_p11_buffer_add_uint16 (P11Output *buffer,
                        uint16_t value)
{
	size_t offset;
	if (!_p11_buffer_reserve (buffer, buffer->buf.length + 2))
		return_if_reached();
	offset = buffer->buf.length;
	buffer->buf.length += 2;
	_p11_buffer_set_uint16 (buffer, offset, value);
}

int
_p11_buffer_set_uint16 (P11Output *buffer,
                        size_t offset,
                        uint16_t value)
{
	unsigned char *ptr;
	if (buffer->buf.length < 2 || offset > buffer->buf.length - 2) {
		_p11_buffer_fail (buffer);
		return 0;
	}
	ptr = (unsigned char*)buffer->buf.data + offset;
	_p11_buffer_encode_uint16 (ptr, value);
	return 1;
}

int
_p11_buffer_get_uint16 (P11Buffer *buf,
                        size_t offset,
                        size_t *next_offset,
                        uint16_t *value)
{
	unsigned char *ptr;
	if (buf->length < 2 || offset > buf->length - 2) {
		_p11_buffer_fail (buf);
		return 0;
	}
	ptr = (unsigned char*)buf->data + offset;
	if (value != NULL)
		*value = _p11_buffer_decode_uint16 (ptr);
	if (next_offset != NULL)
		*next_offset = offset + 2;
	return 1;
}

void
_p11_buffer_encode_uint32 (unsigned char* data,
                           uint32_t value)
{
	data[0] = (value >> 24) & 0xff;
	data[1] = (value >> 16) & 0xff;
	data[2] = (value >> 8) & 0xff;
	data[3] = (value >> 0) & 0xff;
}

uint32_t
_p11_buffer_decode_uint32 (unsigned char* ptr)
{
	uint32_t val = ptr[0] << 24 | ptr[1] << 16 | ptr[2] << 8 | ptr[3];
	return val;
}

void
_p11_buffer_add_uint32 (P11Output *buffer,
                        uint32_t value)
{
	size_t offset;
	if (_p11_buffer_reserve (buffer, buffer->buf.length + 4) < 0)
		return;
	offset = buffer->buf.length;
	buffer->buf.length += 4;
	_p11_buffer_set_uint32 (buffer, offset, value);
}

int
_p11_buffer_set_uint32 (P11Output *buffer,
                        size_t offset,
                        uint32_t value)
{
	unsigned char *ptr;
	if (buffer->buf.length < 4 || offset > buffer->buf.length - 4) {
		_p11_buffer_fail (buffer);
		return 0;
	}
	ptr = (unsigned char*)buffer->buf.data + offset;
	_p11_buffer_encode_uint32 (ptr, value);
	return 1;
}

int
_p11_buffer_get_uint32 (P11Buffer *buf,
                        size_t offset,
                        size_t *next_offset,
                        uint32_t *value)
{
	unsigned char *ptr;
	if (buf->length < 4 || offset > buf->length - 4) {
		_p11_buffer_fail (buf);
		return 0;
	}
	ptr = (unsigned char*)buf->data + offset;
	if (value != NULL)
		*value = _p11_buffer_decode_uint32 (ptr);
	if (next_offset != NULL)
		*next_offset = offset + 4;
	return 1;
}

void
_p11_buffer_add_uint64 (P11Output *buffer,
                        uint64_t value)
{
	_p11_buffer_add_uint32 (buffer, ((value >> 32) & 0xffffffff));
	_p11_buffer_add_uint32 (buffer, (value & 0xffffffff));
}

int
_p11_buffer_get_uint64 (P11Buffer *buf,
                        size_t offset,
                        size_t *next_offset,
                        uint64_t *value)
{
	uint32_t a, b;
	if (!_p11_buffer_get_uint32 (buf, offset, &offset, &a) ||
	    !_p11_buffer_get_uint32 (buf, offset, &offset, &b))
		return 0;
	if (value != NULL)
		*value = ((uint64_t)a) << 32 | b;
	if (next_offset != NULL)
		*next_offset = offset;
	return 1;
}

void
_p11_buffer_add_byte_array (P11Output *buffer,
                            const unsigned char *data,
                            size_t length)
{
	if (data == NULL) {
		_p11_buffer_add_uint32 (buffer, 0xffffffff);
		return;
	} else if (length >= 0x7fffffff) {
		_p11_buffer_fail (buffer);
		return;
	}
	_p11_buffer_add_uint32 (buffer, length);
	_p11_buffer_append (buffer, data, length);
}

int
_p11_buffer_get_byte_array (P11Buffer *buf,
                            size_t offset,
                            size_t *next_offset,
                            const unsigned char **data,
                            size_t *length)
{
	uint32_t len;
	if (!_p11_buffer_get_uint32 (buf, offset, &offset, &len))
		return 0;
	if (len == 0xffffffff) {
		if (next_offset)
			*next_offset = offset;
		if (data)
			*data = NULL;
		if (length)
			*length = 0;
		return 1;
	} else if (len >= 0x7fffffff) {
		_p11_buffer_fail (buf);
		return 0;
	}

	if (buf->length < len || offset > buf->length - len) {
		_p11_buffer_fail (buf);
		return 0;
	}

	if (data)
		*data = buf->data + offset;
	if (length)
		*length = len;
	if (next_offset)
		*next_offset = offset + len;

	return 1;
}

P11Output *
_p11_buffer_cast_to_output (P11Buffer *buf,
                            const char *caller_func_name)
{
	if (buf->private == (void *)buf)
		return buf->private;

	_p11_debug_precond ("p11-kit: a static or caller-allocated P11Buffer structure "
	                    "was passed to a function that requires a dynamically allocated "
	                    "structure allocated with p11_buffer_new() or similar: %s",
	                    caller_func_name);
	return NULL;
}
