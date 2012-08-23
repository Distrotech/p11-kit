/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* buffer.h - Generic data buffer, used by openssh, gnome-keyring

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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdlib.h>
#include <stdint.h>

#include "rpc.h"

enum {
	P11_BUFFER_FAILED = 1 << 0,
};

typedef struct {
	P11Buffer buf;
	size_t allocated;
	void * (* frealloc) (void *data, size_t size);
	void (* ffree) (void *data);
} P11Output;

int             _p11_buffer_init             (P11Output *buffer,
                                              size_t reserve);

void            _p11_buffer_init_full        (P11Output *buffer,
                                              unsigned char *data,
                                              size_t length,
                                              void * (* frealloc) (void *data, size_t size),
                                              void (* ffree) (void *data));

void            _p11_buffer_uninit           (P11Output *buffer);

P11Output *     _p11_buffer_cast_to_output   (P11Buffer *buf,
                                              const char *caller_func_name);

void            _p11_buffer_reset            (P11Output *buffer);

int             _p11_buffer_reserve          (P11Output *buffer,
                                              size_t len);

void            _p11_buffer_append           (P11Output *buffer,
                                              const unsigned char *data,
                                              size_t length);

void            _p11_buffer_add_byte         (P11Output *buffer,
                                              unsigned char value);

int             _p11_buffer_get_byte         (P11Buffer *buf,
                                              size_t offset,
                                              size_t *next_offset,
                                              unsigned char *value);

void            _p11_buffer_encode_uint32    (unsigned char *data,
                                              uint32_t value);

uint32_t        _p11_buffer_decode_uint32    (unsigned char *data);

void            _p11_buffer_add_uint32       (P11Output *buffer,
                                              uint32_t value);

int             _p11_buffer_set_uint32       (P11Output *buffer,
                                              size_t offset,
                                              uint32_t value);

int             _p11_buffer_get_uint32       (P11Buffer *buf,
                                              size_t offset,
                                              size_t *next_offset,
                                              uint32_t *value);

void            _p11_buffer_encode_uint16    (unsigned char *data,
                                              uint16_t value);

uint16_t        _p11_buffer_decode_uint16    (unsigned char *data);

void            _p11_buffer_add_uint16       (P11Output *buffer,
                                              uint16_t val);

int             _p11_buffer_set_uint16       (P11Output *buffer,
                                              size_t offset,
                                              uint16_t val);

int             _p11_buffer_get_uint16       (P11Buffer *buf,
                                              size_t offset,
                                              size_t *next_offset,
                                              uint16_t *val);

void            _p11_buffer_add_byte_array   (P11Output *buffer,
                                              const unsigned char *val,
                                              size_t len);

int             _p11_buffer_get_byte_array   (P11Buffer *buf,
                                              size_t offset,
                                              size_t *next_offset,
                                              const unsigned char **val,
                                              size_t *vlen);

void            _p11_buffer_add_uint64       (P11Output *buffer,
                                              uint64_t val);

int             _p11_buffer_get_uint64       (P11Buffer *buf,
                                              size_t offset,
                                              size_t *next_offset,
                                              uint64_t *val);

#define         _p11_buffer_fail(buf) \
	(((P11Buffer *)(buf))->flags |= P11_BUFFER_FAILED)

#define         _p11_buffer_failed(buf) \
	(((P11Buffer *)(buf))->flags & P11_BUFFER_FAILED)

#define         _p11_buffer_to_output(buf) \
	_p11_buffer_cast_to_output ((buf), __func__)

#endif /* BUFFER_H */
