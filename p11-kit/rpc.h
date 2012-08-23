/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2012 Stefan Walter

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

   Author: Stef Walter <stefw@gnome.org>
*/

#ifndef __P11_KIT_RPC_H__
#define __P11_KIT_RPC_H__

#include "pkcs11.h"

typedef struct _P11Buffer P11Buffer;

struct _P11Buffer {
	unsigned char *data;
	size_t length;
	int flags;
	void *private;
};

P11Buffer *     p11_buffer_new              (size_t reserve);

P11Buffer *     p11_buffer_new_full         (size_t reserve,
                                             void * (* frealloc) (void *data, size_t size),
                                             void (* ffree) (void *data));

int             p11_buffer_reset            (P11Buffer *buf,
                                             size_t reserve);

void            p11_buffer_free             (P11Buffer *buf);

#endif /* __P11_KIT_RPC_H__ */
