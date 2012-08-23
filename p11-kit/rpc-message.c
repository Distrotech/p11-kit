/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* p11-rpc-message.c - our marshalled PKCS#11 protocol.

   Copyright (C) 2008, Stef Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#include "config.h"

#include "debug.h"
#include "private.h"
#include "rpc-message.h"

#include <assert.h>
#include <string.h>

void
_p11_rpc_message_init (RpcMessage *msg,
                       P11Buffer *input,
                       P11Output *output)
{
	assert (input != NULL);
	assert (output != NULL);
	assert (output->ffree != NULL);
	assert (output->frealloc != NULL);

	memset (msg, 0, sizeof (*msg));

	msg->output = output;
	msg->input = input;
}

void
_p11_rpc_message_clear (RpcMessage *msg)
{
	void *allocated;
	void **data;

	assert (msg != NULL);

	/* Free up the extra allocated memory */
	allocated = msg->extra;
	while (allocated != NULL) {
		data = (void **)allocated;

		/* Pointer to the next allocation */
		allocated = *data;
		assert (msg->output->ffree);
		(msg->output->ffree) (data);
	}

	msg->output = NULL;
	msg->input = NULL;
	msg->extra = NULL;
}

void *
_p11_rpc_message_alloc_extra (RpcMessage *msg,
                              size_t length)
{
	void **data;

	assert (msg != NULL);

	if (length > 0x7fffffff)
		return NULL;

	assert (msg->output->frealloc != NULL);
	data = (msg->output->frealloc) (NULL, sizeof (void *) + length);
	if (data == NULL)
		return NULL;

	/* Munch up the memory to help catch bugs */
	memset (data, 0xff, sizeof (void *) + length);

	/* Store pointer to next allocated block at beginning */
	*data = msg->extra;
	msg->extra = data;

	/* Data starts after first pointer */
	return (void *)(data + 1);
}

int
_p11_rpc_message_prep (RpcMessage *msg,
                       int call_id,
                       RpcMessageType type)
{
	int len;

	assert (type != 0);
	assert (call_id >= RPC_CALL_ERROR);
	assert (call_id < RPC_CALL_MAX);

	_p11_buffer_reset (msg->output);
	msg->signature = NULL;

	/* The call id and signature */
	if (type == RPC_REQUEST)
		msg->signature = rpc_calls[call_id].request;
	else if (type == RPC_RESPONSE)
		msg->signature = rpc_calls[call_id].response;
	else
		assert_not_reached ();
	assert (msg->signature != NULL);
	msg->sigverify = msg->signature;

	msg->call_id = call_id;
	msg->call_type = type;

	/* Encode the two of them */
	_p11_buffer_add_uint32 (msg->output, call_id);
	if (msg->signature) {
		len = strlen (msg->signature);
		_p11_buffer_add_byte_array (msg->output, (unsigned char*)msg->signature, len);
	}

	msg->parsed = 0;
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_parse (RpcMessage *msg,
                        RpcMessageType type)
{
	const unsigned char *val;
	size_t len;
	uint32_t call_id;

	assert (msg != NULL);
	assert (msg->input != NULL);

	msg->parsed = 0;

	/* Pull out the call identifier */
	if (!_p11_buffer_get_uint32 (msg->input, msg->parsed, &(msg->parsed), &call_id)) {
		_p11_message ("invalid message: couldn't read call identifier");
		return 0;
	}

	msg->signature = msg->sigverify = NULL;

	/* The call id and signature */
	if (call_id < 0 || call_id >= RPC_CALL_MAX) {
		_p11_message ("invalid message: bad call id: %d", call_id);
		return 0;
	}
	if (type == RPC_REQUEST)
		msg->signature = rpc_calls[call_id].request;
	else if (type == RPC_RESPONSE)
		msg->signature = rpc_calls[call_id].response;
	else
		assert_not_reached ();
	assert (msg->signature != NULL);
	msg->call_id = call_id;
	msg->call_type = type;
	msg->sigverify = msg->signature;

	/* Verify the incoming signature */
	if (!_p11_buffer_get_byte_array (msg->input, msg->parsed, &(msg->parsed), &val, &len)) {
		_p11_message ("invalid message: couldn't read signature");
		return 0;
	}

	if ((strlen (msg->signature) != len) || (memcmp (val, msg->signature, len) != 0)) {
		_p11_message ("invalid message: signature doesn't match");
		return 0;
	}

	return 1;
}

int
_p11_rpc_message_verify_part (RpcMessage *msg,
                              const char* part)
{
	int len, ok;

	if (!msg->sigverify)
		return 1;

	len = strlen (part);
	ok = (strncmp (msg->sigverify, part, len) == 0);
	if (ok)
		msg->sigverify += len;
	return ok;
}

int
_p11_rpc_message_write_attribute_buffer (RpcMessage *msg,
                                         CK_ATTRIBUTE_PTR arr,
                                         CK_ULONG num)
{
	CK_ATTRIBUTE_PTR attr;
	CK_ULONG i;

	assert (num == 0 || arr != NULL);
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fA"));

	/* Write the number of items */
	_p11_buffer_add_uint32 (msg->output, num);

	for (i = 0; i < num; ++i) {
		attr = &(arr[i]);

		/* The attribute type */
		_p11_buffer_add_uint32 (msg->output, attr->type);

		/* And the attribute buffer length */
		_p11_buffer_add_uint32 (msg->output, attr->pValue ? attr->ulValueLen : 0);
	}

	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_attribute_array (RpcMessage *msg,
                                        CK_ATTRIBUTE_PTR arr,
                                        CK_ULONG num)
{
	CK_ULONG i;
	CK_ATTRIBUTE_PTR attr;
	unsigned char validity;

	assert (num == 0 || arr != NULL);
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "aA"));

	/* Write the number of items */
	_p11_buffer_add_uint32 (msg->output, num);

	for (i = 0; i < num; ++i) {
		attr = &(arr[i]);

		/* The attribute type */
		_p11_buffer_add_uint32 (msg->output, attr->type);

		/* Write out the attribute validity */
		validity = (((CK_LONG)attr->ulValueLen) == -1) ? 0 : 1;
		_p11_buffer_add_byte (msg->output, validity);

		/* The attribute length and value */
		if (validity) {
			_p11_buffer_add_uint32 (msg->output, attr->ulValueLen);
			_p11_buffer_add_byte_array (msg->output, attr->pValue, attr->ulValueLen);
		}
	}

	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_read_byte (RpcMessage *msg,
                            CK_BYTE *val)
{
	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "y"));
	return _p11_buffer_get_byte (msg->input, msg->parsed, &msg->parsed, val);
}

int
_p11_rpc_message_write_byte (RpcMessage *msg,
                             CK_BYTE val)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "y"));
	_p11_buffer_add_byte (msg->output, val);
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_read_ulong (RpcMessage *msg,
                             CK_ULONG *val)
{
	uint64_t v;

	assert (msg != NULL);
	assert (msg->input != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "u"));

	if (!_p11_buffer_get_uint64 (msg->input, msg->parsed, &msg->parsed, &v))
		return 0;
	if (val)
		*val = (CK_ULONG)v;
	return 1;
}

int
_p11_rpc_message_write_ulong (RpcMessage *msg,
                              CK_ULONG val)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "u"));
	_p11_buffer_add_uint64 (msg->output, val);
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_byte_buffer (RpcMessage *msg,
                                    CK_ULONG count)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fy"));
	_p11_buffer_add_uint32 (msg->output, count);
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_byte_array (RpcMessage *msg,
                                   CK_BYTE_PTR arr,
                                   CK_ULONG num)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "ay"));

	/* No array, no data, just length */
	if (!arr) {
		_p11_buffer_add_byte (msg->output, 0);
		_p11_buffer_add_uint32 (msg->output, num);
	} else {
		_p11_buffer_add_byte (msg->output, 1);
		_p11_buffer_add_byte_array (msg->output, arr, num);
	}

	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_ulong_buffer (RpcMessage *msg,
                                     CK_ULONG count)
{
	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fu"));
	_p11_buffer_add_uint32 (msg->output, count);
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_ulong_array (RpcMessage *msg,
                                    CK_ULONG_PTR array,
                                    CK_ULONG n_array)
{
	CK_ULONG i;

	assert (msg != NULL);
	assert (msg->output != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "au"));

	/* We send a byte which determines whether there's actual data present or not */
	_p11_buffer_add_byte (msg->output, array ? 1 : 0);
	_p11_buffer_add_uint32 (msg->output, n_array);

	/* Now send the data if valid */
	if (array) {
		for (i = 0; i < n_array; ++i)
			_p11_buffer_add_uint64 (msg->output, array[i]);
	}

	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_read_version (RpcMessage *msg,
                               CK_VERSION *version)
{
	assert (msg != NULL);
	assert (msg->input != NULL);
	assert (version != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "v"));

	return _p11_buffer_get_byte (msg->input, msg->parsed, &msg->parsed, &version->major) &&
	       _p11_buffer_get_byte (msg->input, msg->parsed, &msg->parsed, &version->minor);
}

int
_p11_rpc_message_write_version (RpcMessage *msg,
                                CK_VERSION *version)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (version != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "v"));

	_p11_buffer_add_byte (msg->output, version->major);
	_p11_buffer_add_byte (msg->output, version->minor);

	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_read_space_string (RpcMessage *msg,
                                    CK_UTF8CHAR *buffer,
                                    CK_ULONG length)
{
	const unsigned char *data;
	size_t n_data;

	assert (msg != NULL);
	assert (msg->input != NULL);
	assert (buffer != NULL);
	assert (length != 0);

	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "s"));

	if (!_p11_buffer_get_byte_array (msg->input, msg->parsed, &msg->parsed, &data, &n_data))
		return 0;

	if (n_data != length) {
		_p11_message ("invalid length space padded string received: %d != %d",
		              (int)length, (int)n_data);
		return 0;
	}

	memcpy (buffer, data, length);
	return 1;
}

int
_p11_rpc_message_write_space_string (RpcMessage *msg,
                                     CK_UTF8CHAR *data,
                                     CK_ULONG length)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (data != NULL);
	assert (length != 0);

	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "s"));

	_p11_buffer_add_byte_array (msg->output, data, length);
	return !_p11_buffer_failed (msg->output);
}

int
_p11_rpc_message_write_zero_string (RpcMessage *msg,
                                    CK_UTF8CHAR *string)
{
	assert (msg != NULL);
	assert (msg->output != NULL);
	assert (string != NULL);

	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "z"));

	_p11_buffer_add_byte_array (msg->output, string,
	                            string ? strlen ((char *)string) : 0);
	return !_p11_buffer_failed (msg->output);
}
