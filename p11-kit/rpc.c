/*
 * Copyright (C) 2012 Stefan Walter
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "library.h"
#include "pkcs11.h"
#include "private.h"
#include "rpc.h"
#include "rpc-message.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct {
	int fd;
	int refs;
	int last_code;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int sent_creds;

	/* Filled in if a thread reads data it doesn't own */
	uint32_t header_len;
	uint32_t header_code;
} RpcSocket;

typedef struct {
	char *module_name;
	char *exec_line;
	RpcSocket *socket;
} RpcContext;

static void
rpc_socket_free (void *data)
{
	RpcSocket *sock = data;

	assert (sock != NULL);
	assert (sock->refs == 0);

	/* Free up resources */
	pthread_cond_destroy (&sock->cond);
	pthread_mutex_destroy (&sock->mutex);
	free (sock);
}

static RpcSocket *
rpc_socket_new (int fd)
{
	RpcSocket *sock;

	sock = calloc (1, sizeof (RpcSocket));
	if (sock == NULL)
		return NULL;

	sock->fd = fd;
	sock->last_code = 0x10;

	if (pthread_mutex_init (&sock->mutex, NULL) != 0) {
		free (sock);
		return NULL;
	}

	if (pthread_cond_init (&sock->cond, NULL) != 0) {
		pthread_mutex_destroy (&sock->mutex);
		free (sock);
		return NULL;
	}

	return sock;
}

static RpcSocket *
rpc_socket_ref (RpcSocket *sock)
{
	assert (sock != NULL);

	pthread_mutex_lock (&sock->mutex);
	sock->refs++;
	pthread_mutex_unlock (&sock->mutex);

	return sock;
}

static RpcSocket *
rpc_socket_open (int fd)
{
	RpcSocket *sock = NULL;

	sock = rpc_socket_new (fd);
	if (sock == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	return rpc_socket_ref (sock);
}

static int
rpc_socket_is_open (RpcSocket *sock)
{
	assert (sock != NULL);
	return sock->fd >= 0;
}


static void
rpc_socket_unref (RpcSocket *sock)
{
	int release = 0;

	assert (sock != NULL);

	/* Unreference the socket */
	pthread_mutex_lock (&sock->mutex);
	if (--sock->refs == 0)
		release = 1;
	pthread_mutex_unlock (&sock->mutex);

	if (release)
		rpc_socket_free (sock);
}

/* Write all data to session socket.  */
static int
write_all (int fd,
           unsigned char* data,
           size_t len)
{
	int r;

	assert (data != NULL);
	assert (len > 0);

	while (len > 0) {
		r = write (fd, data, len);
		if (r == -1) {
			if (errno == EPIPE) {
				p11_message ("couldn't send data: closed connection");
				return 0;
			} else if (errno != EAGAIN && errno != EINTR) {
				p11_message ("couldn't send data: %s", strerror (errno));
				return 0;
			}
		} else {
			p11_debug ("wrote %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return 1;
}

static CK_RV
read_all (int fd,
          unsigned char* data,
          size_t len)
{
	int r;

	assert (data != NULL);
	assert (len > 0);

	while (len > 0) {
		r = read (fd, data, len);
		if (r == 0) {
			p11_message ("couldn't receive data: closed connection");
			return 0;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				p11_message ("couldn't receive data: %s", strerror (errno));
				return 0;
			}
		} else {
			p11_debug ("read %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return 1;
}

static CK_RV
rpc_socket_write (RpcSocket *sock,
                  int call_code,
                  p11_buffer *buffer)
{
	unsigned char header[8];
	unsigned char dummy = '\0';

	/* The socket is locked and referenced at this point */
	assert (buffer != NULL);

	/* Place holder byte, will later carry unix credentials (on some systems) */
	if (!sock->sent_creds) {
		if (write_all (sock->fd, &dummy, 1) != 1) {
			p11_message ("couldn't send socket credentials: %s", strerror (errno));
			return CKR_DEVICE_ERROR;
		}
		sock->sent_creds = 1;
	}

	p11_rpc_buffer_encode_uint32 (header, buffer->len + 4);
	p11_rpc_buffer_encode_uint32 (header + 4, call_code);

	if (!write_all (sock->fd, header, 8) ||
	    !write_all (sock->fd, buffer->data, buffer->len))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static CK_RV
rpc_socket_read (RpcSocket *sock,
                 int call_code,
                 p11_buffer *buffer)
{
	unsigned char header[8];

	/* The socket is locked and referenced at this point */

	for (;;) {
		if (sock->header_code == 0) {
			if (!read_all (sock->fd, header, 8))
				return CKR_DEVICE_ERROR;

			sock->header_len = p11_rpc_buffer_decode_uint32 (header);
			sock->header_code = p11_rpc_buffer_decode_uint32 (header + 4);
			if (sock->header_code == 0 || sock->header_len < 4) {
				p11_message ("received invalid rpc header values: perhaps wrong protocol");
				return CKR_DEVICE_ERROR;
			}
		}

		/* Our header */
		if (sock->header_code == call_code) {
			if (!p11_buffer_reset (buffer, sock->header_len))
				return_val_if_reached (CKR_HOST_MEMORY);

			if (!read_all (sock->fd, buffer->data, sock->header_len))
				return CKR_DEVICE_ERROR;

			buffer->len = sock->header_len;

			/* Yay, we got our data, off we go */
			sock->header_code = 0;
			sock->header_len = 0;
			pthread_cond_broadcast (&sock->cond);
			return CKR_OK;
		}

		/* Wait until another thread reads the data for this header */
		if (sock->header_code != 0) {
			pthread_cond_broadcast (&sock->cond);

			if (pthread_cond_wait (&sock->cond, &sock->mutex) != 0)
				return CKR_DEVICE_ERROR;
		}
	}
}

static CK_RV
on_rpc_socket_transport (p11_rpc_client_vtable *vtable,
                         p11_buffer *request,
                         p11_buffer *response)
{
	RpcSocket *sock = vtable->data;
	CK_RV rv = CKR_OK;
	int call_code;

	assert (sock != NULL);
	assert (request != NULL);
	assert (response != NULL);

	pthread_mutex_lock (&sock->mutex);
	assert (sock->refs > 0);
	sock->refs++;

	/* Get the next socket reply code */
	call_code = sock->last_code++;

	if (sock->fd == -1)
		rv = CKR_DEVICE_ERROR;
	if (rv == CKR_OK)
		rv = rpc_socket_write (sock, call_code, request);
	if (rv == CKR_OK)
		rv = rpc_socket_read (sock, call_code, response);
	if (rv != CKR_OK && sock->fd != -1) {
		p11_message ("closing socket due to protocol failure");
		close (sock->fd);
		sock->fd = -1;
	}

	sock->refs--;
	assert (sock->refs > 0);
	pthread_mutex_unlock (&sock->mutex);

	return rv;
}

static void
on_rpc_disconnect (p11_rpc_client_vtable *vtable,
                   void *fini_reserved)
{
	rpc_socket_unref (vtable->data);

}

static int
set_cloexec_on_fd (void *data,
                   int fd)
{
	int *max_fd = data;
	if (fd >= *max_fd)
		fcntl (fd, F_SETFD, FD_CLOEXEC);
	return 0;
}

CK_RV
on_rpc_exec_initialize (p11_rpc_client_vtable *vtable,
                        void *init_reserved)
{
	RpcContext *rpc = (RpcContext *)vtable;
	pid_t pid;
	int max_fd;
	int fds[2];
	int errn;

	if (socketpair (AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		p11_message ("failed to create pipe for rpc: %s", strerror (errno));
		return CKR_DEVICE_ERROR;
	}

	pid = fork ();
	switch (pid) {

	/* Failure */
	case -1:
		close (fds[0]);
		close (fds[1]);
		p11_message ("failed to fork for rpc: %s",
		              strerror (errno));
		return CKR_DEVICE_ERROR;

	/* Child */
	case 0:
		if (dup2 (fds[1], STDIN_FILENO) < 0 ||
		    dup2 (fds[1], STDOUT_FILENO) < 0)
			p11_message ("couldn't dup file descriptors in rpc child: %s",
			              strerror (errno));
			_exit (2);
		}

		/* Close file descriptors, except for above on exec */
		max_fd = STDERR_FILENO;
		fdwalk (set_cloexec_on_fd, &max_fd);

		execv (rpc->command_line[0], rpc->command_line);

		errn = errno;
		p11_message ("couldn't execute program for rpc: %s", rpc->command_line[0]);
		_exit (errn);

	/* The parent */
	default:
		break;
	}

	close (fds[1]);

	xxx write credentials xxx

	rpc->socket = _p11_rpc_socket_open (fds[0]);

	xxx handle errors xxx;
	xxx;
}

RpcModule *
_p11_rpc_module_new_shared (const char *name)
{
	RpcModule *rpc;

	rpc = calloc (1, sizeof (RpcModule));
	if (rpc == NULL) {
		p11_message ("couldn't allocate new rpc module");
		return NULL;
	}

	rpc->vtable.initialize = on_shared_initialize;
	rpc->vtable.finalize = on_rpc_finalize;
	rpc->vtable.transport = on_rpc_transport;

	rpc->funcs = _p11_rpc_client_register (&rpc->vtable);
	if (rpc->funcs == NULL) {
		free (rpc);
		return NULL;
	}

	rpc->shared_name = strdup (name);
	return rpc;
}

CK_RV
on_rpc_exec_initialize (RpcClientVtable *vtable,
                        void *init_reserved)
{
	RpcModule *rpc = (RpcModule *)vtable;
	pid_t pid;
	int max_fd;
	int fds[2];
	int errn;

	sock = connect_to_or_start_xxx ();


	close (fds[1]);
	rpc->socket = _p11_rpc_socket_open (fds[0]);
	xxx handle errors xxx;
	xxx;
}

RpcModule *
_p11_rpc_module_new_exec (const char *command_line)
{
	RpcModule *rpc;

	rpc = calloc (1, sizeof (RpcModule));
	if (rpc == NULL) {
		p11_message ("couldn't allocate new rpc module");
		return NULL;
	}

	rpc->vtable.initialize = rpc_exec_initialize;
	rpc->vtable.finalize = rpc_exec_finalize;
	rpc->vtable.transport = rpc_transport;

	rpc->funcs = _p11_rpc_client_register (&rpc->vtable);
	if (rpc->funcs == NULL) {
		free (rpc);
		return NULL;
	}

	rpc->shared_name = strdup (name);
	return rpc;

}

CK_FUNCTION_LIST_PTR
_p11_rpc_module_get_functions (RpcModule *rpc)
{
	assert (rpc != NULL);
	return rpc->funcs;
}

void
_p11_rpc_module_destroy (void *data)
{
	RpcModule *rpc = data;

	_p11_rpc_client_unregister (&rpc->vtable);
	rpc_socket_unref (rpc->socket);
	free (rpc->shared_name);
	free (rpc->command_line);
	free (rpc);
}
