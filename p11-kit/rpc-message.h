/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2012 Red Hat Inc.
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

#ifndef _RPC_MESSAGE_H
#define _RPC_MESSAGE_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include "buffer.h"
#include "pkcs11.h"

/* The calls, must be in sync with array below */
enum {
	RPC_CALL_ERROR = 0,

	RPC_CALL_C_Initialize,
	RPC_CALL_C_Finalize,
	RPC_CALL_C_GetInfo,
	RPC_CALL_C_GetSlotList,
	RPC_CALL_C_GetSlotInfo,
	RPC_CALL_C_GetTokenInfo,
	RPC_CALL_C_GetMechanismList,
	RPC_CALL_C_GetMechanismInfo,
	RPC_CALL_C_InitToken,
	RPC_CALL_C_OpenSession,
	RPC_CALL_C_CloseSession,
	RPC_CALL_C_CloseAllSessions,
	RPC_CALL_C_GetSessionInfo,
	RPC_CALL_C_InitPIN,
	RPC_CALL_C_SetPIN,
	RPC_CALL_C_GetOperationState,
	RPC_CALL_C_SetOperationState,
	RPC_CALL_C_Login,
	RPC_CALL_C_Logout,
	RPC_CALL_C_CreateObject,
	RPC_CALL_C_CopyObject,
	RPC_CALL_C_DestroyObject,
	RPC_CALL_C_GetObjectSize,
	RPC_CALL_C_GetAttributeValue,
	RPC_CALL_C_SetAttributeValue,
	RPC_CALL_C_FindObjectsInit,
	RPC_CALL_C_FindObjects,
	RPC_CALL_C_FindObjectsFinal,
	RPC_CALL_C_EncryptInit,
	RPC_CALL_C_Encrypt,
	RPC_CALL_C_EncryptUpdate,
	RPC_CALL_C_EncryptFinal,
	RPC_CALL_C_DecryptInit,
	RPC_CALL_C_Decrypt,
	RPC_CALL_C_DecryptUpdate,
	RPC_CALL_C_DecryptFinal,
	RPC_CALL_C_DigestInit,
	RPC_CALL_C_Digest,
	RPC_CALL_C_DigestUpdate,
	RPC_CALL_C_DigestKey,
	RPC_CALL_C_DigestFinal,
	RPC_CALL_C_SignInit,
	RPC_CALL_C_Sign,
	RPC_CALL_C_SignUpdate,
	RPC_CALL_C_SignFinal,
	RPC_CALL_C_SignRecoverInit,
	RPC_CALL_C_SignRecover,
	RPC_CALL_C_VerifyInit,
	RPC_CALL_C_Verify,
	RPC_CALL_C_VerifyUpdate,
	RPC_CALL_C_VerifyFinal,
	RPC_CALL_C_VerifyRecoverInit,
	RPC_CALL_C_VerifyRecover,
	RPC_CALL_C_DigestEncryptUpdate,
	RPC_CALL_C_DecryptDigestUpdate,
	RPC_CALL_C_SignEncryptUpdate,
	RPC_CALL_C_DecryptVerifyUpdate,
	RPC_CALL_C_GenerateKey,
	RPC_CALL_C_GenerateKeyPair,
	RPC_CALL_C_WrapKey,
	RPC_CALL_C_UnwrapKey,
	RPC_CALL_C_DeriveKey,
	RPC_CALL_C_SeedRandom,
	RPC_CALL_C_GenerateRandom,
	RPC_CALL_C_WaitForSlotEvent,

	RPC_CALL_MAX
};

typedef struct _RpcCall {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} RpcCall;

/*
 *  a_ = prefix denotes array of _
 *  A  = CK_ATTRIBUTE
 *  f_ = prefix denotes buffer for _
 *  M  = CK_MECHANISM
 *  u  = CK_ULONG
 *  s  = space padded string
 *  v  = CK_VERSION
 *  y  = CK_BYTE
 *  z  = null terminated string
 */

static const RpcCall rpc_calls[] = {
	{ RPC_CALL_ERROR,                  "ERROR",                  NULL,      "u"                    },
	{ RPC_CALL_C_Initialize,           "C_Initialize",           "ay",      ""                     },
	{ RPC_CALL_C_Finalize,             "C_Finalize",             "",        ""                     },
	{ RPC_CALL_C_GetInfo,              "C_GetInfo",              "",        "vsusv"                },
	{ RPC_CALL_C_GetSlotList,          "C_GetSlotList",          "yfu",     "au"                   },
	{ RPC_CALL_C_GetSlotInfo,          "C_GetSlotInfo",          "u",       "ssuvv"                },
	{ RPC_CALL_C_GetTokenInfo,         "C_GetTokenInfo",         "u",       "ssssuuuuuuuuuuuvvs"   },
	{ RPC_CALL_C_GetMechanismList,     "C_GetMechanismList",     "ufu",     "au"                   },
	{ RPC_CALL_C_GetMechanismInfo,     "C_GetMechanismInfo",     "uu",      "uuu"                  },
	{ RPC_CALL_C_InitToken,            "C_InitToken",            "uayz",    ""                     },
	{ RPC_CALL_C_OpenSession,          "C_OpenSession",          "uu",      "u"                    },
	{ RPC_CALL_C_CloseSession,         "C_CloseSession",         "u",       ""                     },
	{ RPC_CALL_C_CloseAllSessions,     "C_CloseAllSessions",     "u",       ""                     },
	{ RPC_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "u",       "uuuu"                 },
	{ RPC_CALL_C_InitPIN,              "C_InitPIN",              "uay",     ""                     },
	{ RPC_CALL_C_SetPIN,               "C_SetPIN",               "uayay",   ""                     },
	{ RPC_CALL_C_GetOperationState,    "C_GetOperationState",    "ufy",     "ay"                   },
	{ RPC_CALL_C_SetOperationState,    "C_SetOperationState",    "uayuu",   ""                     },
	{ RPC_CALL_C_Login,                "C_Login",                "uuay",    ""                     },
	{ RPC_CALL_C_Logout,               "C_Logout",               "u",       ""                     },
	{ RPC_CALL_C_CreateObject,         "C_CreateObject",         "uaA",     "u"                    },
	{ RPC_CALL_C_CopyObject,           "C_CopyObject",           "uuaA",    "u"                    },
	{ RPC_CALL_C_DestroyObject,        "C_DestroyObject",        "uu",      ""                     },
	{ RPC_CALL_C_GetObjectSize,        "C_GetObjectSize",        "uu",      "u"                    },
	{ RPC_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uufA",    "aAu"                  },
	{ RPC_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "uuaA",    ""                     },
	{ RPC_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "uaA",     ""                     },
	{ RPC_CALL_C_FindObjects,          "C_FindObjects",          "ufu",     "au"                   },
	{ RPC_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "u",       ""                     },
	{ RPC_CALL_C_EncryptInit,          "C_EncryptInit",          "uMu",     ""                     },
	{ RPC_CALL_C_Encrypt,              "C_Encrypt",              "uayfy",   "ay"                   },
	{ RPC_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_EncryptFinal,         "C_EncryptFinal",         "ufy",     "ay"                   },
	{ RPC_CALL_C_DecryptInit,          "C_DecryptInit",          "uMu",     ""                     },
	{ RPC_CALL_C_Decrypt,              "C_Decrypt",              "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptFinal,         "C_DecryptFinal",         "ufy",     "ay"                   },
	{ RPC_CALL_C_DigestInit,           "C_DigestInit",           "uM",      ""                     },
	{ RPC_CALL_C_Digest,               "C_Digest",               "uayfy",   "ay"                   },
	{ RPC_CALL_C_DigestUpdate,         "C_DigestUpdate",         "uay",     ""                     },
	{ RPC_CALL_C_DigestKey,            "C_DigestKey",            "uu",      ""                     },
	{ RPC_CALL_C_DigestFinal,          "C_DigestFinal",          "ufy",     "ay"                   },
	{ RPC_CALL_C_SignInit,             "C_SignInit",             "uMu",     ""                     },
	{ RPC_CALL_C_Sign,                 "C_Sign",                 "uayfy",   "ay"                   },
	{ RPC_CALL_C_SignUpdate,           "C_SignUpdate",           "uay",     ""                     },
	{ RPC_CALL_C_SignFinal,            "C_SignFinal",            "ufy",     "ay"                   },
	{ RPC_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "uMu",     ""                     },
	{ RPC_CALL_C_SignRecover,          "C_SignRecover",          "uayfy",   "ay"                   },
	{ RPC_CALL_C_VerifyInit,           "C_VerifyInit",           "uMu",     ""                     },
	{ RPC_CALL_C_Verify,               "C_Verify",               "uayay",   ""                     },
	{ RPC_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "uay",     ""                     },
	{ RPC_CALL_C_VerifyFinal,          "C_VerifyFinal",          "uay",     ""                     },
	{ RPC_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "uMu",     ""                     },
	{ RPC_CALL_C_VerifyRecover,        "C_VerifyRecover",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_GenerateKey,          "C_GenerateKey",          "uMaA",    "u"                    },
	{ RPC_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "uMaAaA",  "uu"                   },
	{ RPC_CALL_C_WrapKey,              "C_WrapKey",              "uMuufy",  "ay"                   },
	{ RPC_CALL_C_UnwrapKey,            "C_UnwrapKey",            "uMuayaA", "u"                    },
	{ RPC_CALL_C_DeriveKey,            "C_DeriveKey",            "uMuaA",   "u"                    },
	{ RPC_CALL_C_SeedRandom,           "C_SeedRandom",           "uay",     ""                     },
	{ RPC_CALL_C_GenerateRandom,       "C_GenerateRandom",       "ufy",     "ay"                   },
	{ RPC_CALL_C_WaitForSlotEvent,     "C_WaitForSlotEvent",     "u",       "u"                    },
};

#ifdef _DEBUG
#define RPC_CHECK_CALLS() \
	{ int i; for (i = 0; i < RPC_CALL_MAX; ++i) assert (rpc_calls[i].call_id == i); }
#endif

#define RPC_HANDSHAKE \
	((unsigned char *)"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1")
#define RPC_HANDSHAKE_LEN \
	(strlen ((char *)RPC_HANDSHAKE))

typedef enum _p11_rpc_message_type {
	RPC_REQUEST = 1,
	RPC_RESPONSE
} p11_rpc_message_type;

typedef struct _p11_rpc_message {
	int call_id;
	p11_rpc_message_type call_type;
	const char *signature;
	p11_buffer *input;
	p11_buffer *output;
	size_t parsed;
	const char *sigverify;
	void *extra;
} p11_rpc_message;

void             p11_rpc_message_init                    (p11_rpc_message *msg,
                                                          p11_buffer *input,
                                                          p11_buffer *output);

void             p11_rpc_message_clear                   (p11_rpc_message *msg);

#define          p11_rpc_message_is_verified(msg)        (!(msg)->sigverify || (msg)->sigverify[0] == 0)

void *           p11_rpc_message_alloc_extra             (p11_rpc_message *msg,
                                                          size_t length);

bool             p11_rpc_message_prep                    (p11_rpc_message *msg,
                                                          int call_id,
                                                          p11_rpc_message_type type);

bool             p11_rpc_message_parse                   (p11_rpc_message *msg,
                                                          p11_rpc_message_type type);

bool             p11_rpc_message_verify_part             (p11_rpc_message *msg,
                                                          const char* part);

bool             p11_rpc_message_write_byte              (p11_rpc_message *msg,
                                                          CK_BYTE val);

bool             p11_rpc_message_write_ulong             (p11_rpc_message *msg,
                                                          CK_ULONG val);

bool             p11_rpc_message_write_zero_string       (p11_rpc_message *msg,
                                                          CK_UTF8CHAR *string);

bool             p11_rpc_message_write_space_string      (p11_rpc_message *msg,
                                                          CK_UTF8CHAR *buffer,
                                                                   CK_ULONG length);

bool             p11_rpc_message_write_byte_buffer       (p11_rpc_message *msg,
                                                          CK_ULONG count);

bool             p11_rpc_message_write_byte_array        (p11_rpc_message *msg,
                                                          CK_BYTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_ulong_buffer      (p11_rpc_message *msg,
                                                          CK_ULONG count);

bool             p11_rpc_message_write_ulong_array       (p11_rpc_message *msg,
                                                          CK_ULONG_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_attribute_buffer  (p11_rpc_message *msg,
                                                          CK_ATTRIBUTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_attribute_array   (p11_rpc_message *msg,
                                                          CK_ATTRIBUTE_PTR arr,
                                                          CK_ULONG num);

bool             p11_rpc_message_write_version           (p11_rpc_message *msg,
                                                          CK_VERSION* version);

bool             p11_rpc_message_read_byte               (p11_rpc_message *msg,
                                                          CK_BYTE* val);

bool             p11_rpc_message_read_ulong              (p11_rpc_message *msg,
                                                          CK_ULONG* val);

bool             p11_rpc_message_read_space_string       (p11_rpc_message *msg,
                                                          CK_UTF8CHAR* buffer,
                                                          CK_ULONG length);

bool             p11_rpc_message_read_version            (p11_rpc_message *msg,
                                                          CK_VERSION* version);

p11_buffer *     p11_rpc_buffer_new                      (size_t reserve);

p11_buffer *     p11_rpc_buffer_new_full                 (size_t reserve,
                                                          void * (* frealloc) (void *data, size_t size),
                                                          void (* ffree) (void *data));

void             p11_rpc_buffer_free                     (p11_buffer *buf);

void             p11_rpc_buffer_add_byte                 (p11_buffer *buf,
                                                          unsigned char value);

int              p11_rpc_buffer_get_byte                 (p11_buffer *buf,
                                                          size_t *offset,
                                                          unsigned char *val);

void             p11_rpc_buffer_encode_uint32            (unsigned char *data,
                                                          uint32_t value);

uint32_t         p11_rpc_buffer_decode_uint32            (unsigned char *data);

void             p11_rpc_buffer_add_uint32               (p11_buffer *buffer,
                                                          uint32_t value);

bool             p11_rpc_buffer_set_uint32               (p11_buffer *buffer,
                                                          size_t offset,
                                                          uint32_t value);

bool             p11_rpc_buffer_get_uint32               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint32_t *value);

void             p11_rpc_buffer_encode_uint16            (unsigned char *data,
                                                          uint16_t value);

uint16_t         p11_rpc_buffer_decode_uint16            (unsigned char *data);

void             p11_rpc_buffer_add_uint16               (p11_buffer *buffer,
                                                          uint16_t val);

bool             p11_rpc_buffer_set_uint16               (p11_buffer *buffer,
                                                          size_t offset,
                                                          uint16_t val);

bool             p11_rpc_buffer_get_uint16               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint16_t *val);

void             p11_rpc_buffer_add_byte_array           (p11_buffer *buffer,
                                                          const unsigned char *val,
                                                          size_t len);

bool             p11_rpc_buffer_get_byte_array           (p11_buffer *buf,
                                                          size_t *offset,
                                                          const unsigned char **val,
                                                          size_t *vlen);

void             p11_rpc_buffer_add_uint64               (p11_buffer *buffer,
                                                          uint64_t val);

bool             p11_rpc_buffer_get_uint64               (p11_buffer *buf,
                                                          size_t *offset,
                                                          uint64_t *val);

#endif /* _RPC_MESSAGE_H */
