/* $Id: interface.c 220 2008-08-22 14:53:02Z roe $ */

#include <fpwchk/word.h>
#include "parse.h"
#include "key.h"
#include "strconv.h"
#include "debug.h"
#include "compat.h"

#include <wchar.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
	crypto_algo_e algo;
	size_t keybits;
	size_t maxkeybits;
	uint8_t salt[16];
	uint8_t ev[16];
	uint8_t evh[20];
	key_rc4basic_ctx_t *rc4basic;
	key_rc4capi_ctx_t *rc4capi;
} ctx_t; /* 48 bytes */

fpwchk_handle_t
fpwchk_word_create(FILE *f)
{
	ctx_t *ctx = (ctx_t*)malloc(sizeof(ctx_t));

	memset(ctx, 0, sizeof(ctx_t));
	ctx->algo = parse_word_headers(f, &ctx->keybits, &ctx->maxkeybits,
			ctx->salt, sizeof(ctx->salt),
			ctx->ev, sizeof(ctx->ev),
			ctx->evh, sizeof(ctx->evh));

	if (((uint64_t*)ctx->salt)[0] == 0 && ((uint64_t*)ctx->salt)[1] == 0) {
		return NULL; /* not encrypted */
	}

	switch (ctx->algo) {
		case rc4_basic:
			DPRINTF("Using RC4 (w/o Crypto API).\n");
			ctx->rc4basic = key_rc4basic_create(ctx->salt,
					ctx->ev, ctx->evh);
			break;

		case rc4_capi:
			DPRINTF("Using RC4 (w/Crypto API).\n");
			ctx->rc4capi = key_rc4capi_create(ctx->salt,
					ctx->ev, ctx->evh,
					ctx->keybits, ctx->maxkeybits);
			break;

		case unknown:
		default:
			DPRINTF("Unknown/unhandled crypto algorithm used.\n");
			return NULL;
	}

#ifdef DEBUG
	DPRINTF("Salt:\n\t");
	for (int i = 0; i < 16; i++) {
		DPRINTF("%02x ", ctx->salt[i]);
	}
	DPRINTF("\n");

	DPRINTF("EncryptedVerifier:\n\t");
	for (int i = 0; i < 16; i++) {
		DPRINTF("%02x ", ctx->ev[i]);
	}
	DPRINTF("\n");

	DPRINTF("EncryptedVerifierHash:\n\t");
	for (int i = 0; i < 16; i++) {
		DPRINTF("%02x ", ctx->evh[i]);
	}
	DPRINTF("\n\n");
#endif /* DEBUG */

	return (fpwchk_handle_t)ctx;
}

wchar_t *
fpwchk_word_crack_rc4basic(ctx_t* ctx, fpwchk_nextpw_cb_t nextpw, void *up)
{
	for (wchar_t *pw = nextpw(up); pw; pw = nextpw(up)) {
		uint8_t ucs2pw[2*16];
		size_t pwsz = ucs2_from_wcs(ucs2pw, sizeof(ucs2pw), pw);
		DPRINTF("===> Checking Password <%ls>\n", pw);
		if (key_rc4basic_verify(ctx->rc4basic, ucs2pw, pwsz)) {
#ifdef DEBUG

			// Decrypt the encrypted streams of the document.
			uint8_t *stream = NULL;
			size_t sz = 0;

			DPRINTF("Stream 'WordDocument'\n");
			get_stream(word, &stream, &sz);
			key_rc4basic_decrypt(ctx->rc4basic,
					ucs2pw, pwsz, stream, sz);

			DPRINTF("Stream '1Table'\n");
			get_stream(one_table, &stream, &sz);
			key_rc4basic_decrypt(ctx->rc4basic,
					ucs2pw, pwsz, stream, sz);

			DPRINTF("Stream 'Data'\n");
			get_stream(data, &stream, &sz);
			key_rc4basic_decrypt(ctx->rc4basic,
					ucs2pw, pwsz, stream, sz);
#endif /* DEBUG */
			return wcsdup(pw);
		}
	}
	return NULL;
}

wchar_t *
fpwchk_word_crack_rc4capi(ctx_t* ctx, fpwchk_nextpw_cb_t nextpw, void *up)
{
	for (wchar_t *pw = nextpw(up); pw; pw = nextpw(up)) {
		uint8_t ucs2pw[2*1024];
		size_t pwsz = ucs2_from_wcs(ucs2pw, sizeof(ucs2pw), pw);
		DPRINTF("===> Checking Password <%ls>\n", pw);
		if (key_rc4capi_verify(ctx->rc4capi, ucs2pw, pwsz)) {
			return wcsdup(pw);
		}
	}
	return NULL;
}

wchar_t *
fpwchk_word_crack(fpwchk_handle_t handle, fpwchk_nextpw_cb_t nextpw, void *up)
{
	ctx_t *ctx = (ctx_t*)handle;
	if (!ctx) {
		return NULL;
	}

	switch (ctx->algo) {
		case rc4_basic:
			return fpwchk_word_crack_rc4basic(ctx, nextpw, up);
		case rc4_capi:
			return fpwchk_word_crack_rc4capi(ctx, nextpw, up);
		default:
			/* this is always a programming error */
			assert(0);
			return NULL;
	}
}

void
fpwchk_word_destroy(fpwchk_handle_t handle)
{
	ctx_t *ctx = (ctx_t*)handle;

	if (ctx->rc4basic) {
		key_rc4basic_destroy(ctx->rc4basic);
		ctx->rc4basic = NULL;
	}

	if (ctx->rc4capi) {
		key_rc4capi_destroy(ctx->rc4capi);
		ctx->rc4capi = NULL;
	}

	if (ctx) {
		free(ctx);
	}
}

void
fpwchk_word_freepw(wchar_t *pw)
{
	if (pw) {
		free(pw);
	}
}

