/* $Id: test.c 204 2008-08-22 11:40:20Z rkeller $ */

#include <fpwchk/word.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

typedef struct {
	int index;
	wchar_t **passwords; /* NULL terminated list of passwords */
	wchar_t aaa[1024];
} ctx_t;

wchar_t *
next_password(void *usrp)
{
	ctx_t *ctx = (ctx_t*)usrp;
	if (ctx->passwords[ctx->index]) {
		return ctx->passwords[ctx->index++];
	} else {
		if (wcslen(ctx->aaa) + 1 >= sizeof(ctx->aaa) / sizeof(wchar_t))
			return NULL;
		wcscat(ctx->aaa, L"a");
#if DEBUG
		fprintf(stderr, "%d <%ls> \n", wcslen(ctx->aaa), ctx->aaa);
#endif
		return ctx->aaa;
	}
}

wchar_t *passwords[] = {
	L"secret",
	L"thierry",
	L"foo",
	L"bar",
	L"baz",
	L"password",
	L"kryptdet",
	NULL
};

int
main(int argc, char *argv[])
{
	ctx_t ctx = { .index = 0, .passwords = passwords, .aaa = L"" };
	wchar_t *password;
	FILE *file;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		exit(1);
	}

	if (!(file = fopen(argv[1], "rb"))) {
		fprintf(stderr, "fopen(\"%s\", \"rb\") => %s\n",
				argv[1], strerror(errno));
		exit(1);
	}
	fpwchk_handle_t handle = fpwchk_word_create(file);
	fclose(file);
	if (!handle) {
		fprintf(stderr, "Failed to open handle!\n"
				"Is file really encrypted?\n");
		exit(1);
	}
	password = fpwchk_word_crack(handle, next_password, (void*)&ctx);
	fpwchk_word_destroy(handle);
	if (password) {
		printf("Found password <%ls>\n", password);
		fpwchk_word_freepw(password);
		return 0;
	}

	printf("Password not found\n");
	return 1;
}

