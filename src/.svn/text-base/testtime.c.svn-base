#include <fpwchk/word.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <time.h>

#define MAX_PWDS	1000000

typedef struct {
	int count;
} ctx_t;

wchar_t *
next_password(void *usrp)
{
	ctx_t *ctx = (ctx_t*)usrp;

	if (ctx->count > MAX_PWDS)
	{
		return NULL;
	}

	ctx->count++;

	return L"123456789012345";
}

int
main(int argc, char *argv[])
{
	ctx_t ctx = { .count = 0 };
	wchar_t *password;
	clock_t  start;
	clock_t  end;
	clock_t  delta;
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

	start = clock();
	password = fpwchk_word_crack(handle, next_password, (void*)&ctx);
	end = clock();

	delta = end - start;
	printf("Checked %d Passwords in %g seconds.\n", MAX_PWDS, (double)delta / (double)CLOCKS_PER_SEC);
	printf("--> %g pwd/sec.\n", (double)MAX_PWDS / ((double)delta / (double)CLOCKS_PER_SEC));

	fpwchk_word_destroy(handle);
	if (password) {
		printf("Found password <%ls>\n", password);
		fpwchk_word_freepw(password);
		return 0;
	}

	printf("Password not found\n");
	return 1;
}
