/* $Id: testthread.c 220 2008-08-22 14:53:02Z roe $
 * $PDF: test.c 74 2008-08-18 13:41:09Z mweber $ */
#define _GNU_SOURCE

#include <fpwchk/word.h>
#include "compat.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <wchar.h>
#include <pthread.h>

#define NUM_EMPTY_RUNS 500000
#define NUM_THREADS 2

pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
wchar_t* final_password=0;
long long num_runs = 0;

double walltime(double *t0) {
   double mic, time;
   double mega=0.000001;
   struct timeval tp;
   static long base_sec = 0;
   static long base_usec = 0;

   (void) gettimeofday(&tp, NULL);
   if (base_sec == 0) {
     base_sec  = tp.tv_sec;
     base_usec = tp.tv_usec;
   }
   time = (double)(tp.tv_sec - base_sec);
   mic = (double)(tp.tv_usec - base_usec);
   time = (time + mic * mega) - *t0;
   return(time);
}


typedef struct {
	int index;
	wchar_t **passwords; /* NULL terminated list of passwords */
} ctx_t;

wchar_t *
next_password(void *usrp)
{
	ctx_t *ctx = (ctx_t*)usrp;
	ctx->index++;
	if (ctx->index > NUM_EMPTY_RUNS) {
		return ctx->passwords[ctx->index-NUM_EMPTY_RUNS];
	}
	return ctx->passwords[0];
}

wchar_t *passwords[] = { L"secret", L"thierry", L"foo", L"bar", L"baz", L"test", L"password", L"daniel", L"ghijkl", L"abcdef", NULL };

void *runTest(void* handle) {
	ctx_t ctx;// = { .index = 0, .passwords = passwords };
	ctx.index = 0;
	ctx.passwords = passwords;
	wchar_t *password;
	password = fpwchk_word_crack((fpwchk_handle_t)handle, next_password, (void*)&ctx);
	pthread_mutex_lock(&global_mutex);
	num_runs += ctx.index;
	if (password) {
		printf("GOT A PASSWORD\n");
		final_password = wcsdup(password);
	}
	pthread_mutex_unlock(&global_mutex);
	fpwchk_word_freepw(password);

	return 0;
}

int
main(int argc, char *argv[])
{
	FILE *file;
	double time1=0.0;
	void* status;
	int rc, i, result;
	pthread_t threads[NUM_THREADS];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		exit(1);
	}

	if (!(file = fopen(argv[1], "rb"))) {
		fprintf(stderr, "fopen(\"%s\", \"rb\") => %s\n",
				argv[1], strerror(errno));
	}
	fpwchk_handle_t handle = fpwchk_word_create(file);
	fclose(file);
	time1 = walltime(&time1);
	for (i=0; i<NUM_THREADS; i++) {
		rc = pthread_create(&threads[i], &attr, runTest, handle);
		if (rc) {
			printf("Got Error on create of thread");
			return -1;
		}
	}

	for (i=0; i<NUM_THREADS; i++) {
		rc = pthread_join(threads[i], &status);
		if (rc) {
			printf("Got error on join");
			return -1;
		}
	}

	time1 = walltime(&time1);
	fpwchk_word_destroy(handle);

	pthread_attr_destroy(&attr);

	if (final_password) {
		printf("Found password <%ls>\n", final_password);
		free(final_password);
		result = 0;
	} else {
		printf("Password not found\n");
		result = 1;
	}

	printf("Time used: %.2fs for %lld passwords (passwords/s: %.0f)\n", 
				time1, num_runs, num_runs/time1);

	pthread_exit(NULL);
	return 1;
}

