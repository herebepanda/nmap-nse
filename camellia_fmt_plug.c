/* Standard includes */
#include <string.h>
#include <assert.h>
#include <errno.h>

/* John includes */
#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"
#include "base64.h"

/* If openmp */
#ifdef _OPENMP
#include <omp.h>
#define OMP_SCALE 32
#endif

/* crypto includes */
#include <openssl/camellia.h>

#define	FORMAT_LABEL		"camellia"
#define	FORMAT_NAME		"Camellia bruteforce"
#define ALGORITHM_NAME		"32/" ARCH_BITS_STR
#define	BENCHMARK_COMMENT	""
#define	BENCHMARK_LENGTH	-1
#define	PLAINTEXT_LENGTH	32
#define	BINARY_SIZE		16
#define	SALT_SIZE		0
#define	MIN_KEYS_PER_CRYPT	1
#define	MAX_KEYS_PER_CRYPT	1


static struct fmt_tests cam_tests[] = {
	{"$camellia$NeEGbM0Vhz7u+FGJZrcPiw==", "admin" },
	{NULL}
};

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char (*crypt_out)[BINARY_SIZE];

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	int omp_t;
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) *
		self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) *
		self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	return !strncmp(ciphertext, "$camellia$", 10); //magic secret number
}

static void *get_binary(char *ciphertext)
{
	static union {
		unsigned char c[BINARY_SIZE+1];
		ARCH_WORD dummy;
	} buf;
	unsigned char *out = buf.c;
	char *p;
	p = strrchr(ciphertext, '$') + 1;
	base64_decode(p, strlen(p), (char*)out);
	return out;
}

static void crypt_all(int count)
{
	int index = 0;
#ifdef _OPENMP
#pragma omp parallel for
	for (index = 0; index < count; index++)
#endif
	{
		CAMELLIA_KEY st_key;
		unsigned char in[16] = {0};
		unsigned char key[32] = {0};
		memcpy(key, saved_key[index], strlen(saved_key[index]));
		Camellia_set_key(key, 256, &st_key);
		Camellia_encrypt(in, crypt_out[index], &st_key);
	}
}

static int cmp_all(void *binary, int count)
{
	int index = 0;
#ifdef _OPENMP
	for (; index < count; index++)
#endif
	if (!memcmp(binary, crypt_out[index], BINARY_SIZE))
		return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static void cam_set_key(char *key, int index)
{
	int saved_key_length = strlen(key);
	if (saved_key_length > PLAINTEXT_LENGTH)
		saved_key_length = PLAINTEXT_LENGTH;
	memcpy(saved_key[index], key, saved_key_length);
	saved_key[index][saved_key_length] = 0;
}

static char *get_key(int index)
{
	return saved_key[index];
}

struct fmt_main fmt_camellia = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		cam_tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
	{
			fmt_default_binary_hash,
	},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		cam_set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
			{
				fmt_default_get_hash,
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};
