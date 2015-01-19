#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common_macro.h"
#include "bhash.h"

int
main(int argc, char*argv[])
{
	bhash_t *bhash;

	fprintf(stderr, "test 1\n");
        //------
	ASSERT(bhash_create(&bhash, 1, NULL, NULL) == 0);
	fprintf(stderr, "step 1\n");
	ASSERT(bhash_replace(bhash, "foo", 4, "4", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 2\n");
        ASSERT(bhash_replace(bhash, "hoge", 5, "0", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 3\n");
	ASSERT(bhash_replace(bhash, "foo", 4, "4", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 4\n");
        ASSERT(bhash_replace(bhash, "hoge", 5, "0", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 5\n");
        ASSERT(bhash_replace(bhash, "foo", 5, "0", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 6\n");
        ASSERT(bhash_replace(bhash, "piyo", 5, "0", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 7\n");
	ASSERT(bhash_destroy(bhash) == 0);
	fprintf(stderr, "end\n");

	fprintf(stderr, "test 2\n");
        //------
	ASSERT(bhash_create(&bhash, 1, NULL, NULL) == 0);
	fprintf(stderr, "step 1\n");
	ASSERT(bhash_replace(bhash, "foo", 4, "4", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 2\n");
	ASSERT(bhash_replace(bhash, "foo", 4, "4", 2, NULL, NULL) == 0);
	fprintf(stderr, "step 3\n");
        ASSERT(bhash_replace(bhash, "foo", 4, "0123456789012345678901234567890123456789", 41, NULL, NULL) == 0);
	fprintf(stderr, "step 4\n");
	ASSERT(bhash_destroy(bhash) == 0);
	fprintf(stderr, "end\n");


        fprintf(stderr, "value = %d\n", bhash_compute_value("hoge.test.localnet", sizeof("hoge.test.localnet"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("piyo.piyo.localnet", sizeof("piyo.piyo.localnet"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("hoge.piyo.piyo.localnet", sizeof("hoge.piyo.piyo.localnet"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("localnet", sizeof("localnet"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("a", sizeof("a"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("aa", sizeof("aa"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("aaa", sizeof("aaa"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("aaaa", sizeof("aaaa"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("aaaaa", sizeof("aaaaa"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("ab", sizeof("ab"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("abc", sizeof("abc"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("abcd", sizeof("abcd"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("abcde", sizeof("abcde"), 67));
        fprintf(stderr, "value = %d\n", bhash_compute_value("piyo.piyo.localnet", sizeof("piyo.piyo.localnet"), 127));
        fprintf(stderr, "value = %d\n", bhash_compute_value("a", sizeof("a"), 127));

	return 0;
}
