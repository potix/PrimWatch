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

	return 0;
}
