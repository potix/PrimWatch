#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common_macro.h"
#include "logger.h"
#include "string_util.h"

int
main(int argc, char*argv[]) {
	tuple_split_t tuple;
	char buff[8192];

	errno = 0;
	snprintf(buff, sizeof(buff), "a b c");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 0);
	ASSERT(errno == 0);
	ASSERT(tuple.value_count = 3);
	ASSERT(strcmp(tuple.value[0], "a") == 0);
	ASSERT(strcmp(tuple.value[1], "b") == 0);
	ASSERT(strcmp(tuple.value[2], "c") == 0);

	snprintf(buff, sizeof(buff), "hoge    piyo		kooo jjjjj ");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 0);
	ASSERT(errno == 0);
	ASSERT(tuple.value_count == 4);
	ASSERT(strcmp(tuple.value[0], "hoge") == 0);
	ASSERT(strcmp(tuple.value[1], "piyo") == 0);
	ASSERT(strcmp(tuple.value[2], "kooo") == 0);
	ASSERT(strcmp(tuple.value[3], "jjjjj") == 0);

	snprintf(buff, sizeof(buff), "ggggg");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 0);
	ASSERT(errno == 0);
	ASSERT(tuple.value_count == 1);
	ASSERT(strcmp(tuple.value[0], "ggggg") == 0);

	snprintf(buff, sizeof(buff), "");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 0);
	ASSERT(errno == 0);
	ASSERT(tuple.value_count == 0);

	snprintf(buff, sizeof(buff), "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 0);
	ASSERT(errno == 0);
	ASSERT(tuple.value_count == 32);
	ASSERT(strcmp(tuple.value[0], "1") == 0);
	ASSERT(strcmp(tuple.value[1], "2") == 0);
	ASSERT(strcmp(tuple.value[2], "3") == 0);
	ASSERT(strcmp(tuple.value[3], "4") == 0);
	ASSERT(strcmp(tuple.value[4], "5") == 0);
	ASSERT(strcmp(tuple.value[5], "6") == 0);
	ASSERT(strcmp(tuple.value[6], "7") == 0);
	ASSERT(strcmp(tuple.value[7], "8") == 0);
	ASSERT(strcmp(tuple.value[8], "9") == 0);
	ASSERT(strcmp(tuple.value[9], "10") == 0);
	ASSERT(strcmp(tuple.value[10], "11") == 0);
	ASSERT(strcmp(tuple.value[11], "12") == 0);
	ASSERT(strcmp(tuple.value[12], "13") == 0);
	ASSERT(strcmp(tuple.value[13], "14") == 0);
	ASSERT(strcmp(tuple.value[14], "15") == 0);
	ASSERT(strcmp(tuple.value[15], "16") == 0);
	ASSERT(strcmp(tuple.value[16], "17") == 0);
	ASSERT(strcmp(tuple.value[17], "18") == 0);
	ASSERT(strcmp(tuple.value[18], "19") == 0);
	ASSERT(strcmp(tuple.value[19], "20") == 0);
	ASSERT(strcmp(tuple.value[20], "21") == 0);
	ASSERT(strcmp(tuple.value[21], "22") == 0);
	ASSERT(strcmp(tuple.value[22], "23") == 0);
	ASSERT(strcmp(tuple.value[23], "24") == 0);
	ASSERT(strcmp(tuple.value[24], "25") == 0);
	ASSERT(strcmp(tuple.value[25], "26") == 0);
	ASSERT(strcmp(tuple.value[26], "27") == 0);
	ASSERT(strcmp(tuple.value[27], "28") == 0);
	ASSERT(strcmp(tuple.value[28], "29") == 0);
	ASSERT(strcmp(tuple.value[29], "30") == 0);
	ASSERT(strcmp(tuple.value[30], "31") == 0);
	ASSERT(strcmp(tuple.value[31], "32") == 0);

	snprintf(buff, sizeof(buff), "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33");
	ASSERT(string_tuple_split_b(&tuple, buff, " \t") == 1);
	ASSERT(errno == ENOBUFS);
	ASSERT(tuple.value_count == 32);
	ASSERT(strcmp(tuple.value[0], "1") == 0);
	ASSERT(strcmp(tuple.value[1], "2") == 0);
	ASSERT(strcmp(tuple.value[2], "3") == 0);
	ASSERT(strcmp(tuple.value[3], "4") == 0);
	ASSERT(strcmp(tuple.value[4], "5") == 0);
	ASSERT(strcmp(tuple.value[5], "6") == 0);
	ASSERT(strcmp(tuple.value[6], "7") == 0);
	ASSERT(strcmp(tuple.value[7], "8") == 0);
	ASSERT(strcmp(tuple.value[8], "9") == 0);
	ASSERT(strcmp(tuple.value[9], "10") == 0);
	ASSERT(strcmp(tuple.value[10], "11") == 0);
	ASSERT(strcmp(tuple.value[11], "12") == 0);
	ASSERT(strcmp(tuple.value[12], "13") == 0);
	ASSERT(strcmp(tuple.value[13], "14") == 0);
	ASSERT(strcmp(tuple.value[14], "15") == 0);
	ASSERT(strcmp(tuple.value[15], "16") == 0);
	ASSERT(strcmp(tuple.value[16], "17") == 0);
	ASSERT(strcmp(tuple.value[17], "18") == 0);
	ASSERT(strcmp(tuple.value[18], "19") == 0);
	ASSERT(strcmp(tuple.value[19], "20") == 0);
	ASSERT(strcmp(tuple.value[20], "21") == 0);
	ASSERT(strcmp(tuple.value[21], "22") == 0);
	ASSERT(strcmp(tuple.value[22], "23") == 0);
	ASSERT(strcmp(tuple.value[23], "24") == 0);
	ASSERT(strcmp(tuple.value[24], "25") == 0);
	ASSERT(strcmp(tuple.value[25], "26") == 0);
	ASSERT(strcmp(tuple.value[26], "27") == 0);
	ASSERT(strcmp(tuple.value[27], "28") == 0);
	ASSERT(strcmp(tuple.value[28], "29") == 0);
	ASSERT(strcmp(tuple.value[29], "30") == 0);
	ASSERT(strcmp(tuple.value[30], "31") == 0);
	ASSERT(strcmp(tuple.value[31], "32") == 0);
}

