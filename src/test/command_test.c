#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "common_macro.h"
#include "logger.h"
#include "string_util.h"

void
print_args(parse_cmd_t *parse_cmd) {
	int i;
	for (i = 0; i < parse_cmd->arg_size; i++) {
		printf("%s ", parse_cmd->args[i]);
	}
	printf("%d\n", parse_cmd->arg_size);
}

int
main(int argc, char*argv[])
{
	parse_cmd_t parse_cmd;
	char cmd[4096];

	strlcpy(cmd, "test", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(parse_cmd.args[1] == NULL);

	strlcpy(cmd, "test -f tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test   -f   tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test \"-f tttt\"", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f tttt") == 0);
	ASSERT(parse_cmd.args[2] == NULL);

	strlcpy(cmd, "test '-f tttt'", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f tttt") == 0);
	ASSERT(parse_cmd.args[2] == NULL);

	strlcpy(cmd, "test -f\\ tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f tttt") == 0);
	ASSERT(parse_cmd.args[2] == NULL);

	strlcpy(cmd, "test -f\\\" tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "-f\"") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test \"jjj kkk ' lll '\" tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "jjj kkk ' lll '") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test \"jjj \\\"kkk \" tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "jjj \"kkk ") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test 'jjj kkk \" lll \"' tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "jjj kkk \" lll \"") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	strlcpy(cmd, "test 'jjj \\'kkk ' tttt", sizeof(cmd));
	ASSERT(parse_cmd_b(&parse_cmd, cmd) == 0);
	print_args(&parse_cmd);
	ASSERT(strcmp(parse_cmd.args[0], "test") == 0);
	ASSERT(strcmp(parse_cmd.args[1], "jjj 'kkk ") == 0);
	ASSERT(strcmp(parse_cmd.args[2], "tttt") == 0);
	ASSERT(parse_cmd.args[3] == NULL);

	return 0;
}
