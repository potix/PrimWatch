#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include "common_macro.h"
#include "string_util.h"

#ifdef USE_BSD_STRLCPY
// ----------------------------------------------------------------------//
/*	$OpenBSD: strlcpy.c,v 1.11 2006/05/05 15:27:38 millert Exp $	*/

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0) {
		while (--n != 0) {
			if ((*d++ = *s++) == '\0')
				break;
		}
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

#endif

#ifdef USE_BSD_STRLCAT
// ----------------------------------------------------------------------//
/*	$OpenBSD: strlcat.c,v 1.13 2005/08/08 08:05:37 espie Exp $	*/

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}
#endif

int
string_lstrip_b(
    char **new_str,
    char *str,
    const char *strip_str)
{
	int len, last;
	char *find;

	if (new_str == NULL ||
	    str == NULL ||
	    strip_str == NULL) {
		return 1;
	}
	last = strlen(str);
	len = 0;
	while(len < last && str[len] != '\0') {
		find = strchr(strip_str, str[len]);
		if (!find) {
			break;
		}
		str[len] = '\0';
		len++;
	}
	*new_str = &str[len];

	return 0;
}

int
string_rstrip_b(
    char *str,
    const char *strip_str)
{
	int len;
	char *find;

	if (str == NULL || strip_str == NULL) {
		return 1;
	}
	len = strlen(str);
	while(len > 0  && str[len - 1] != '\0') {
		find = strchr(strip_str, str[len - 1]);
		if (!find) {
			break;
		}
		str[len - 1] = '\0';
		len--;
	}

	return 0;
}

int
string_kv_split_b(
    kv_split_t *kv,
    char *str,
    const char *delim_str)
{
	char *key;
	char *value;

	if (kv == NULL ||
	    str == NULL ||
	    delim_str == NULL) {
		return 1;
	}
	if (string_rstrip_b(str, " \t\r")) {
		return 1;
	}
	if ((key = strsep(&str, delim_str)) == NULL) {
		return 1;
	}
	if (string_rstrip_b(key, " \t\r")) {
		return 1;
	}
	if (string_lstrip_b(&value, str, " \t\r")) {
		return 1;
	}
	if (string_rstrip_b(value, " \t\r")) {
		return 1;
	}
        kv->key = key;
        kv->value = value;

        return 0;
}


int
string_tuple_split_b(
    tuple_split_t *tuple,
    char *str,
    const char *delim_str)
{
	int i;
	char *value;

	if (tuple == NULL ||
	    str == NULL ||
	    delim_str == NULL) {
		return 1;
	}
	tuple->value_count = 0;
	if (string_rstrip_b(str, " \t\r")) {
		return 1;
	}
	if (*str == '\0') {
            return 0;
        }
        for (i = 0; tuple->value_count < TUPLE_MAX; i++) {
		if ((value = strsep(&str, delim_str)) == NULL) {
			return 1;
		}
		if (string_rstrip_b(value, " \t\r")) {
			return 1;
		}
		tuple->value[tuple->value_count] = value;
		tuple->value_count += 1;
		if (str == NULL) {
			break;
		}
		if (string_lstrip_b(&str, str, " \t\r")) {
			return 1;
		}
	}
	if (str != NULL) {
		errno = ENOBUFS;
		return 1;
	}

        return 0;
}

static int
strtovalue(
    long *value,
    const char *str,
    int base,
    long min,
    long max)
{
        long l;
        char *ptr;

	ASSERT(value != NULL);
	ASSERT(str != NULL);
	ASSERT(*str != '\0');
        errno = 0;
        l = strtol(str, &ptr, base);
        if (*ptr !='\0' ||
            (l == 0 && errno == EINVAL) ||
            (l == LONG_MIN && errno == ERANGE) ||
            (l == LONG_MAX && errno == ERANGE)) {
                return 1;
        }
        if (l > max || l < min) {
                errno = ERANGE;
                return 1;
        }
        *value = l;

        return 0;
}

int
strtoint(
    int *value,
    const char *str,
    int base)
{
        long l;

        if (value == NULL ||
            str == NULL ||
            *str == '\0') {
                errno = EINVAL;
                return 1;
        }
	if (strtovalue(&l, str, base, INT_MIN, INT_MAX)) {
		return 1;
	}
        *value = (int)l;

        return 0;
}

int
strtouc(
    unsigned char *value,
    const char *str,
    int base)
{
        long l;

        if (value == NULL ||
            str == NULL ||
            *str == '\0') {
                errno = EINVAL;
                return 1;
        }
	if (strtovalue(&l, str, base, 0, 255)) {
		return 1;
	}
        *value = (unsigned char)l;

        return 0;
}

	 
int
parse_cmd_b(
    parse_cmd_t *parse_cmd,
    char *cmd)
{
	int squote = 0;
	int dquote = 0;
	int cmd_size;
	char *ptr;

        if (parse_cmd == NULL ||
            cmd == NULL) {
                errno = EINVAL;
                return 1;
        }
	ptr = parse_cmd->args[0] = cmd;
	parse_cmd->args[1] = NULL;
	parse_cmd->arg_size = 1;
	cmd_size = strlen(cmd) + 1;
	while (*ptr != '\0') {
		if (!(squote || dquote) && *ptr == ' ') {
			*ptr = '\0';
			if (*(ptr + 1) != '\0') {
				if (parse_cmd->args[parse_cmd->arg_size - 1][0] == '\0') {
					parse_cmd->arg_size--;
				}
				parse_cmd->args[parse_cmd->arg_size] = ptr + 1;
				parse_cmd->args[parse_cmd->arg_size + 1] = NULL;
				parse_cmd->arg_size++;
				if (parse_cmd->arg_size >= NCARGS) {
					errno = ENOBUFS;
					return 1;
				}
			}
		} else if (!squote && *ptr == '"') {
			if (dquote == 1) {
				*ptr = '\0';
				dquote = 0;
			} else {
				parse_cmd->args[parse_cmd->arg_size - 1]++;
				dquote = 1;
			}
		} else if (!dquote && *ptr == '\'') {
			if (squote == 1) {
				*ptr = '\0';
				squote = 0;
			} else {
				parse_cmd->args[parse_cmd->arg_size - 1]++;
				squote = 1;
			}
		} else if (*ptr == '\\' && (*(ptr + 1) == ' ' || *(ptr + 1) == '"' || *(ptr + 1) == '\'')) {
			memmove(ptr, ptr + 1, (cmd + cmd_size) - (ptr + 1));
		}
		ptr++; 
	}

	return 0;
}

