#ifndef COMMON_MACRO_H
#define COMMON_MACRO_H

#define COMMON_DEBUG

#ifdef COMMON_DEBUG
#define ASSERT(x)                        \
do {                                     \
        if (!(x)) {                      \
                fprintf(stderr,          \
                    "assert %s:%d (%d)", \
                     __func__,           \
                     __LINE__,           \
                     (x));               \
                abort();                 \
        }                                \
} while(0)
#else
#define ASSERT(x)
#endif

#ifdef COMMON_DEBUG
#define IFASSERT(c, x)                           \
do {                                             \
	if ((c)) {                               \
		if (!(x)) {                      \
			fprintf(stderr,          \
			    "assert %s:%d (%d)", \
			     __func__,           \
			     __LINE__,           \
			     (x));               \
			abort();                 \
		}                                \
        }                                        \
} while(0)
#else
#define IFASSERT(c, x)
#endif

#define ABORT(msg)                               \
do {                                             \
        fprintf(stderr, msg " - abort %s:%d:%m", \
             __func__, __LINE__);                \
        abort();                                 \
} while(0)

#endif
