
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#ifndef WIN32
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#else
#include "win32/getopt.h"
#include "win32/string.h"
#endif

#define DEFAULT_MATCH "</head>"

static int
_stdin(void) {
#ifndef WIN32
    struct stat st;

    if (fstat(STDIN_FILENO, &st) == 0 &&
        S_ISFIFO(st.st_mode)) {
        return 1;
    }

    return 0;
#else
    return 1;
#endif
}

static void
usage(char *arg, char *message)
{
#ifndef WIN32
    char *command = basename(arg);
#else
    char *command = arg;
#endif

    printf("Usage: %s [-m MATCH] URL\n\n", command);

    printf("  -m, --match=MATCH insert before matching [DEFAULT: \"%s\"]\n",
           DEFAULT_MATCH);
    printf("  -q, --quiet          quiet message\n");

    if (message) {
        printf("\nINFO: %s\n", message);
    }
}

int
main(int argc, char **argv)
{
    char buf[BUFSIZ];
    char *match = DEFAULT_MATCH;
    char *url = NULL;
    int quiet = 0;
    size_t len;

    int opt;
    const struct option long_options[] = {
        { "match", 1, NULL, 'm' },
        { "quiet", 0, NULL, 'q' },
        { "help", 0, NULL, 0 },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "m:qh",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'm':
                match = optarg;
                break;
            case 'q':
                quiet = 1;
                break;
            default:
                usage(argv[0], NULL);
                return -1;
        }
    }

    if (argc <= optind) {
        if (!quiet) {
            usage(argv[0], "required args to URL");
        }
        return -1;
    }
    url = argv[optind];

    if (!_stdin()) {
        if (!quiet) {
            usage(argv[0], "not standard input");
        }
        return -1;
    }

    while (1) {
        int eot = 0;
        char *out = NULL, *str = NULL;

        memset(buf, 0, sizeof(char) * BUFSIZ);
        out = buf;

        len = fread(buf, sizeof(char), BUFSIZ, stdin);
        if (len == 0) {
            break;
        }

        if (len < BUFSIZ) {
            eot = 1;
        }

        str = strcasestr(buf, match);
        if (str != NULL) {
            printf("%.*s", str - buf, buf);
            printf("<script type=\"text/javascript\" src=\"%s\"></script>\n",
                   url);
            out = str;
            len -= str - buf;
        }
        printf("%.*s", len, out);

        if (eot) {
            break;
        }
    }

    return 0;
}
