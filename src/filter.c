
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <fnmatch.h>

#define BUFFER_SIZE 4096
#define DEFAULT_MATCH "*</head>*"

static int
_stdin(void) {
    struct stat st;

    if (fstat(STDIN_FILENO, &st) == 0 &&
        S_ISFIFO(st.st_mode)) {
        return 1;
    }

    return 0;
}

static void
usage(char *arg, char *message)
{
    char *command = basename(arg);

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
    char buf[BUFFER_SIZE];
    char *match = DEFAULT_MATCH;
    char *url = NULL;
    int quiet = 0;

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
        memset(buf, 0, BUFFER_SIZE);
        if (fgets(buf, BUFFER_SIZE, stdin) == NULL) {
            break;
        }

        if (fnmatch(match, buf, FNM_FILE_NAME | FNM_CASEFOLD) == 0) {
            printf("<script type=\"text/javascript\" src=\"%s\"></script>\n",
                   url);
        }
        printf("%s", buf);
    }

    return 0;
}
