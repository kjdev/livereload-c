#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>
#include <regex.h>

#include <libwebsockets.h>
#include <jansson.h>

#if HAVE_INOTIFYTOOLS
#include <inotifytools/inotifytools.h>
#include <inotifytools/inotify.h>
#endif

static int interrupted = 0;
static int verbose = 0;
static int quiet = 0;
static unsigned char *str = NULL;

#define DEFAULT_ADDRESS "localhost"
#define DEFAULT_PORT 35729

#define ERR(...) fprintf(stderr, "ERR: "__VA_ARGS__)
#define DEBUG(l, ...) if (!quiet && verbose >= l) { printf(__VA_ARGS__); }
#define NOTICE(l, ...) if (!quiet && verbose >= l) { lwsl_notice(__VA_ARGS__); }

static int
callback_default(struct libwebsocket_context *context, struct libwebsocket *wsi,
                 enum libwebsocket_callback_reasons reason, void *user,
                 void *in, size_t len)
{
    return 0;
}

static void
signal_handler(int sig)
{
    interrupted = 1;
}

static void
signals(void)
{
    struct sigaction sa;

    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

static void
usage(char *arg, char *message)
{
    char *command = basename(arg);

    printf("Usage: %s [-a ADDRESS] [-p PORT]"
#if HAVE_INOTIFYTOOLS
           " [-w]"
#endif
           " [-h HOST] [-s SUFFIX]\n", command);
    printf("%*s        [-c SSL_CERT_PATH -k SSL_KEY_PATH] PATH\n\n",
           (int)strlen(command), "");

    printf("  -a, --addres=ADDRESS connection server address [DEFAULT: %s]\n",
           DEFAULT_ADDRESS);
    printf("  -p, --port=PORT      connection server port [DEFAULT: %d]\n",
           DEFAULT_PORT);
#if HAVE_INOTIFYTOOLS
    printf("  -w, --watch          watch change file of PATH\n");
#endif
    printf("  -h, --host=HOST      append web host name\n");
    printf("  -s, --suffix=SUFFIX  remove a trailing SUFFIX\n");
    printf("  -c, --certpath=FILE  ssl certificate file path\n");
    printf("  -k, --keypath=FILE   ssl private key file path\n");
    printf("  -v, --verbose        verbosity message\n");
    printf("  -q, --quiet          quiet message\n");
#if HAVE_INOTIFYTOOLS
    printf("  PATH                 send or watch path name\n");
#else
    printf("  PATH                 send path name\n");
#endif

    if (message) {
        printf("\nINFO: %s\n", message);
    }
}

static struct libwebsocket_protocols protocols[] = {
    {
        "default",        /* name */
        callback_default, /* callback */
        0,                /* per_session_data_size */
        0,                /* max frame size / rx buffer */
        NULL,             /* owning_server */
        0                 /* protocol_index */
    },
    { NULL, NULL, 0, 0, NULL, 0 } /* End of list */
};

int
main (int argc, char **argv)
{
    char *address = DEFAULT_ADDRESS;
    int port = DEFAULT_PORT;
    char *cert_path = NULL;
    char *key_path = NULL;
    int use_ssl = 0;
    char *host = NULL;
    char *origin = NULL;
    int watch = 0;
    char *arg, *msg = NULL;
    json_t *json = NULL;
    int json_flags =
        JSON_COMPACT|JSON_ENCODE_ANY|JSON_PRESERVE_ORDER|JSON_ENSURE_ASCII;
    char *web = NULL, *suffix = NULL;
    char path[PATH_MAX];
    char *str = NULL;
#if HAVE_INOTIFYTOOLS
    int inotify = 0;
#endif

    struct libwebsocket_context *context;
    struct libwebsocket *wsi;
    struct lws_context_creation_info info;

    int opt;
    const struct option long_options[] = {
        { "address", 1, NULL, 'a' },
        { "port", 1, NULL, 'p' },
#if HAVE_INOTIFYTOOLS
        { "watch", 0, NULL, 'w' },
#endif
        { "suffix", 1, NULL, 's' },
        { "host", 1, NULL, 'h' },
        { "certpath", 1, NULL, 'c' },
        { "keypath", 1, NULL, 'k' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "help", 0, NULL, 0 },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "a:p:ws:h:c:k:vs",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'w':
                watch = 1;
                break;
            case 's':
                suffix = optarg;
                break;
            case 'h':
                web = optarg;
                break;
            case 'c':
                cert_path = optarg;
                break;
            case 'k':
                key_path = optarg;
                break;
            case 'v':
                if (optarg) {
                    verbose = atoi(optarg);
                } else {
                    verbose = 1;
                }
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
        usage(argv[0], "required args to PATH");
        return -1;
    }
    arg = argv[optind];

    if (!address || strlen(address) <= 0) {
        usage(argv[0], "invalid server address");
        return -1;
    }

    if (port < 0) {
        usage(argv[0], "invalid server port");
        return -1;
    }

    if (cert_path || key_path) {
        use_ssl = 1;
    }

    if (quiet) {
        lws_set_log_level(-1, NULL);
    } else if (verbose == 0 || verbose == 1) {
        lws_set_log_level(LLL_WARN, NULL);
    } else if (verbose == 2) {
        lws_set_log_level(LLL_NOTICE, NULL);
    }

#if HAVE_INOTIFYTOOLS
    if (watch) {
        inotify = inotifytools_initialize();
        if (!inotify) {
            ERR("%s\n", strerror(inotifytools_error()));
            return -1;
        }

        inotifytools_set_printf_timefmt("%H:%M:%S");

        //if (!inotifytools_watch_recursively(arg, IN_ALL_EVENTS)) {
        if (!inotifytools_watch_recursively(arg, IN_CLOSE_WRITE)) {
            ERR("%s\n", strerror(inotifytools_error()));
            return -1;
        }

        signals();

        DEBUG(1, "Starting watch [%s] ...\n", arg);
    } else {
        interrupted = 1;
    }
#else
    interrupted = 1;
#endif

    do {
        char *filename = NULL;

#if HAVE_INOTIFYTOOLS
        if (watch) {
            char *name = NULL;
            size_t len;
            struct inotify_event *event = inotifytools_next_event(-1);
            if (!event || interrupted) {
                break;
            }

            if (event->mask != IN_CLOSE_WRITE) {
                continue;
            }

            name = inotifytools_filename_from_wd(event->wd);
            if (!name) {
                continue;
            }

            len = strlen(name) + strlen(event->name) + 1;
            filename = (char *)malloc(len * sizeof(char));
            if (!filename) {
                ERR("Memory allocate\n");
                return -1;
            }
            memset(filename, 0, len);

            str = strcat(filename, name);
            str = strcat(str, event->name);

            arg = filename;
        }
#endif

        memset(path, 0, sizeof(path));
        str = path;

        if (web) {
            if (use_ssl) {
                str = strcat(str, "https://");
            } else {
                str = strcat(str, "http://");
            }
            str = strcat(str, web);
        }

        if (suffix) {
            regex_t preg;
            regmatch_t pmatch[1];
            char *regex = (char *)malloc((strlen(suffix) + 4) * sizeof(char));
            if (!regex) {
                ERR("Memory allocate\n");
                return -1;
            }

            sprintf(regex, "(%s)$", suffix);

            if (regcomp(&preg, suffix, REG_EXTENDED|REG_NEWLINE) == 0) {
                if (regexec(&preg, arg, 1, pmatch, 0) == 0) {
                    str = strncat(str, arg, (int)pmatch[0].rm_so);
                } else {
                    str = strcat(str, arg);
                }
                regfree(&preg);
            } else {
                str = strcat(str, arg);
            }

            free(regex);
        } else {
            str = strcat(str, arg);
        }

        json = json_object();
        if (!json) {
            ERR("Creating json object failed\n");
            break;
        }

        json_object_set_new(json, "command", json_string("reload"));
        json_object_set_new(json, "path", json_string(path));

        msg = json_dumps(json, json_flags);
        json_delete(json);

        DEBUG(1, "Send Message=[%s]\n", msg);

        memset(&info, 0, sizeof info);

        info.port = CONTEXT_PORT_NO_LISTEN;
        info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
        info.extensions = libwebsocket_get_internal_extensions();
#endif
        /* TODO: ssl */
        info.ssl_cert_filepath = cert_path;
        info.ssl_private_key_filepath = key_path;
        info.gid = -1;
        info.uid = -1;

        context = libwebsocket_create_context(&info);
        if (context == NULL) {
            ERR("Creating libwebsocket context failed\n");
        } else {
            host = address;

            wsi = libwebsocket_client_connect(context, address, port, use_ssl,
                                              "/", host, origin, NULL, -1);
            if (wsi == NULL) {
                ERR("libwebsocket dumb connect failed\n");
            } else if (msg) {
                libwebsocket_service(context, 30);
                libwebsocket_write(wsi, msg, strlen(msg), LWS_WRITE_TEXT);
            }

            libwebsocket_context_destroy(context);
        }

        if (msg) {
            free(msg);
        }

        if (filename) {
            free(filename);
            filename = NULL;
        }
    } while (!interrupted);

#if HAVE_INOTIFYTOOLS
    if (watch && inotify) {
        inotifytools_cleanup();
        DEBUG(1, "\nFinished\n");
    }
#endif

    return 0;
}
