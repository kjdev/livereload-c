#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef WIN32
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <regex.h>
#else
#include "win32/getopt.h"
#endif

#include <libwebsockets.h>
#include <jansson.h>

#ifdef HAVE_WATCH
#include "watcher.h"
#endif

#define HAVE_SSL
#ifndef WIN32
#define HAVE_SUFFIX
#endif

static int interrupted = 0;
static int verbose = 0;
static int quiet = 0;
static unsigned char *str = NULL;

#define DEFAULT_ADDRESS "localhost"
#define DEFAULT_PORT 35729

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define _ERR(...) fprintf(stderr, "ERR: "__VA_ARGS__)
#define _debug(l, ...) if (!quiet && verbose >= l) { printf(__VA_ARGS__); }
#define _NOTICE(l, ...) if (!quiet && verbose >= l) { lwsl_notice(__VA_ARGS__); }

static int
callback_livereload(struct libwebsocket_context *context,
                    struct libwebsocket *wsi,
                    enum libwebsocket_callback_reasons reason, void *user,
                    void *in, size_t len)
{
    return 0;
}

#ifndef WIN32
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
#else
static BOOL WINAPI
signal_handler(DWORD type)
{
    interrupted = 1;
    return TRUE;
}

static void
signals(void)
{
    SetConsoleCtrlHandler(signal_handler, TRUE);
}
#endif

static void
usage(char *arg, char *message)
{
#ifndef WIN32
    char *command = basename(arg);
#else
    char *command = arg;
#endif

    printf("Usage: %s [-a ADDRESS] [-p PORT] [-H HOST]"
#ifdef HAVE_WATCH
           " [-W]"
#endif
#ifdef HAVE_SUFFIX
           " [-s SUFFIX]"
#endif
           "\n", command);
    printf("%*s       ", (int)strlen(command), "");

#ifdef HAVE_SSL
    printf(" [-c SSL_CERT_PATH -k SSL_KEY_PATH]");
#endif
    printf(" PATH\n\n");

    printf("  -a, --addres=ADDRESS connection server address [DEFAULT: %s]\n",
           DEFAULT_ADDRESS);
    printf("  -p, --port=PORT      connection server port [DEFAULT: %d]\n",
           DEFAULT_PORT);
    printf("  -H, --host=HOST      append web host name\n");
#ifdef HAVE_WATCH
    printf("  -W, --watch          watch change file of PATH\n");
#endif
#ifdef HAVE_SUFFIX
    printf("  -s, --suffix=SUFFIX  remove a trailing SUFFIX\n");
#endif
#ifdef HAVE_SSL
    printf("  -c, --certpath=FILE  ssl certificate file path\n");
    printf("  -k, --keypath=FILE   ssl private key file path\n");
#endif
    printf("  -v, --verbose        verbosity message\n");
    printf("  -q, --quiet          quiet message\n");
#ifdef HAVE_WATCH
    printf("  PATH                 send or watch path name\n");
#else
    printf("  PATH                 send path name\n");
#endif

    if (message) {
        printf("\nINFO: %s\n", message);
    }
}

static struct libwebsocket_protocols protocols[] = {
    { "livereload", callback_livereload, 0, 0, NULL, 0 },
    { NULL, NULL, 0, 0, NULL, 0 } /* End of list */
    /*
     - name
     - callback
     - per_session_data_size, max frame size / rx buffer
     - owning_server
     - protocol_index
    */
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
#ifdef HAVE_WATCH
    watcher_t *watcher;
#endif

    struct libwebsocket_context *context;
    struct libwebsocket *wsi;
    struct lws_context_creation_info info;

    int opt;
    const struct option long_options[] = {
        { "address", 1, NULL, 'a' },
        { "port", 1, NULL, 'p' },
#ifdef HAVE_WATCH
        { "watch", 0, NULL, 'W' },
#endif
        { "suffix", 1, NULL, 's' },
        { "host", 1, NULL, 'H' },
        { "certpath", 1, NULL, 'c' },
        { "keypath", 1, NULL, 'k' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "help", 0, NULL, 0 },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "a:p:Ws:H:c:k:vs",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'W':
                watch = 1;
                break;
            case 's':
                suffix = optarg;
                break;
            case 'H':
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

#ifdef HAVE_SSL
    if (cert_path || key_path) {
        use_ssl = 1;
    }
#else
    use_ssl = 0;
    cert_path = NULL;
    key_path = NULL;
#endif

    if (quiet) {
        lws_set_log_level(-1, NULL);
    } else if (verbose == 0 || verbose == 1) {
        lws_set_log_level(LLL_WARN, NULL);
    } else if (verbose == 2) {
        lws_set_log_level(LLL_NOTICE, NULL);
    }

#ifdef HAVE_WATCH
    if (watch) {
        watcher = watcher_init();
        if (!watcher) {
            _ERR("%s\n", watcher_error());
            return -1;
        }
        if (watcher_recursively(watcher, arg) != 0) {
            _ERR("%s\n", watcher_error());
            watcher_destroy(watcher);
            return -1;
        }

        signals();

        _debug(1, "Starting watching [%s] ...\n", arg);
    } else {
        interrupted = 1;
    }
#else
    interrupted = 1;
#endif

    do {
        char *filename = NULL;

#ifdef HAVE_WATCH
        if (watch) {
            if (watcher_next_event(watcher) != 0 || interrupted) {
                break;
            }

            if (watcher_in_event(watcher) != 0) {
                continue;
            }

            filename = watcher_get_filename(watcher);
            if (!filename) {
                _ERR("Memory allocate\n");
                watcher_destroy(watcher);
                return -1;
            }

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
        } else {
            str = strcat(str, "file://");
        }

#ifdef HAVE_SUFFIX
        if (suffix) {
            regex_t preg;
            regmatch_t pmatch[1];
            char *regex = (char *)malloc((strlen(suffix) + 4) * sizeof(char));
            if (!regex) {
                _ERR("Memory allocate\n");
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
#else
        str = strcat(str, arg);
#endif

        json = json_object();
        if (!json) {
            _ERR("Creating json object failed\n");
            break;
        }

        json_object_set_new(json, "command", json_string("reload"));
        json_object_set_new(json, "path", json_string(path));

        msg = json_dumps(json, json_flags);
        json_delete(json);

        _debug(1, "Send Message=[%s]\n", msg);

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
            _ERR("Creating libwebsocket context failed\n");
        } else {
            host = address;

            wsi = libwebsocket_client_connect(context, address, port, use_ssl,
                                              "/", host, origin,
                                              "livereload", -1);
            if (wsi == NULL) {
                _ERR("libwebsocket dumb connect failed\n");
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

#ifdef HAVE_WATCH
    if (watch) {
        watcher_destroy(watcher);
    }
#endif

    _debug(1, "\nFinished\n");

    return 0;
}
