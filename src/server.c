#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>

#include <libwebsockets.h>
#include <jansson.h>

static int interrupted = 0;
static int verbose = 0;
static int quiet = 0;
static int reload_all = 0;
static unsigned char *str = NULL;

#define DEFAULT_PORT 35729
#define DEFAULT_PIDFILE "/tmp/livereload.pid"

#define MAX_MESSAGE_QUEUE 32
#define MAX_DATA_PAYLOAD 4096

#define ERR(...) fprintf(stderr, "ERR: "__VA_ARGS__)
#define DEBUG(l, ...) if (!quiet && verbose >= l) { printf(__VA_ARGS__); }
#define NOTICE(l, ...) if (!quiet && verbose >= l) { lwsl_notice(__VA_ARGS__); }

struct command_message {
    void *payload;
    char *path;
    size_t len;
};

static struct command_message rbuf[MAX_MESSAGE_QUEUE];
static int rbuf_pos = 0;

struct per_session_data_default {
    unsigned char url[LWS_SEND_BUFFER_PRE_PADDING +
                      LWS_SEND_BUFFER_POST_PADDING + MAX_DATA_PAYLOAD];
    int len;
    int rbuf_pos;
};

static int
callback_default(struct libwebsocket_context *context, struct libwebsocket *wsi,
                 enum libwebsocket_callback_reasons reason, void *user,
                 void *in, size_t len)
{
    int ret;
    json_t *json = NULL;
    struct per_session_data_default *data =
        (struct per_session_data_default *)user;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            NOTICE(2, "Established\n");
            break;
        case LWS_CALLBACK_CLOSED:
            NOTICE(2, "Close\n");
            break;
        case LWS_CALLBACK_RECEIVE:
            //char *str = (unsigned char *)in;
            str = (unsigned char *)in;
            DEBUG(1, "Receive=[%s]\n", str);
            NOTICE(2, "Receive=[%s]\n", str);

            if (!str || len == 0) {
                break;
            }
            else if (len > MAX_DATA_PAYLOAD) {
                lwsl_err("Server received packet bigger than %u\n",
                         MAX_DATA_PAYLOAD);
                return 1;
            }

            //command: hello
            if (strncmp(str, "{\"command\":\"hello\"", 18) == 0) {
                ret = libwebsocket_write(wsi, str, len, LWS_WRITE_TEXT);
                if (ret < 0) {
                    lwsl_err("Writing to socket, %d\n", ret);
                    return -1;
                }
                break;
            }

            //command: info
            if (strncmp(str, "{\"command\":\"info\"", 17) == 0) {
                json = json_loadb(str, len, JSON_DECODE_ANY, NULL);
                if (json) {
                    const char *command = NULL;
                    const char *url = NULL;
                    json_t *plugins = NULL;
                    if (json_unpack(json, "{s:s,s:O,s:s}",
                                    "command", &command,
                                    "plugins", &plugins,
                                    "url", &url) == 0 && url) {
                        data->len = (unsigned int)strlen(url);
                        data->rbuf_pos = 0;
                        strncpy(&data->url[LWS_SEND_BUFFER_PRE_PADDING],
                                url, strlen(url));
                        DEBUG(3, "DATA=[%s]\n", url);
                    }
                    json_delete(json);
                    if (plugins) {
                        json_delete(plugins);
                    }
                }
            }

            //command: reload
            if (strncmp(str, "{\"command\":\"reload\"", 19) == 0) {
                json = json_loadb(str, len, JSON_DECODE_ANY, NULL);
                if (json) {
                    const char *command = NULL;
                    const char *path = NULL;
                    if (json_unpack(json, "{s:s,s:s}",
                                    "command", &command,
                                    "path", &path) == 0 && path) {
                        size_t payload_size = LWS_SEND_BUFFER_PRE_PADDING +
                            len + LWS_SEND_BUFFER_POST_PADDING;
                        size_t path_size = strlen(path) + 1;

                        DEBUG(3, "PATH=[%s]\n", path);

                        if (rbuf[rbuf_pos].payload) {
                            free(rbuf[rbuf_pos].payload);
                        }
                        if (rbuf[rbuf_pos].path) {
                            free(rbuf[rbuf_pos].path);
                        }
                        rbuf[rbuf_pos].payload = malloc(payload_size);
                        rbuf[rbuf_pos].path = malloc(path_size);
                        rbuf[rbuf_pos].len = len;

                        memset(rbuf[rbuf_pos].payload, 0, payload_size);
                        memset(rbuf[rbuf_pos].path, 0, path_size);

                        memcpy((char *)rbuf[rbuf_pos].payload +
                               LWS_SEND_BUFFER_PRE_PADDING, in, len);
                        strcpy(rbuf[rbuf_pos].path, path);

                        if (rbuf_pos == (MAX_MESSAGE_QUEUE - 1)) {
                            rbuf_pos = 0;
                        } else {
                            rbuf_pos++;
                        }

                        DEBUG(3, "Writable all\n");
                        libwebsocket_callback_on_writable_all_protocol(
                            libwebsockets_get_protocol(wsi));
                    }
                    json_delete(json);
                }
            }
            break;
        case LWS_CALLBACK_SERVER_WRITEABLE: {
            char *url = &data->url[LWS_SEND_BUFFER_PRE_PADDING];
            int pos = data->rbuf_pos;
            if (!url || data->len <= 0 ||
                !rbuf[pos].payload || !rbuf[pos].path) {
                break;
            }

            NOTICE(2, "Writeable=[%s]\n",
                   rbuf[pos].payload + LWS_SEND_BUFFER_PRE_PADDING);
            DEBUG(3, "PATH=[%s]\n", rbuf[pos].path);
            DEBUG(3, "DATA=[%s]\n", url);

            if (reload_all == 1 ||
                strncasecmp(rbuf[pos].path, url, strlen(rbuf[pos].path)) == 0) {
                libwebsocket_write(wsi,
                                   (unsigned char *)rbuf[pos].payload +
                                   LWS_SEND_BUFFER_PRE_PADDING,
                                   rbuf[pos].len, LWS_WRITE_TEXT);
            }

            if (pos == (MAX_MESSAGE_QUEUE - 1)) {
                data->rbuf_pos = 0;
            } else {
                data->rbuf_pos++;
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            DEBUG(3, "Client established\n");
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            DEBUG(3, "Client writeable\n");
            break;
        case LWS_CALLBACK_HTTP:
            DEBUG(3, "Http\n");
            break;
        case LWS_CALLBACK_HTTP_FILE_COMPLETION:
            DEBUG(3, "Http file completion\n");
            break;
        case LWS_CALLBACK_HTTP_WRITEABLE:
            DEBUG(3, "Http writeable\n");
            break;
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
            DEBUG(3, "Filter network connection\n");
            break;
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            DEBUG(3, "Filter protocol connection\n");
            break;
        case LWS_CALLBACK_PROTOCOL_INIT:
            DEBUG(3, "Protocol init\n");
            break;
        case LWS_CALLBACK_PROTOCOL_DESTROY:
            DEBUG(3, "Protocol destroy\n");
            break;
        case LWS_CALLBACK_ADD_POLL_FD:
        case LWS_CALLBACK_DEL_POLL_FD:
        case LWS_CALLBACK_SET_MODE_POLL_FD:
        case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
        default:
            DEBUG(3, "Unhandled callback: %d\n", reason);
            break;
    }

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

    printf("Usage: %s [-p PORT] [-d COMMAND] [-P FILE] [-r]\n", command);
    printf("%*s        [-c SSL_CERT_PATH -k SSL_KEY_PATH]\n\n",
           (int)strlen(command), "");

    printf("  -p, --port=PORT         server bind port [DEFAULT: %d]\n",
           DEFAULT_PORT);
    printf("  -d, --daemonize=COMMAND daemon command [start|stop]\n");
    printf("  -P, --pidfile=FILE      daemon pid file path [DEFAULT: %s]\n",
           DEFAULT_PIDFILE);
    printf("  -r, --reloadall         all reload command\n");
    printf("  -c, --certpath=FILE     ssl certificate file path\n");
    printf("  -k, --keypath=FILE      ssl private key file path\n");
    printf("  -v, --verbose           verbosity message\n");
    printf("  -q, --quiet             quiet message\n");

    if (message) {
        printf("\nINFO: %s\n", message);
    }
}

static struct libwebsocket_protocols protocols[] = {
    {
        "default",                               /* name */
        callback_default,                        /* callback */
        sizeof(struct per_session_data_default), /* per_session_data_size */
        0,                                       /* max frame size / rx buffer */
        NULL,                                    /* owning_server */
        0                                        /* protocol_index */
    },
    { NULL, NULL, 0, 0, NULL, 0 }
};

int
main(int argc, char **argv)
{
    const char *interface = NULL;
    int port = DEFAULT_PORT;
    char *daemonize = NULL;
    char *pidfile = DEFAULT_PIDFILE;
    char *cert_path = NULL;
    char *key_path = NULL;
    int i, opts = 0;

    struct libwebsocket_context *context;
    struct lws_context_creation_info info;

    int opt;
    const struct option long_options[] = {
        { "port", 1, NULL, 'p' },
        { "daemonize", 1, NULL, 'd' },
        { "pidfile", 1, NULL, 'P' },
        { "reloadall", 0, NULL, 'r' },
        { "certpath", 1, NULL, 'c' },
        { "keypath", 1, NULL, 'k' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "help", 0, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "p:d:P:rc:k:vsq",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'd':
                daemonize = optarg;
                break;
            case 'P':
                pidfile = optarg;
                break;
            case 'r':
                reload_all = 1;
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

    if (port < 0) {
        usage(argv[0], "invalid port number");
        return -1;
    }

    if (daemonize) {
        if (!pidfile || strlen(pidfile) <= 0) {
            usage(argv[0], "unknown pid file path");
            return -1;
        }

        DEBUG(3, "PidFile=[%s]\n", pidfile);

        openlog("livereload", LOG_PID, LOG_DAEMON);
        if (strcasecmp(daemonize, "start") == 0) {
            int nochdir = 1, noclose = 0;
            pid_t pid;
            FILE *fp;

            if (daemon(nochdir, noclose) == -1) {
                syslog(LOG_INFO, "Failed to %s daemon\n", argv[0]);
                ERR("Invalid daemon start");
                return -1;
            }
            syslog(LOG_INFO, "%s daemon startted\n", argv[0]);

            pid = getpid();
            fp = fopen(pidfile, "w");
            if (fp != NULL) {
                fprintf(fp, "%d\n", pid);
                fclose(fp);
            } else {
                syslog(LOG_INFO, "Failed to record process id to file: %d\n",
                       pid);
            }
        } else if (strcasecmp(daemonize, "stop") == 0) {
            int retval;
            pid_t pid;
            FILE *fp = fopen(pidfile, "r");
            if (fp != NULL) {
                fscanf(fp, "%d\n", &pid);
                fclose(fp);
                unlink(pidfile);
                retval = kill(pid, SIGTERM);
                if (retval == 0) {
                    syslog(LOG_INFO, "%s daemon stopped\n", argv[0]);
                }
                retval = 0;
            } else {
                retval = -1;
            }
            return retval;
        } else {
            usage(argv[0], "unknown daemon command");
            return -1;
        }
    }

    if (quiet) {
        lws_set_log_level(-1, NULL);
    } else if (verbose == 0 || verbose == 1) {
        lws_set_log_level(LLL_WARN, NULL);
    } else if (verbose == 2) {
        lws_set_log_level(LLL_NOTICE, NULL);
    }

    memset(&info, 0, sizeof info);

    info.port = port;
    info.iface = interface;
    info.protocols = protocols;
#ifndef LWS_NO_EXTENSIONS
    info.extensions = libwebsocket_get_internal_extensions();
#endif
    /* TODO: ssl */
    info.ssl_cert_filepath = cert_path;
    info.ssl_private_key_filepath = key_path;
    info.gid = -1;
    info.uid = -1;
    info.options = opts;

    context = libwebsocket_create_context(&info);
    if (context == NULL) {
        ERR("libwebsocket init failed\n");
        return -1;
    }

    for (i = 0; i < MAX_MESSAGE_QUEUE; i++) {
        rbuf[i].payload = NULL;
        rbuf[i].path = NULL;
        rbuf[i].len = 0;
    }

    DEBUG(1, "Starting server [%d] ...\n", port);

    signals();

    while (!interrupted) {
        libwebsocket_service(context, 30);
    }

    libwebsocket_context_destroy(context);

    for (i = 0; i < MAX_MESSAGE_QUEUE; i++) {
        if (rbuf[i].payload) {
            free(rbuf[i].payload);
        }
        if (rbuf[i].path) {
            free(rbuf[i].path);
        }
    }

    DEBUG(1, "\nFinished\n");

    return 0;
}
