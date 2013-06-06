
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <libgen.h>
#include <regex.h>
#else
#include "win32/getopt.h"
#include "win32/string.h"
#endif

#include <libwebsockets.h>
#include <jansson.h>

#define HAVE_SSL

static int interrupted = 0;
static int verbose = 0;
static int quiet = 0;
static int all_reload = 0;
static char *script_file = NULL;
static char *resource_dir = NULL;

#define DEFAULT_PORT 35729
#define DEFAULT_PIDFILE "/tmp/livereload.pid"

#define MAX_MESSAGE_QUEUE 32
#define MAX_DATA_PAYLOAD 4096

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define _err(...) fprintf(stderr, "ERR: "__VA_ARGS__)
#define _debug(l, ...) if (!quiet && verbose >= l) { printf(__VA_ARGS__); }
#define _notice(l, ...) if (!quiet && verbose >= l) { lwsl_notice(__VA_ARGS__); }

struct command_message {
    void *payload;
    char *path;
    size_t len;
};

static struct command_message rbuf[MAX_MESSAGE_QUEUE];
static int rbuf_pos = 0;

struct per_session_data_livereload {
    char url[LWS_SEND_BUFFER_PRE_PADDING +
             LWS_SEND_BUFFER_POST_PADDING + MAX_DATA_PAYLOAD];
    int len;
    int rbuf_pos;
};

struct types {
    int html;
    const char *ext;
    const char *type;
};

static const struct types mime[] = {
    { 1, ".html", "text/html" },
    { 1, ".htm", "text/html" },
    { 0, ".ico", "image/x-ico" },
    { 0, ".png", "image/png" },
    { 0, ".jpg", "image/jpeg" },
    { 0, ".gif", "image/gif" },
    { 0, ".css", "text/css" },
    { 0, ".js", "application/javascript" },
    { 0, ".txt", "text/plain" }
};

struct per_session_data_http {
    FILE *fp;
};

static int
output_not_found(struct libwebsocket *wsi)
{
    char *buf =
        "HTTP/1.0 404 Not Found\x0d\x0a"
        "Server: livereload\x0d\x0a"
        "Content-Type: text/plain; charset=UTF-8\x0d\x0a"
        "Content-Length: 9\x0d\x0a\x0d\x0a"
        "Not Found";
    size_t size = strlen(buf);

    return libwebsocket_write(wsi, buf, size, LWS_WRITE_HTTP);
}

static int
output_html(struct libwebsocket *wsi, FILE *fp, const char *mime, size_t size)
{
    char *script =
        "<script type=\"text/javascript\" src=\"/livereload.js\"></script>\n";
    int n, m, in, out = 0;
    char *buf, *str, *head;
    char header[1024];
    size_t len, script_len;

    script_len = strlen(script);

    buf = (char *)malloc(size + 1);
    if (!buf) {
        return -1;
    }

    memset(buf, 0, size + 1);
    in = fread(buf, 1, size, fp);
    if (in <= 0) {
        free(buf);
        return -1;
    }

    len = in;
    head = strcasestr(buf, "</head>");
    if (head != NULL) {
        len = size + script_len;
    }

    memset(header, 0, sizeof(header));
    sprintf(header,
            "HTTP/1.0 200 OK\x0d\x0a"
            "Server: libwebsockets\x0d\x0a"
            "Content-Type: %s\x0d\x0a"
            "Content-Length: %u\x0d\x0a\x0d\x0a",
            mime, (unsigned int)len);
    if (libwebsocket_write(wsi, header, strlen(header), LWS_WRITE_HTTP) < 0) {
        free(buf);
        return -1;
    }

    str = buf;

    while (!lws_send_pipe_choked(wsi)) {
        if (str == NULL) {
            memset(buf, 0, size + 1);
            in = fread(buf, 1, size, fp);
        }

        if (in > 0) {
            if (head != NULL) {
                m = head - buf;
                n = libwebsocket_write(wsi, buf, m, LWS_WRITE_HTTP);
                if (n < 0) {
                    free(buf);
                    return -1;
                }
                str = head;
                len -= m;
                out += n;

                n = libwebsocket_write(wsi, script, script_len, LWS_WRITE_HTTP);
                if (n < 0) {
                    free(buf);
                    return -1;
                }

                len -= script_len;
                out += n;

                head = NULL;
            }

            n = libwebsocket_write(wsi, str, len, LWS_WRITE_HTTP);
            if (n < 0) {
                free(buf);
                return -1;
            }
            out += n;

            if (in != out) {
                fseek(fp, out - in, SEEK_CUR);
            }

            str = NULL;
        } else if (in < 0) {
            free(buf);
            return -1;
        } else {
            break;
        }
    }

    free(buf);

    return 0;
}

static int
callback_http(struct libwebsocket_context *context, struct libwebsocket *wsi,
              enum libwebsocket_callback_reasons reason, void *user,
              void *in, size_t len)
{
    int n;
    char path[PATH_MAX];
    char buffer[BUFSIZ];
    char *str;
    struct stat st;
    struct per_session_data_http *data = (struct per_session_data_http *)user;

    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            char *ext, *dir;
            char *file = (char *)in;
            if (!file) {
                break;
            }

            _debug(1, "HTTP Request File=[%s]\n", file);

            ext = strrchr(file, '.');
            if (!ext) {
                ext = file;
            }

            dir = strrchr(file, '/');
            if (!dir) {
                dir = file;
            }

            if (resource_dir) {
                sprintf(path, "%s%s", resource_dir, file);
            } else {
                sprintf(path, ".%s", file);
            }
            _debug(1, "HTTP Resouce File=[%s]\n", path);

            if ((int)(dir - ext) >= 0) {
                if (path[strlen(path)-1] != '/') {
                    strcat(path, "/");
                }
                strcat(path, "index.html");
                n = 0;
            } else {
                for (n = 0;
                     n < (int)(sizeof(mime) / sizeof(mime[0]) - 1);
                     n++) {
                    if (strcmp(ext, mime[n].ext) == 0) {
                        break;
                    }
                }
            }

            _debug(1, "Mime-Type=[%s]\n", mime[n].type);
            _debug(1, "Request Path=[%s]\n", path);

            if (stat(path, &st) == 0) {
                _debug(3, "Open File=[%s]\n", path);
                str = buffer;
                data->fp = fopen(path, "rb");
                if (!data->fp) {
                    return -1;
                }
                if (mime[n].html) {
                    output_html(wsi, data->fp, mime[n].type, st.st_size);
                    fclose(data->fp);
                    data->fp = NULL;
                } else {
                    str += sprintf((char *)str,
                                   "HTTP/1.0 200 OK\x0d\x0a"
                                   "Server: libwebsockets\x0d\x0a"
                                   "Content-Type: %s\x0d\x0a"
                                   "Content-Length: %u\x0d\x0a\x0d\x0a",
                                   mime[n].type, (unsigned int)st.st_size);
                    if (libwebsocket_write(wsi, buffer, str - buffer,
                                           LWS_WRITE_HTTP) < 0) {
                        fclose(data->fp);
                        data->fp = NULL;
                        return -1;
                    }
                }
            } else if (strcmp(file, "/livereload.js") == 0) {
                _debug(3, "Open Script File=[%s]\n", script_file);
                if (script_file && stat(script_file, &st) == 0) {
                    data->fp = fopen(script_file, "r");
                    if (!data->fp) {
                        return -1;
                    }
                    str = buffer;
                    str += sprintf((char *)str,
                                   "HTTP/1.0 200 OK\x0d\x0a"
                                   "Server: libwebsockets\x0d\x0a"
                                   "Content-Type: application/javascript\x0d\x0a"
                                   "Content-Length: %u\x0d\x0a\x0d\x0a",
                                   (unsigned int)st.st_size);
                    if (libwebsocket_write(wsi, buffer, str - buffer,
                                           LWS_WRITE_HTTP) < 0) {
                        fclose(data->fp);
                        data->fp = NULL;
                        return -1;
                    }
                } else {
                    data->fp = NULL;
                    if (output_not_found(wsi) < 0) {
                        return -1;
                    }
                }
            } else {
                _debug(3, "Not Found\n");
                data->fp = NULL;
                if (output_not_found(wsi) < 0) {
                    return -1;
                }
            }
            libwebsocket_callback_on_writable(context, wsi);
            break;
        }
        case LWS_CALLBACK_HTTP_FILE_COMPLETION:
            return -1;
        case LWS_CALLBACK_HTTP_WRITEABLE:
            if (!data->fp) {
                return -1;
            }

            while (!lws_send_pipe_choked(wsi)) {
                int in = 0, out = 0;
                memset(buffer, 0, sizeof(buffer));
                in = fread(buffer, 1, sizeof(buffer), data->fp);
                if (in > 0) {
                    out = libwebsocket_write(wsi, buffer, in, LWS_WRITE_HTTP);
                    if (out < 0) {
                        fclose(data->fp);
                        data->fp = NULL;
                        return -1;
                    }
                    if (in != out) {
                        fseek(data->fp, out - in, SEEK_CUR);
                    }
                } else {
                    fclose(data->fp);
                    data->fp = NULL;
                    return -1;
                }
            }
            libwebsocket_callback_on_writable(context, wsi);
            break;
        default:
            //_debug(3, "Unhandled callback: %d\n", reason);
            break;
    }

    return 0;
}

static void
livereload_handshake_info(struct libwebsocket *wsi, int level)
{
    int n;
    static const char *token_names[WSI_TOKEN_COUNT] = {
        "GET URI",    /* WSI_TOKEN_GET_URI */
        "Host",       /* WSI_TOKEN_HOST */
        "Connection", /* WSI_TOKEN_CONNECTION */
        "key 1",      /* WSI_TOKEN_KEY1 */
        "key 2",      /* WSI_TOKEN_KEY2 */
        "Protocol",   /* WSI_TOKEN_PROTOCOL */
        "Upgrade",    /* WSI_TOKEN_UPGRADE */
        "Origin",     /* WSI_TOKEN_ORIGIN */
        "Draft",      /* WSI_TOKEN_DRAFT */
        "Challenge",  /* WSI_TOKEN_CHALLENGE */
        "Key",        /* WSI_TOKEN_KEY */
        "Version",    /* WSI_TOKEN_VERSION */
        "Sworigin",   /* WSI_TOKEN_SWORIGIN */
        "Extensions", /* WSI_TOKEN_EXTENSIONS */
        "Accept",     /* WSI_TOKEN_ACCEPT */
        "Nonce",      /* WSI_TOKEN_NONCE */
        "Http",       /* WSI_TOKEN_HTTP */
        "MuxURL",     /* WSI_TOKEN_MUXURL */
    };
    char buf[256];

    for (n = 0; n < WSI_TOKEN_COUNT; n++) {
        if (!lws_hdr_total_length(wsi, n)) {
            continue;
        }
        lws_hdr_copy(wsi, buf, sizeof buf, n);
        _debug(level, "  %s = %s\n", token_names[n], buf);
    }
}

static int
callback_livereload(struct libwebsocket_context *context,
                    struct libwebsocket *wsi,
                    enum libwebsocket_callback_reasons reason, void *user,
                    void *in, size_t len)
{
    int ret;
    json_t *json = NULL;
    struct per_session_data_livereload *data =
        (struct per_session_data_livereload *)user;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            _notice(2, "Established\n");
            break;
        case LWS_CALLBACK_CLOSED:
            _notice(2, "Close\n");
            break;
        case LWS_CALLBACK_RECEIVE: {
            char *str = (char *)in;
            _notice(1, "Receive=[%s]:\n", str);

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
                        _debug(3, "DATA=[%s]\n", url);
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

                        _debug(3, "PATH=[%s]\n", path);

                        if (rbuf[rbuf_pos].payload) {
                            free(rbuf[rbuf_pos].payload);
                        }
                        if (rbuf[rbuf_pos].path) {
                            free(rbuf[rbuf_pos].path);
                        }
                        rbuf[rbuf_pos].payload = malloc(payload_size);
                        rbuf[rbuf_pos].path = (char *)malloc(path_size);
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

                        _debug(3, "Writable all\n");
                        libwebsocket_callback_on_writable_all_protocol(
                            libwebsockets_get_protocol(wsi));
                    }
                    json_delete(json);
                }
            }
            break;
        }
        case LWS_CALLBACK_SERVER_WRITEABLE: {
            char *url = &data->url[LWS_SEND_BUFFER_PRE_PADDING];
            int pos = data->rbuf_pos;
            if (!url || data->len <= 0 ||
                !rbuf[pos].payload || !rbuf[pos].path) {
                break;
            }

            _notice(2, "Writeable=[%s]\n",
                    (char *)rbuf[pos].payload + LWS_SEND_BUFFER_PRE_PADDING);
            _debug(3, "PATH=[%s]\n", rbuf[pos].path);
            _debug(3, "DATA=[%s]\n", url);

            if (all_reload == 1 ||
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
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION:
            _notice(2, "Filter protocol connection\n");
            if (verbose >= 2) {
                livereload_handshake_info(wsi, 2);
            }
            break;
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            _debug(3, "Client established\n");
            break;
        case LWS_CALLBACK_CLIENT_WRITEABLE:
            _debug(3, "Client writeable\n");
            break;
        case LWS_CALLBACK_HTTP:
            _debug(3, "Http\n");
            break;
        case LWS_CALLBACK_HTTP_FILE_COMPLETION:
            _debug(3, "Http file completion\n");
            break;
        case LWS_CALLBACK_HTTP_WRITEABLE:
            _debug(3, "Http writeable\n");
            break;
        case LWS_CALLBACK_FILTER_NETWORK_CONNECTION:
            _debug(3, "Filter network connection\n");
            break;
        case LWS_CALLBACK_PROTOCOL_INIT:
            _debug(3, "Protocol init\n");
            break;
        case LWS_CALLBACK_PROTOCOL_DESTROY:
            _debug(3, "Protocol destroy\n");
            break;
        case LWS_CALLBACK_ADD_POLL_FD:
        case LWS_CALLBACK_DEL_POLL_FD:
        case LWS_CALLBACK_SET_MODE_POLL_FD:
        case LWS_CALLBACK_CLEAR_MODE_POLL_FD:
        default:
            _debug(3, "Unhandled callback: %d\n", reason);
            break;
    }

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

    printf("Usage: %s [-p PORT] [-R PATH] [-s FILE] [-A]", command);
#ifndef WIN32
    printf("\n%*s        [-d COMMAND] [-P FILE]", (int)strlen(command), "");
#endif
    printf("\n");

#ifdef HAVE_SSL
    printf("%*s        [-c SSL_CERT_PATH -k SSL_KEY_PATH]",
           (int)strlen(command), "");
#endif
    printf("\n\n");

    printf("  -p, --port=PORT         server bind port [DEFAULT: %d]\n",
           DEFAULT_PORT);
    printf("  -R, --resourcedir=PATH  resource path of simple web server\n");
    printf("  -s, --script=FILE       livereload.js script file path.\n");
    printf("  -A, --allreload         all reload command\n");
#ifndef WIN32
    printf("  -d, --daemonize=COMMAND daemon command [start|stop]\n");
    printf("  -P, --pidfile=FILE      daemon pid file path [DEFAULT: %s]\n",
           DEFAULT_PIDFILE);
#endif
#ifdef HAVE_SSL
    printf("  -c, --certpath=FILE     ssl certificate file path\n");
    printf("  -k, --keypath=FILE      ssl private key file path\n");
#endif
    printf("  -v, --verbose           verbosity message\n");
    printf("  -q, --quiet             quiet message\n");

    if (message) {
        printf("\nINFO: %s\n", message);
    }
}

static struct libwebsocket_protocols protocols[] = {
    { "http", callback_http,
      sizeof(struct per_session_data_http), 0, NULL, 0 },
    { "livereload", callback_livereload,
      sizeof(struct per_session_data_livereload), 0, NULL, 0 },
    { NULL, NULL, 0, 0, NULL, 0 }
    /*
     - name
     - callback
     - per_session_data_size, max frame size / rx buffer
     - owning_server
     - protocol_index
    */
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
        { "resourcedir", 1, NULL, 'R' },
        { "script", 1, NULL, 's' },
        { "daemonize", 1, NULL, 'd' },
        { "pidfile", 1, NULL, 'P' },
        { "allreload", 0, NULL, 'A' },
        { "certpath", 1, NULL, 'c' },
        { "keypath", 1, NULL, 'k' },
        { "verbose", 1, NULL, 'v' },
        { "quiet", 0, NULL, 'q' },
        { "help", 0, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "p:R:s:d:P:Ac:k:vsq",
                              long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'R':
                resource_dir = optarg;
                break;
            case 's':
                script_file = optarg;
                break;
            case 'd':
                daemonize = optarg;
                break;
            case 'P':
                pidfile = optarg;
                break;
            case 'A':
                all_reload = 1;
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

#ifndef WIN32
    if (daemonize) {
        if (!pidfile || strlen(pidfile) <= 0) {
            usage(argv[0], "unknown pid file path");
            return -1;
        }

        _debug(3, "PidFile=[%s]\n", pidfile);

        openlog("livereload", LOG_PID, LOG_DAEMON);
        if (strcasecmp(daemonize, "start") == 0) {
            int nochdir = 1, noclose = 0;
            pid_t pid;
            FILE *fp;

            if (daemon(nochdir, noclose) == -1) {
                syslog(LOG_INFO, "Failed to %s daemon\n", argv[0]);
                _err("Invalid daemon start");
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
#endif

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
        _err("libwebsocket init failed\n");
        return -1;
    }

    for (i = 0; i < MAX_MESSAGE_QUEUE; i++) {
        rbuf[i].payload = NULL;
        rbuf[i].path = NULL;
        rbuf[i].len = 0;
    }

    _debug(1, "Starting server [%d] ...\n", port);

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

    _debug(1, "\nFinished\n");

    return 0;
}
