#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>

#include <fbuf.h>
#include <iomux.h>
#include <connections.h>
#include <log.h>

#include <wurfl/wurfl.h>

#define _GNU_SOURCE
#include <getopt.h>

#define WURFL_DBFILE_DEFAULT "/usr/share/wurfl/wurfl.xml"
#define WURFL_PORT_DEFAULT 4321
#define WURFL_ADDRESS_DEFAULT "*"
#define WURFL_LOGLEVEL_DEFAULT 2
#define WURFL_USERAGENT_SIZE_THRESHOLD 16

static wurfl_handle wurfl = NULL;
static iomux_t *iomux = NULL;
static char *wurfl_file = WURFL_DBFILE_DEFAULT;
static int use_http = 1;
static iomux_callbacks_t wurfld_callbacks;

typedef struct {
    fbuf_t *input;
    fbuf_t *output;
    iomux_callbacks_t *callbacks;
    int is_http10;
} wurfld_connection_context;

char *unescape_uri_request(char *uri) {
    static fbuf_t buf = FBUF_STATIC_INITIALIZER;
    fbuf_clear(&buf);
    char *p = uri;
    while (*p != 0) {
        char *n = p;
        while (*n != '%' && *n != 0)
            n++;
        fbuf_add_binary(&buf, p, n-p);
        p = n;
        if (*n != 0) {
            // p and n now both point to %
            p+=3;
            n++;
            int c;
            if (sscanf(n, "%02x", &c) == 1)
                fbuf_add_binary(&buf, (char *)&c, 1);
            else
                WARN("Can't unescape uri byte");
        }
    }
    return fbuf_data(&buf);
}

static void wurfld_get_capabilities(char *useragent, fbuf_t *output) {
    wurfl_device_handle device = wurfl_lookup_useragent(wurfl, useragent); 
    if (device) {
        int count = 0;
        fbuf_printf(output, "{\"match_type\":\"%d\",\"matcher_name\":\"%s\",\"device\":\"%s\",\"capabilities\":{",
                wurfl_device_get_match_type(device), wurfl_device_get_matcher_name(device), wurfl_device_get_id(device) );
        wurfl_device_capability_enumerator_handle enumerator = wurfl_device_get_capability_enumerator(device);
        while(wurfl_device_capability_enumerator_is_valid(enumerator)) {
            char *name = (char *)wurfl_device_capability_enumerator_get_name(enumerator);
            char *val = (char *)wurfl_device_capability_enumerator_get_value(enumerator);
            if (name && val) {
                fbuf_printf(output, "%s\"%s\":" , count ? "," : "", name);
                if (strcmp(val, "true") == 0) {
                    fbuf_add(output, "1");
                } else if (strcmp(val, "false") == 0) {
                    fbuf_add(output, "0");
                } else {
                    char *escaped_val = NULL;
                    unsigned long escaped_len = 0;
                    byte_escape('\"', '\\', val, strlen(val)+1, &escaped_val, &escaped_len);
                    if (escaped_val) {
                        fbuf_printf(output, "\"%s\"", escaped_val);
                        free(escaped_val);
                    } else {
                        fbuf_add(output, "\"\"");
                    }
                }
                count++;
            }
            wurfl_device_capability_enumerator_move_next(enumerator);
        }
        fbuf_add(output, "}}\n");
        wurfl_device_destroy(device);
        DEBUG2("returned %d capabilities", count);
    }
}

static void wurfld_connection_handler(iomux_t *iomux, int fd, void *priv) {
    DEBUG1("New connection using fd %d", fd); 
    iomux_callbacks_t *connection_callbacks = malloc(sizeof(iomux_callbacks_t));
    memcpy(connection_callbacks, &wurfld_callbacks, sizeof(iomux_callbacks_t));

    wurfld_connection_context *context = calloc(1, sizeof(wurfld_connection_context));
    context->input = fbuf_create(0);
    context->output = fbuf_create(0);
    context->callbacks = connection_callbacks;
    connection_callbacks->priv = context;

    iomux_add(iomux, fd, connection_callbacks);
}

static void wurfld_output_handler(iomux_t *iomux, int fd, void *priv) {
    wurfld_connection_context *ctx = (wurfld_connection_context *)priv;
    if (ctx) {
        DEBUG1("Flushing output on fd %d", fd);
        int len = fbuf_used(ctx->output);
        int wb = iomux_write(iomux, fd, fbuf_data(ctx->output), len);
        if (wb)
            fbuf_remove(ctx->output, wb);

        if (wb == len) {
            ctx->callbacks->mux_output = NULL;
            if (ctx->is_http10)
                iomux_close(iomux, fd);
        }
    }
}

static void wurfld_input_handler(iomux_t *iomux, int fd, void *data, int len, void *priv) {
    wurfld_connection_context *ctx = (wurfld_connection_context *)priv;
    if (!ctx)
        return;
    DEBUG1("New data on fd %d", fd);
    fbuf_add_binary(ctx->input, data, len);
    while (fbuf_used(ctx->input)) {
        char *request_data = fbuf_data(ctx->input);
        char *request_terminator = use_http ? strstr(request_data, "\r\n\r\n") : strstr(request_data, "\n");
        if (!request_terminator && use_http) {
            request_terminator = strstr(request_data, "\n\n");
        }
        if (request_terminator) {
            char *useragent = NULL;
            // we have a complete http request
            fbuf_trim(ctx->input);
            if (use_http && strncmp(request_data, "GET /lookup/", 12) == 0) {
                char *reqline_start = fbuf_data(ctx->input) + 12;
                char *reqline_end = reqline_start;

                while (*reqline_end != '\r' && *reqline_end != '\n')
                    reqline_end++;
                reqline_end++;

                char reqline[reqline_end-reqline_start];
                snprintf(reqline, reqline_end-reqline_start, "%s", reqline_start);

                char *httpv = strstr(reqline, " HTTP/1");
                if (httpv) {
                    *httpv = 0;
                    httpv++;
                    ctx->is_http10 = (strncmp(httpv, "HTTP/1.0", 8) == 0);
                }
                useragent = unescape_uri_request(reqline);
            } else if (!use_http) {
                useragent = fbuf_data(ctx->input);
            }

            if (useragent && strlen(useragent)) {
                DEBUG1("Looking up useragent : %s", useragent);
                wurfld_get_capabilities(useragent, ctx->output);

                int len = fbuf_used(ctx->output);

                if (use_http) {
                    char response_header[1024];
                    sprintf(response_header, "%s 200 OK\r\nContent-Type: application/json\r\nContent-length: %d\r\nServer: wurfld\r\n%s\r\n",
                            ctx->is_http10 ? "HTTP/1.0" : "HTTP/1.1", len, ctx->is_http10 ? "Connection: Close\r\n" : "");
                    iomux_write(iomux, fd, response_header, strlen(response_header));
                }

                int wb = iomux_write(iomux, fd, fbuf_data(ctx->output), len);
                if (wb)
                    fbuf_remove(ctx->output, wb);
                // check if we still need to write stuff (because we might have filled in the output buffer
                // and in case register an output handler to take care of that
                if (wb != len) {
                    ctx->callbacks->mux_output = wurfld_output_handler;
                    if (ctx->is_http10)
                        break;
                } else if (ctx->is_http10) {
                    iomux_close(iomux, fd);
                    break;
                }
            } else if (use_http) {
                char response[2048];
                snprintf(response, sizeof(response),
                         "%s 400 NOT SUPPORTED\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\n400 NOT SUPPORTED",
                         ctx->is_http10 ? "HTTP/1.0" : "HTTP/1.1");
                iomux_write(iomux, fd, response, strlen(response));
            }
            fbuf_remove(ctx->input, request_terminator - request_data);
            fbuf_trim(ctx->input);
        } else {
            break;
        }
    }
}

static void wurfld_eof_handler(iomux_t *iomux, int fd, void *priv) {
    DEBUG1("Connection to %d closed", fd);

    wurfld_connection_context *ctx = (wurfld_connection_context *)priv;
    if (ctx) {
        int len = fbuf_used(ctx->output);
        if (len) {
            // flush pending data
            int wb = write(fd, fbuf_data(ctx->output), len);
            while (wb != len) {
                fbuf_remove(ctx->output, wb);
                len = fbuf_used(ctx->output);
                wb = write(fd, fbuf_data(ctx->output), len);
                if (wb == -1) {
                    WARN("Connection closed while pending data still present: %s\n",
                          strerror(errno));
                    break;
                }
            }
        }
        fbuf_destroy(ctx->input);
        fbuf_destroy(ctx->output);
        free(ctx->callbacks);
        free(ctx);
    }
    close(fd);
}

static void wurfld_timeout_handler(iomux_t *iomux, int fd, void *priv) {
    // NOTE: here we can perform extra actions when idle because no i/o is in progress
}

static void usage(char *progname, char *msg) {
    if (msg)
        printf("%s\n", msg);

    printf("Usage: %s [OPTION]...\n"
           "Possible options:\n"
           "    -f                    run in foreground\n"
           "    -d <level>            debug level\n"
           "    -l <ip_address>       ip address where to listen for incoming connections\n"
           "    -p <port>             tcp port where to listen for incoming connections\n"
           "    -w <wurfl_file>       path to the wurfl xml file\n"
           "    -n                    no http, expects a raw useragent string on the connected\n"
           "                          socket, terminated by a newline\n", progname);
    exit(-2);
}

static void wurfl_init() {
    NOTICE("Initializing WURFL");
    wurfl = wurfl_create(); 
    wurfl_set_engine_target(wurfl, WURFL_ENGINE_TARGET_HIGH_PERFORMANCE);
    wurfl_set_cache_provider(wurfl, WURFL_CACHE_PROVIDER_DOUBLE_LRU, "10000,3000");
    wurfl_set_root(wurfl, wurfl_file);
    wurfl_error err = wurfl_load(wurfl);
    if (err != WURFL_OK) {
        WARN("Can't initialize wurfl %s", wurfl_get_error_message(wurfl));
        exit(-1);
    }
    NOTICE("DONE");
}

static void wurfld_reload(int sig) {
    NOTICE("reloading database");
    if (wurfl) {
        wurfl_destroy(wurfl);
        wurfl = NULL;
    }
    wurfl_init();
}

static void wurfld_stop(int sig) {
    iomux_end_loop(iomux);
}

static void wurfld_do_nothing(int sig) {
    DEBUG1("Signal %d received ... doing nothing\n", sig);
}

int main(int argc, char **argv) {

    int option_index = 0;
    int foreground = 0;
    int loglevel = WURFL_LOGLEVEL_DEFAULT;
    char *listen_address = WURFL_ADDRESS_DEFAULT;
    uint16_t listen_port = WURFL_PORT_DEFAULT;

    static struct option long_options[] = {
        {"debug", 2, 0, 'd'},
        {"foreground", 0, 0, 'f'},
        {"listen", 2, 0, 'l'},
        {"port", 2, 0, 'p'},
        {"wurfl_file", 1, 0, 'w'},
        {"nohttp", 0, 0, 'n'},
        {"help", 0, 0, 'h'},
        {0, 0, 0, 0}
    };

    char c;
    while ((c = getopt_long (argc, argv, "d:fhl:np:w:?", long_options, &option_index))) {
        if (c == -1) {
            break;
        }
        switch (c) {
            case 'd':
                loglevel = optarg ? atoi(optarg) : 1;
                break;
            case 'f':
                foreground = 1;
                break;
            case 'l':
                listen_address = optarg;
                break;
            case 'p':
                listen_port = atoi(optarg);
                break;
            case 'w':
                wurfl_file = optarg;
                break;
            case 'n':
                use_http = 0;
                break;
            case 'h':
            case '?':
                usage(argv[0], NULL);
                break;
            default:
                break;
        }
    }

    if (!foreground)
        daemon(0, 0);

    log_init("wurfld", loglevel);

    wurfl_init();

    signal(SIGHUP, wurfld_reload);
    signal(SIGINT, wurfld_stop);
    signal(SIGQUIT, wurfld_stop);
    signal(SIGPIPE, wurfld_do_nothing);

    // initialize the callbacks descriptor
    wurfld_callbacks.mux_input = wurfld_input_handler;
    wurfld_callbacks.mux_output = NULL;
    wurfld_callbacks.mux_timeout = wurfld_timeout_handler;
    wurfld_callbacks.mux_eof = wurfld_eof_handler;
    wurfld_callbacks.mux_connection = wurfld_connection_handler;
    wurfld_callbacks.priv = NULL;
 
    iomux = iomux_create();

    int listen_fd = open_socket(listen_address, listen_port);    
    if (listen_fd < 0) {
        ERROR("Can't bind address %s:%d - %s",
                listen_address, listen_port, strerror(errno));
        exit(-1);
    }
    NOTICE("Listening on %s:%d", listen_address, listen_port);

    iomux_add(iomux, listen_fd, &wurfld_callbacks);
    iomux_listen(iomux, listen_fd);

    // this takes over the runloop and handle incoming connections
    iomux_loop(iomux, 0);

    // if we are here, iomux has exited the loop
    NOTICE("exiting");
    iomux_destroy(iomux);
    wurfl_destroy(wurfl);
    close(listen_fd);
    
    exit(0);
}
