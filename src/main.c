/**
 * The base network/socket programming and poll structure stuff is based on
 * Beej's network programming guide. https://beej.us/guide/bgnet/html/.
 */
#define _GNU_SOURCE

#include "ht.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: take in as args
#define PORT "8080"
#define CONTENT_PATH "content"
// max number of incoming connections the kernel will buffer
#define BACKLOG 10
// the max number of events epoll will notify us about each time. Not sure how
// this affects performance
#define EPOLL_MAX_EVENTS 100
// size of the buffer (in bytes) into which we read data sent to us by HTTP
// clients connecting to us. 131072 is the kernel's default receive buffer size
// on the platform this will primarily be running on (check with `cat
// /proc/sys/net/ipv4/tcp_rmem`)
#define CLIENT_BUFFER_LEN 131072
// quick max length of the `GET <path> HTTP x.y` line in a request we'll accept.
// Suggested number from RFC 9112. Would make more sense to calculate something
// closer to the max path length we'll generate.
#define MAX_REQUEST_LINE_LENGTH 8000
// if we're waiting for more data from a connection and we don't receive any for
// this many seconds, we'll close it.
#define SESSION_TIMEOUT_SEC 5
// return codes for try_parse_request_path().

// to prevent user-initiated filesystem interaction, and to avoid having to
// worry about path cleaning, load all content into memory on startup, and
// access via hash table keyed on HTTP request path.
// unfortunately it needs to be a global var because we walk the content dir
// with ntfw(), and its callback function doesn't have any user parameters.
ht *content_ht;
// same, needs to be global for the callback
char *content_dir_path = CONTENT_PATH;

typedef enum
{
    // not enough data to determine the requested path yet
    TPRP_NEEDMOREDATA,
    // we have enough data to say that the request doesn't start properly. It's
    // a bad request and the session should be closed.
    TPRP_NOPREFIX,
    // we've reached the maximum line length we'll try parsing, without finding
    // a path. It's a bad request and the session should be closed.
    TPRP_TOOLONG,
    // we've successfully parsed the path.
    TPRP_PARSED,
} tprp_rv;

/**
 * We pass a few different structs to epoll to return to us, as a union. This
 * differentiates between them.
 */
typedef enum
{
    // listen socket
    EPT_LISTEN,
    // per-connection socket
    EPT_CONNECTION,
    // timerfd
    EPT_TIMEOUT,
} event_ptr_type;

// forward declaration so session_t can use it.
typedef struct timeout_t timeout_t;

/**
 * A HTTP request/response section. A pointer to one of these is passed to each
 * connection entry stored in our epoll instance. Allows us to buffer data
 * across multiple epoll loops as we wait for it all to come in or go out.
 *
 * use session_new() / session_delete().
 *
 * Strings are not NUL-terminated, use the related length var.
 */
typedef struct
{
    // which of the union structs this struct is
    event_ptr_type type;

    // the socket fd this session is associated with. epoll's fd and data
    // storage is a union, so we have to re-include it now that we're asking
    // epoll to track custom data for us.
    int fd;

    // the HTTP request text.
    char *request;
    // number of chars in request so far.
    size_t request_len;
    // if request_path_len is > 0, the relative path parsed from request. e.g.
    // in http://example.com/path/file.html it would be /path/file.html. in
    // http://example.com it would be /. It's the <path> in `GET <path> HTTP
    // x.y`.
    char *request_path;
    // number of chars in request_path.
    size_t request_path_len;

    // the HTTP response when we generate it.
    uint8_t *response;
    // number of chars in response.
    size_t response_len;
    // the number of chars from response that we've sent so far
    size_t response_sent_len;

    // the timer that has been set to close this session if there isn't more
    // request data within a short enough time.
    timeout_t *timeout;

} session_t;

/**
 * Event data passed to epoll for listen sockets.
 *
 * use listen_sock_new() / listen_sock_delete().
 *
 */
typedef struct
{
    // which of the union structs this struct is
    event_ptr_type type;

    // the socket fd this listen_sock is associated with. epoll's fd and data
    // storage is a union, so we have to re-include it now that we're asking
    // epoll to track custom data for us.
    int fd;

} listen_sock_t;

/**
 * Event data passed to epoll for timers that we use to close sessions that
 * haven't been active in a while, to prevent them hanging around too long.
 *
 * use timeout_new() / timeout_delete().
 *
 * (named because we need to forward-declare above).
 */
typedef struct timeout_t
{
    // which of the union structs this struct is
    event_ptr_type type;

    // the socket fd this timer is associated with. epoll's fd and data
    // storage is a union, so we have to re-include it now that we're asking
    // epoll to track custom data for us.
    int fd;

    // the session that we should close if our timer is triggered.
    session_t *session;

} timeout_t;

/**
 * We have epoll monitor 3 distinct things, and track a pointer to some data for
 * them.
 */
typedef union
{
    listen_sock_t listen_sock;
    session_t session;
    timeout_t timeout;
} uh_epoll_data;

/**
 * A http response resource (.html, .jpg, .css file etc) we load from disk.
 */
typedef struct
{
    uint8_t *content;
    size_t content_len;
} content_t;

/**
 * If return_value is -1, prints "<prefix>: <string description of errno>" then
 * exits with a return code of 1.
 */
void check_error(int return_value, const char *prefix)
{
    if (return_value == -1)
    {
        // using this instead of perror so that we can get it into stdout
        // instead of stderr, to maintain log ordering. Otherwise buffering can
        // put things confusingly out of order
        printf("%s: %s\n", prefix, strerror(errno));
        exit(1);
    }
}

/**
 * Same as check_error but for getaddrinfo().
 */
void check_error_gai(int return_value, const char *prefix)
{
    if (return_value != 0)
    {
        printf("%s: %s\n", prefix, gai_strerror(return_value));
        exit(1);
    }
}

/**
 * Same as check_error but for void pointers that return NULL on error.
 */
void check_error_null(void *return_value, const char *prefix)
{
    if (return_value == NULL)
    {
        printf("%s: %s\n", prefix, strerror(errno));
        exit(1);
    }
}

/**
 * Like check_error but with no exit.
 */
void print_if_error(int return_value, const char *prefix)
{
    if (return_value == -1)
    {
        printf("%s: %s\n", prefix, strerror(errno));
    }
}

/**
 * Use to construct all session_t's. Allocates and
 * initializes.
 */
uh_epoll_data *session_new()
{
    uh_epoll_data *s = malloc(sizeof *s);
    check_error_null(s, "malloc session_new");
    s->session.type = EPT_CONNECTION;
    s->session.fd = -1;
    s->session.request = NULL;
    s->session.request_len = 0;
    s->session.request_path = NULL;
    s->session.request_path_len = 0;
    s->session.response = NULL;
    s->session.response_len = 0;
    s->session.response_sent_len = 0;
    s->session.timeout = NULL;

    return s;
}

/**
 * Deallocates all memory for session. Doesn't deallocate timeout.
 */
void session_delete(session_t *session)
{
    free(session->request);
    free(session->request_path);
    free(session->response);
    free(session);
}

/**
 * Use to construct all listen_sock_t's. Allocates and initializes.
 */
uh_epoll_data *listen_sock_new()
{
    uh_epoll_data *l = malloc(sizeof *l);
    check_error_null(l, "malloc listen_sock_new");
    l->listen_sock.type = EPT_LISTEN;
    l->listen_sock.fd = -1;

    return l;
}

/**
 * Deallocates all memory for listen_sock.
 */
void listen_sock_delete(listen_sock_t *listen_sock) { free(listen_sock); }

/**
 * Use to construct all timeout_t's. Allocates and initializes.
 */
uh_epoll_data *timeout_new()
{
    uh_epoll_data *t = malloc(sizeof *t);
    check_error_null(t, "malloc timeout_new");
    t->timeout.type = EPT_TIMEOUT;
    t->timeout.fd = -1;
    t->timeout.session = NULL;

    return t;
}

/**
 * Deallocates all memory for timeout. Doesn't deallocate session.
 */
void timeout_delete(timeout_t *timeout) { free(timeout); }

/**
 * Returns in out_str, the IP referenced by addrinfo. out_str should be `char
 * example[INET6_ADDRSTRLEN]` to fit an IPv6 address.
 *
 * Copied from Beej's guide
 */
void addrinfo_ip_str(const struct addrinfo *in_addrinfo, char *out_str,
                     int out_str_len)
{
    void *addr;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    // get the pointer to the address itself, different fields in IPv4 and IPv6:
    if (in_addrinfo->ai_family == AF_INET)
    { // IPv4
        ipv4 = (struct sockaddr_in *)in_addrinfo->ai_addr;
        addr = &(ipv4->sin_addr);
    }
    else
    { // IPv6
        ipv6 = (struct sockaddr_in6 *)in_addrinfo->ai_addr;
        addr = &(ipv6->sin6_addr);
    }

    inet_ntop(in_addrinfo->ai_family, addr, out_str, out_str_len);
}

/**
 * Prints len chars from buffer to stdout. wraps in newlines and `==========`
 * separators. the start and end content is immediately delimited by `||`.
 *
 * reading all the non-printable characters is best done with something like
 * `make run | batcat --show-all --pager=never`.
 */
void print_buffer(void *buffer, int len)
{
    // %.*s is the format to
    // print a specific number of a characters, instead of a
    // NUL-terminated string
    printf("\n==========\n||");
    printf("%.*s", len, (char *)buffer);
    printf("||\n==========\n\n");
    // force printf to actually output, without appending a \n
    fflush(stdout);
}

// run through all the syscalls to get us to a point where we're listening on a
// port, and return those listening sockets.
//
// Can return multiple because we listen on all IPs we can (IPv4 and IPv6
// wildcard IPs - so all), but currently only returns one: it turns out that if
// you request to listen on the IPv6 wildcard address with the default settings,
// it's dual-stack anyway.
void create_listen_sockets(int **out_listen_fds, int *out_listen_fds_len)
{
    // detail our desired bind type, and get results back about what we can
    // potentially bind to
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    // this is actually dual-stack, so gives us IPv4 as well
    hints.ai_family = AF_INET6;
    // TCP
    hints.ai_socktype = SOCK_STREAM;
    // from the man page: when combined with NULL in the getaddrinfo call,
    // setting AI_PASSIVE here returns the wildcard addresses, which will listen
    // on all IPs when we bind to them.
    hints.ai_flags = AI_PASSIVE;
    // this is a pointer, which we will pass to getaddrinfo via another pointer,
    // because getaddrinfo needs to control the return size of the linked-list,
    // and it can't do that to a local array/list (the same reason for the
    // double pointer argument to to our function).
    struct addrinfo *results;
    getaddrinfo(NULL, PORT, &hints, &results);

    int yes = 1;
    char ipstr[INET6_ADDRSTRLEN];
    if (*out_listen_fds != NULL)
        free(*out_listen_fds);
    *out_listen_fds_len = 0;
    // listen on every IP we can. There should be two - the IPv4 and IPv6
    // wildcard IPs
    for (struct addrinfo *result = results; result != NULL;
         result = result->ai_next)
    {
        // the `sizeof <array>` only works within the function where the array
        // was defined. and `sizeof <array>` instead of `sizeof <array> * sizeof
        // <array type>` only works because `sizeof char` is 1 anyway.
        addrinfo_ip_str(result, ipstr, sizeof ipstr);
        printf("attempting to listen on %s\n", ipstr);

        int socket_fd =
            socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        check_error(socket_fd, "socket()");

        // avoid "address already in use errors" - linux prevents re-use for a
        // small while, if the server-side closes a connection and it's left in
        // TIME_WAIT
        int sso_rv =
            setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        check_error(sso_rv, "setsockopt");

        int b_rv = bind(socket_fd, result->ai_addr, result->ai_addrlen);
        check_error(b_rv, "bind");

        int l_rv = listen(socket_fd, BACKLOG);
        check_error(l_rv, "listen");

        // if we're here, we're listening on this address/socket. Record its fd.
        // resize the array first
        (*out_listen_fds_len)++;
        *out_listen_fds = realloc(*out_listen_fds, sizeof(**out_listen_fds) *
                                                       (*out_listen_fds_len));
        check_error_null(*out_listen_fds, "realloc out_listen_fds");
        (*out_listen_fds)[*out_listen_fds_len - 1] = socket_fd;

        printf("listening on %s\n", ipstr);
    }

    freeaddrinfo(results);
}

/**
 * Shared functionality in the epoll loop for closing a client session we no
 * longer need. Includes removing and cleaning up the associated timer.
 */
void close_session(session_t *session, int epoll_fd)
{
    printf("closing session fd %d\n", session->fd);
    int ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, session->fd, NULL);
    check_error(ectl_rv, "close_session epoll_ctl");
    close(session->fd);
    timeout_t *timeout = session->timeout;
    session_delete(session);

    ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, timeout->fd, NULL);
    check_error(ectl_rv, "close_session epoll_ctl");
    close(timeout->fd);
    timeout_delete(timeout);
}

/**
 * Tries to extract the requested relative path from session->request, into
 * session->request_path. Success can be determined by checking if
 * session->request_path_len is > 0, or checking the return code. Return codes
 * return TPRP_* values, and should be checked. Some indicate that it's bad data
 * and the session should be closed.
 */
tprp_rv try_parse_request_path(session_t *session)
{
    static char *http_get_prefix = "GET ";
    static int http_get_prefix_len = 4;

    // the buffer we're trying to parse needs to at least be as long as the
    // prefix we're checking for
    if (session->request_len < strlen(http_get_prefix))
        return TPRP_NEEDMOREDATA;

    // the first line (the only line we're parsing) needs to be a reasonable
    // length
    if (session->request_len > MAX_REQUEST_LINE_LENGTH)
        return TPRP_TOOLONG;

    // it needs to start with `GET `
    if (memcmp(session->request, http_get_prefix, http_get_prefix_len) != 0)
        return TPRP_NOPREFIX;

    // there needs to be another space after the path
    void *trailing_space = memchr(session->request + http_get_prefix_len, ' ',
                                  session->request_len - http_get_prefix_len);
    if (trailing_space == NULL)
        return TPRP_NEEDMOREDATA;

    // everything is satisfied, pull out the path.

    // path length is the distance between the trailing space's pointer and the
    // start of the line's pointer, minus the prefix length
    session->request_path_len =
        trailing_space - (void *)session->request - http_get_prefix_len;
    session->request_path = malloc(session->request_path_len);
    check_error_null(session->request_path, "malloc session->request_path");
    memcpy(session->request_path, session->request + http_get_prefix_len,
           session->request_path_len);
    return TPRP_PARSED;
}

/**
 * Based on session->request_path, generates the HTML response to send back, and
 * stores it in session->response.
 */
void generate_response(session_t *session)
{
    if (session->request_len == 0)
    {
        printf("generate_response(): request_len is 0\n");
        return;
    }

    // our struct strings are all length-delimited, but ht uses null-terminated
    // strings. The paths we get in are user-controlled. I don't want to rewrite
    // ht to support length-delimited strings, so we'll just add a null
    // terminator here to guarantee the string we get from the user always has
    // one (load_content() which we control ensures our keys have them too). In
    // the correct case, our non-null-terminated path will get a single null
    // terminator at the end. In a malicious case, if a user inserts a null
    // terminator in the path, it just won't match a key and no content will be
    // returned. ht_get() and its underlying functions don't do anything strange
    // to the key.
    char *null_term_path = malloc(session->request_path_len + 1);
    check_error_null(null_term_path, "malloc null_term_path");
    strncpy(null_term_path, session->request_path, session->request_path_len);
    null_term_path[session->request_path_len] = '\0';

    content_t *content = ht_get(content_ht, null_term_path);
    free(null_term_path);

    if (content == NULL)
    {
        // content not found, return a 404
        static char *fof = "HTTP/1.0 404 Not Found\r\n"
                           "Server: unsafehttp\r\n"
                           "Connection: close\r\n"
                           "Content-Type: text/html\r\n"
                           "Content-Length: 28\r\n"
                           "\r\n"
                           "<html>404 Not Found</html>\r\n";
        session->response = malloc(strlen(fof));
        check_error_null(session->response, "malloc session->response");
        memcpy(session->response, fof, strlen(fof));
        session->response_len = strlen(fof);
    }
    else
    {
        // found some content to return. construct a response and send it.

        // prepare to convert content-length to str. calling snprintf like this
        // gives you the required string length of the converted value
        int content_len_str_len =
            snprintf(NULL, 0, "%zu", content->content_len);

        // prepare each part of the response, calculate size and allocate space,
        // copy into the session data

        static char *prefix = "HTTP/1.0 200 OK\r\n"
                              "Server: unsafehttp\r\n"
                              "Connection: close\r\n"
                              "Content-Type: text/html\r\n"
                              "Content-Length: ";
        static char *middle = "\r\n"
                              "\r\n";

        session->response_len = strlen(prefix) + content_len_str_len +
                                strlen(middle) + content->content_len;

        session->response = malloc(session->response_len);
        check_error_null(session->response, "malloc session->response");

        void *memcpy_rv = memcpy(session->response, prefix, strlen(prefix));
        check_error_null(memcpy_rv, "generate_response 200 memcpy 1");

        // +1 because snprintf will truncate to fit the null terminator. We'll overwrite it
        snprintf((char *)session->response + strlen(prefix), content_len_str_len + 1, "%zu",
                 content->content_len);

        memcpy_rv =
            memcpy(session->response + strlen(prefix) + content_len_str_len,
                   middle, strlen(middle));
        check_error_null(memcpy_rv, "generate_response 200 memcpy 2");

        memcpy_rv = memcpy(session->response + strlen(prefix) +
                               content_len_str_len + strlen(middle),
                           content->content, content->content_len);
        check_error_null(memcpy_rv, "generate_response 200 memcpy 3");
    }
}

/**
 * Tries to send the entire session->response to the non-blocking socket fd.
 * Tracks the amount sent in session->response_sent_len. If a fatal error is
 * received, will close the session. If a write would block, modifies the epoll
 * entry to notify when writes are possible again - in this case (EPOLLOUT is
 * received), call this function again and it will continue sending from where
 * it left off.
 */
void send_response(int fd, session_t *session, struct epoll_event *epoll_events,
                   int i, int epoll_fd)
{
    // start with a standard send-all-bytes loop
    while (session->response_sent_len < session->response_len)
    {
        // try to send all the remaining bytes. start from where we're up to if
        // we'd already sent some previously
        int num_bytes_sent =
            write(fd, session->response + session->response_sent_len,
                  session->response_len - session->response_sent_len);

        // failed to send this time, but might not be fatal
        if (num_bytes_sent == -1)
        {
            // we're using non-blocking sockets, so check if it's a potential
            // block
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("got EAGAIN or EWOULDBLOCK\n");
                // if it is, then ask epoll to tell us when we can write again
                epoll_events[i].events |= EPOLLOUT;
                int ectl_rv =
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &epoll_events[i]);
                check_error(ectl_rv, "close_session epoll_ctl");
            }
            else
            {
                // otherwise log and close
                print_if_error(num_bytes_sent, "send_response");
                close_session(session, epoll_fd);
            }

            break;
        }
        else
        {
            // we sent some data. track it, then let the loop try again if
            // required
            session->response_sent_len += num_bytes_sent;
            printf("sent %d bytes\n", num_bytes_sent);
        }
    }

    // if we've sent everything, we're done with this session
    if (session->response_sent_len == session->response_len)
        close_session(session, epoll_fd);
}

/**
 * Per-file callback function for load_content
 */
int load_content_file(const char *fpath, const struct stat *sb, int typeflag,
                      struct FTW *ftwbuf)
{
    // ignore directories
    if (typeflag != FTW_F)
        return 0;

    printf("lcf: %s, %d, %d\n", fpath, ftwbuf->base, ftwbuf->level);

    // read the file into memory, and pre-prepare a HTTP response based on it.
    // global/singleton data - not freeing. See end of main().

    uint8_t *content_bytes = malloc(sb->st_size);
    check_error_null(content_bytes, "load_content_file malloc");

    FILE *f = fopen(fpath, "rb");
    check_error_null(f, "fopen");
    int num_read = fread(content_bytes, sb->st_size, 1, f);
    check_error(num_read, "fread");
    int fc_rv = fclose(f);
    check_error(fc_rv, "fclose");

    content_t *content = malloc(sizeof *content);
    check_error_null(content, "content malloc");
    content->content = content_bytes;
    content->content_len = sb->st_size;

    // convert the relative (from the content directory) path into a key. ht_set
    // will handle the copy so we only need to point to the start of the key. we
    // want to include the / at the start of the relative path as that's how the
    // HTTP requests will come in.
    int has_trailing_slash =
        content_dir_path[strlen(content_dir_path - 1)] == '/';
    const char *key =
        fpath + strlen(content_dir_path) + (has_trailing_slash ? -1 : 0);

    // store it
    void *hts_rv = (void *)ht_set(content_ht, key, content);
    check_error_null(hts_rv, "ht_set load_content_file");

    return 0;
}

/**
 * Loads content of all files under content_dir as values int content_ht, keyed
 * by their relative path (from the root of content_dir). Keys will be
 * null-terminated as required by content_ht, but values (the contents of the
 * files) won't be. Values are content_t structs.
 */
void load_content()
{
    content_ht = ht_create();

    // walk the content directory and load each file in as a prepared response,
    // keyed on the relative path
    int ntfwt_rv = nftw(content_dir_path, load_content_file, 1000, 0);
    check_error(ntfwt_rv, "nftw");
}

int main(int argc, char const *argv[])
{
    // to prevent user-initiated filesystem interaction, and to avoid having to
    // worry about path cleaning, load all content into memory on startup, and
    // access via hash table keyed on HTTP request path.
    load_content();

    // listen on all IPs
    int *listen_fds = NULL;
    int listen_fds_len = 0;
    create_listen_sockets(&listen_fds, &listen_fds_len);

    // set up epoll to efficiently monitor our listen and individual client
    // connection sockets
    int epoll_fd = epoll_create1(0);
    check_error(epoll_fd, "epoll_create1()");
    // start with just the listen sockets we have
    for (int i = 0; i < listen_fds_len; i++)
    {
        int listen_fd = listen_fds[i];
        // I'm assuming we don't want our accepts() to block, but because we're
        // only accepting() when epoll tells us there's something to accept(),
        // I'm not sure it matters
        fcntl(listen_fd, F_SETFL, O_NONBLOCK);

        struct epoll_event ee;
        ee.events = EPOLLIN;
        uh_epoll_data *ed = listen_sock_new();
        ed->listen_sock.fd = listen_fd;
        ee.data.ptr = ed;
        int ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ee);
        check_error(ectl_rv, "close_session epoll_ctl");
    }

    // shared vars we'll need in all loop iterations
    struct epoll_event epoll_events[EPOLL_MAX_EVENTS];
    void *client_buffer = malloc(CLIENT_BUFFER_LEN);
    check_error_null(client_buffer, "client_buffer");
    struct itimerspec timeout_timerspec;
    memset(&timeout_timerspec, 0, sizeof timeout_timerspec);
    timeout_timerspec.it_value.tv_sec = SESSION_TIMEOUT_SEC;

    while (1)
    {
        int num_events =
            epoll_wait(epoll_fd, epoll_events, EPOLL_MAX_EVENTS, -1);
        check_error(num_events, "epoll_wait");
        for (int i = 0; i < num_events; i++)
        {
            // all members of the union have the same initial members so this is
            // valid for all
            int fd = ((uh_epoll_data *)(epoll_events[i].data.ptr))->session.fd;
            int fd_type =
                ((uh_epoll_data *)(epoll_events[i].data.ptr))->session.type;

            if (fd_type == EPT_LISTEN)
            {
                // we're the listening socket, and have a new connection. Accept
                // it
                struct sockaddr_storage their_addr;
                socklen_t sin_size = sizeof their_addr;
                int connection_fd =
                    accept(fd, (struct sockaddr *)&their_addr, &sin_size);
                check_error(connection_fd, "accept");

                // make non-blocking
                fcntl(connection_fd, F_SETFL, O_NONBLOCK);

                // have epoll notify us when there's something to do on the
                // connection
                struct epoll_event ee;
                // don't ask about EPOLLOUT (ability to write) until we need it,
                // otherwise it will continue to trigger
                ee.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
                uh_epoll_data *ed = session_new();
                ed->session.fd = connection_fd;
                ee.data.ptr = ed;
                int ectl_rv =
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_fd, &ee);
                check_error(ectl_rv, "create session epoll_ctl");

                // don't leave stale connections hanging around. Start a timer
                // for each connection. if it expires without us receiving any
                // more data, we'll close the connection
                int timerfd = timerfd_create(CLOCK_MONOTONIC, O_NONBLOCK);
                check_error(timerfd, "timerfd_create");

                int tfdst_rv =
                    timerfd_settime(timerfd, 0, &timeout_timerspec, NULL);
                check_error(tfdst_rv, "timerfd_settime");

                struct epoll_event eet;
                eet.events = EPOLLIN | EPOLLHUP | EPOLLRDHUP | EPOLLERR;
                uh_epoll_data *edt = timeout_new();
                edt->timeout.fd = timerfd;
                edt->timeout.session = &ed->session;
                eet.data.ptr = edt;
                ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timerfd, &eet);
                check_error(ectl_rv, "create timer epoll_ctl");
                // session needs to know about the timer too. epoll is just
                // tracking a pointer for us so can still set this here
                ed->session.timeout = &edt->timeout;

                printf("got new connection fd %d via listen fd %d\n",
                       connection_fd, fd);
            }
            else if (fd_type == EPT_CONNECTION)
            {
                // we're a client connection.

                uh_epoll_data *ed = epoll_events[i].data.ptr;

                // we've received data
                if (epoll_events[i].events & EPOLLIN)
                {
                    // read it in
                    int num_bytes_recvd =
                        recv(fd, client_buffer, CLIENT_BUFFER_LEN, 0);

                    // can be a -1 plus error code too.
                    if (num_bytes_recvd == -1)
                    {
                        // not specifically handling EAGAIN/EWOULDBLOCK, because
                        // if epoll has notified us we have data to read, it
                        // should never block (?)

                        // print the error and close the session, but don't halt
                        // the entire program
                        print_if_error(num_bytes_recvd, "recv");
                        close_session(&ed->session, epoll_fd);
                        continue;
                    }

                    // clean up the connection if it was closed on the remote
                    // side
                    int socket_closed = num_bytes_recvd == 0;
                    if (socket_closed)
                    {
                        close_session(&ed->session, epoll_fd);
                        continue;
                    }

                    // we read valid data.

                    // reset the timeout timer
                    timerfd_settime(ed->session.timeout->fd, 0,
                                    &timeout_timerspec, NULL);

                    // Add it to what we've received so far
                    int request_orig_len = ed->session.request_len;
                    ed->session.request_len += num_bytes_recvd;
                    ed->session.request =
                        realloc(ed->session.request, ed->session.request_len);
                    check_error_null(ed->session.request,
                                     "realloc session->request");
                    memcpy(ed->session.request + request_orig_len,
                           client_buffer, num_bytes_recvd);

                    // try to extract the request path
                    tprp_rv parse_result =
                        try_parse_request_path(&(ed->session));
                    if (parse_result == TPRP_NEEDMOREDATA)
                    {
                        printf("need more data. So far: %.*s\n",
                               (int)(ed->session.request_len),
                               ed->session.request);
                        // need more data. Wait for next packet
                    }
                    else if (parse_result == TPRP_NOPREFIX ||
                             parse_result == TPRP_TOOLONG)
                    {
                        // bad request, close.
                        close_session(&ed->session, epoll_fd);
                    }
                    else if (parse_result == TPRP_PARSED)
                    {
                        // we have the path. Try to send back the requested
                        // content
                        generate_response(&(ed->session));
                        send_response(fd, &(ed->session), epoll_events, i,
                                      epoll_fd);
                    }
                    else
                    {
                        printf("unhandled TPRP_ parse result: %d\n",
                               parse_result);
                    }

                    // show contents for debugging
                    // print_buffer(client_buffer, num_bytes_read);
                }
                // we previously tried to send data and couldn't send all of it.
                // we can now send more
                else if (epoll_events[i].events & (EPOLLOUT))
                {
                    uh_epoll_data *ed = epoll_events[i].data.ptr;
                    send_response(fd, &(ed->session), epoll_events, i,
                                  epoll_fd);
                }
                // a hangup or error
                else
                {
                    printf("hangup or error on fd %d: %d", fd,
                           epoll_events[i].events);
                    // clean up
                    close_session(&ed->session, epoll_fd);
                }
            }
            else
            {
                // a timer has expired

                uh_epoll_data *ed = epoll_events[i].data.ptr;

                uint64_t _;
                read(ed->timeout.fd, &_, sizeof _);

                printf("timeout for timerfd %d and session fd %d hit\n", fd,
                       ed->timeout.session->fd);

                close_session(ed->timeout.session, epoll_fd);
            }
        }
    }

    // not freeing any global/singleton data for simplicity - the OS will
    // reclaim when we exit. session_t's we're finished with during program
    // execution are still cleaned up. This avoids having to maintain our own
    // list of uh_epoll_data pointers because I can't see a way to iterate over
    // all remaining fds in an epoll instance's interest list.

    return 0;
}
