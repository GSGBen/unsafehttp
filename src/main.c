/**
 * The base network/socket programming and poll structure stuff is based on
 * Beej's network programming guide. https://beej.us/guide/bgnet/html/.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// TODO: take in as arg
#define PORT "8080"
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

// return codes for try_parse_request_path().

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
 * The first part of the request, that precedes the path.
 */
char *http_get_prefix = "GET ";
int http_get_prefix_len = 4;

/**
 * A HTTP request/response section. A pointer to one of these is passed to each
 * connection entry stored in our epoll instance. Allows us to buffer data
 * across multiple epoll loops as we wait for it all to come in or go out.
 *
 * We also re-use this for listen sockets monitored via epoll, as they only need
 * the fd. If they had differing fields we could create another struct that
 * started with an `int fd` member, then union them.
 *
 * Construct with session_new().
 *
 * Strings are not NUL-terminated, use the related length var.
 */
typedef struct
{
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
    char *response;
    // number of chars in response.
    size_t response_len;
    // the number of chars from response that we've sent so far
    size_t response_sent_len;

} session_t;

/**
 * Use to construct all session_t's. Allocates and initializes.
 */
session_t *session_new()
{
    session_t *s = malloc(sizeof *s);
    s->fd = -1;
    s->request = NULL;
    s->request_len = 0;
    s->request_path = NULL;
    s->request_path_len = 0;
    s->response = NULL;
    s->response_len = 0;
    s->response_sent_len = 0;

    return s;
}

/**
 * Deallocates all memory for session.
 */
void session_delete(session_t *session)
{
    free(session->request);
    free(session->request_path);
    free(session->response);
    free(session);
}

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
 * longer need.
 */
void close_session(int fd, struct epoll_event *epoll_events, int i,
                   int epoll_fd)
{
    printf("closing session fd %d\n", fd);
    session_delete((session_t *)epoll_events[i].data.ptr);
    int ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    check_error(ectl_rv, "close_session epoll_ctl");
    close(fd);
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

    // just send a test for now
    char *test_response = "HTTP/1.0 200 OK\n"
                          "Server: unsafehttp\n"
                          "Connection: close\n"
                          "Content-Type: text/html\n"
                          "Content-Length: 16403\n"
                          "\n"
                          "<html>test</html>\n";
    // test multiple writes by sending more than the default tcp write buffer
    // size.
    // not counting null terminators, we'll skip them
    int test_response_total_len = strlen(test_response) + 10000000 + 1;
    char *test_response_total = malloc(test_response_total_len);
    memcpy(test_response_total, test_response, strlen(test_response));
    memset(test_response_total + strlen(test_response), 'a', 10000000);
    char *last_char = test_response_total + test_response_total_len - 1;
    *last_char = 'b';

    session->response_len = test_response_total_len;
    session->response = test_response_total;

    printf("total length: %d\n", test_response_total_len);
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
                close_session(fd, epoll_events, i, epoll_fd);
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
        close_session(fd, epoll_events, i, epoll_fd);
}

int main(int argc, char const *argv[])
{
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
        // the sessions that get monitored later use this struct, re-use it for
        // the listen sockets here
        session_t *session = session_new();
        session->fd = listen_fd;
        ee.data.ptr = session;
        int ectl_rv = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ee);
        check_error(ectl_rv, "close_session epoll_ctl");
    }

    struct epoll_event epoll_events[EPOLL_MAX_EVENTS];
    void *client_buffer = malloc(CLIENT_BUFFER_LEN);
    while (1)
    {
        int num_events =
            epoll_wait(epoll_fd, epoll_events, EPOLL_MAX_EVENTS, -1);
        check_error(num_events, "epoll_wait");
        for (int i = 0; i < num_events; i++)
        {
            int fd = ((session_t *)(epoll_events[i].data.ptr))->fd;
            // check whether epoll is telling is about an event on a listen
            // socket (a new connection), or an event on a client connection
            // socket (usually receiving data). If we had a potential lot of
            // listen_fds to check against, this would be very inefficient, and
            // a more efficient way to do it would be to pass a pointer to a
            // custom struct to epoll instead of just fd (in the epoll_data
            // union), but then we'd have to maintain a separate set of structs,
            // one for each fd that epoll is listening for events on. Luckily,
            // we will only usually have one listen fd (because of the automatic
            // dual-stack), so we can just take the simple path.
            int is_listen_fd = 0;
            for (int j = 0; j < listen_fds_len; j++)
            {
                if (listen_fds[j] == fd)
                {
                    is_listen_fd = 1;
                    break;
                }
            }

            if (is_listen_fd)
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
                session_t *session = session_new();
                session->fd = connection_fd;
                ee.data.ptr = session;
                int ectl_rv =
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_fd, &ee);
                check_error(ectl_rv, "close_session epoll_ctl");

                printf("got new connection fd %d via listen fd %d\n",
                       connection_fd, fd);
            }
            else
            {
                // we're a client connection.

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
                        print_if_error(num_bytes_recvd, "recv");
                        continue;
                    }

                    // clean up the connection if it was closed on the remote
                    // side
                    int socket_closed = num_bytes_recvd == 0;
                    if (socket_closed)
                    {
                        close_session(fd, epoll_events, i, epoll_fd);
                        continue;
                    }

                    // valid data. Add it to what we've received so far
                    session_t *session = epoll_events[i].data.ptr;
                    int request_orig_len = session->request_len;
                    session->request_len += num_bytes_recvd;
                    session->request =
                        realloc(session->request, session->request_len);
                    check_error_null(session->request,
                                     "realloc session->request");
                    memcpy(session->request + request_orig_len, client_buffer,
                           num_bytes_recvd);

                    // try to extract the request path
                    tprp_rv parse_result = try_parse_request_path(session);
                    if (parse_result == TPRP_NEEDMOREDATA)
                    {
                        printf("need more data. So far: %.*s\n",
                               (int)(session->request_len), session->request);
                        // need more data. Wait for next packet
                    }
                    else if (parse_result == TPRP_NOPREFIX ||
                             parse_result == TPRP_TOOLONG)
                    {
                        // bad request, close.
                        close_session(fd, epoll_events, i, epoll_fd);
                    }
                    else if (parse_result == TPRP_PARSED)
                    {
                        // we have the path. Try to send back the requested
                        // content
                        generate_response(session);
                        send_response(fd, session, epoll_events, i, epoll_fd);
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
                    session_t *session = epoll_events[i].data.ptr;
                    send_response(fd, session, epoll_events, i, epoll_fd);
                }
                // a hangup or error
                else
                {
                    printf("hangup or error on fd %d: %d", fd,
                           epoll_events[i].events);
                    // clean up
                    close_session(fd, epoll_events, i, epoll_fd);
                }
            }
        }
    }

    // not freeing listen_fds, client_buffer, or the session_t's of currently
    // open listen or session sockets, for simplicity - the OS will reclaim when
    // we exit. session_t's we're finished with during program execution are
    // still cleaned up. This avoids having to maintain our own list of
    // session_t pointers because I can't see a way to iterate over all
    // remaining fds in an epoll instance's interest list.

    return 0;
}
