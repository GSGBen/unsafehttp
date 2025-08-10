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
        ee.data.fd = listen_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ee);
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
            int fd = epoll_events[i].data.fd;
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
                ee.events = EPOLLIN;
                ee.data.fd = connection_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, connection_fd, &ee);

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
                    int num_bytes_read =
                        recv(fd, client_buffer, CLIENT_BUFFER_LEN, 0);

                    // can be a -1 plus error code too
                    if (num_bytes_read == -1)
                    {
                        print_if_error(num_bytes_read, "recv");
                        continue;
                    }

                    // clean up the connection if it was closed on the remote
                    // side
                    int socket_closed = num_bytes_read == 0;
                    if (socket_closed)
                    {
                        close(fd);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
                        continue;
                    }

                    // show contents for debugging
                    print_buffer(client_buffer, num_bytes_read);
                    // send back some data. Just testing atm - no
                    // EAGAIN/EWOULDBLOCK buffering yet
                    int num_bytes_sent = send(fd, &"hello\n", 6, 0);
                    printf("sent %d bytes\n", num_bytes_sent);
                }
            }
        }
    }

    free(listen_fds);
    free(client_buffer);
    return 0;
}
