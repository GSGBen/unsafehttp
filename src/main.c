// most of this is based on Beej's network programming guide.
// https://beej.us/guide/bgnet/html/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

// TODO: take in as flag
#define PORT "3490"

#define BACKLOG 10

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so save and restore it
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0)
        ;

    errno = saved_errno;
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int main(int argc, char const *argv[])
{
    // old-style C with all variables declared at the top of function scope

    int sockfd, new_fd; // listen on sock_fd, each new connection is on new_fd
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv; // return values of function calls

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // get our IPs
    rv = getaddrinfo(NULL, PORT, &hints, &servinfo);
    if (rv != 0)
    {
        printf("getaddrinfo failed: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all results and bind to the first we can.
    // TODO: listen on all?
    for (p = servinfo; p != NULL; p = p->ai_next)
    {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1)
        {
            perror("server: socket");
            continue;
        }

        rv = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (rv == -1)
        {
            perror("setsockopt");
            exit(1);
        }

        rv = bind(sockfd, p->ai_addr, p->ai_addrlen);
        if (rv == -1)
        {
            close(sockfd);
            perror("server: bind");
            continue;
        }

        break;
    }

    // no longer needed
    freeaddrinfo(servinfo);

    if (p == NULL)
    {
        printf("server: failed to bind to an address\n");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    // bind a handler function to be called whenever one of our spawned child processes
    // exits. The handler will reap the zombie processes
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(1);
    }

    printf("server: waiting for connections...\n");

    // main accept loop
    while (1)
    {
        // not sure why this is in the while loop
        sin_size = sizeof their_addr;
        // blocking. waits here for a connection
        new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd == -1)
        {
            perror("accept");
            continue;
        }

        inet_ntop(
            their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s,
            sizeof s);
        printf("server: got connection from %s\n", s);

        // create a child process for this connection. when fork is called, the calling
        // process is cloned, and both continue executing from this point. The parent
        // process will get a positive int (the PID of the child process), and the child
        // will get a return code of 0.
        int is_parent_process = fork();
        if (!is_parent_process) // inside here is the child process
        {
            // we don't need the main listener. I guess we got a copy of this when we
            // forked, the socket isn't shared, and we're not closing the parent's
            // socket? guessing we wouldn't do this if we created a new thread.
            close(sockfd);
            ssize_t num_sent_bytes = send(new_fd, "Hello, world!", 13, 0);
            if (num_sent_bytes == -1)
            {
                perror("send");
            }
            close(new_fd);
            exit(0);
        }
        // parent doesn't need new connection socket
        close(new_fd);
    }

    return 0;
}