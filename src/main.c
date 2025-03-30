
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>

int main(int argc, char const *argv[])
{
    // most of this is based on Beej's network programming guide.
    // https://beej.us/guide/bgnet/html/

    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status = getaddrinfo(NULL, "8080", &hints, &servinfo);
    if (status != 0)
    {
        printf("getaddrinfo error: %s\n", gai_strerror(status));
        return 1;
    }

    printf("num args: %d\n", argc);

    freeaddrinfo(servinfo);
    return 0;
}