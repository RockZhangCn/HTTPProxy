#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096

int main(int argc, char** argv)
{
    int    sockfd, n;
    char    recvline[BUFFER_SIZE], sendline[BUFFER_SIZE];
    struct sockaddr_in    servaddr;

    if( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("create socket error: %s(errno: %d)\n", strerror(errno),errno);
        exit(0);
    }

    int ttl = 33;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(80);
    servaddr.sin_addr.s_addr = inet_addr("192.243.115.223");

    // if(inet_pton(AF_INET, “192.243.115.223”, &servaddr.sin_addr) <= 0){
    //     printf("inet_pton error for %s\n",argv[1]);
    //     exit(0);
    // }

    if( connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0){
        printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    //const char * sendline = "Hello World";
    strncpy(sendline, "Hello, World!", BUFFER_SIZE);
    if(send(sockfd, sendline, strlen(sendline), 0) < 0)
    {
        printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
        exit(0);
    }

    close(sockfd);
    exit(0);
}
