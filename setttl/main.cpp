#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>


#define HTTP_SERVER "192.243.115.223"
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
    servaddr.sin_addr.s_addr = inet_addr(HTTP_SERVER);

    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        printf("connect error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    int flag = 1; 
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

    char sendbuf[BUFFER_SIZE];
    memset(sendbuf, 0, BUFFER_SIZE);

    strcpy(sendbuf, "GET /index.html HTTP/1.1\r\n");
    strcat(sendbuf, "Host: www.qq");
        
    int sendlen = send(sockfd, sendbuf, strlen(sendbuf),0); ///发送
    if(sendlen == -1)
    {
        close(sockfd);
        return errno;
    }

    printf("Front part send success\n");

    /*
    int flag = 1; 
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
    send(sock, "important data or end of the current message", ...);
    flag = 0; 
    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));
    */

    ttl = 8;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));
    memset(sendbuf, 0, BUFFER_SIZE);
    strcpy(sendbuf, "placeholder\r\n");
    strcat(sendbuf, "DNS1: XXXXXXXXXXXXXXXXXXplaceholder1\r\n");
    strcat(sendbuf, "DNS2: XXXXXXXXXXXXXXXXXXplaceholder2");

    sendlen = send(sockfd, sendbuf, strlen(sendbuf),0); ///发送

    if(sendlen == -1)
    {
        close(sockfd);
        return errno;
    }

    printf("Middle placeholder part send success\n");

    ttl = 64;
    setsockopt(sockfd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl));

    memset(sendbuf, 0, BUFFER_SIZE);
    strcpy(sendbuf, "cgg.com\r\n");
    strcat(sendbuf, "UserAgent: Vivo Browser agent\r\n");
    strcat(sendbuf, "Accept: text/html,*/*;q=0.8\r\n\r\n");

    sendlen = send(sockfd, sendbuf, strlen(sendbuf),0); ///发送
    if(sendlen == -1)
    {
        close(sockfd);
        return errno;
    }
    printf("End part send success\n");

    char recvbuf[BUFFER_SIZE];
    memset(recvbuf, 0, BUFFER_SIZE);

    int recvlen = recv(sockfd, recvbuf, sizeof(recvbuf),0); ///接收

    if(recvlen != -1)//OK.
    {
        puts(recvbuf);
		}




    close(sockfd);
    exit(0);
}
