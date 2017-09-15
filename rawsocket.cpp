#include <stdio.h>  
#include <string.h>  
#include <stdlib.h>  
#include <sys/socket.h>  
#include <sys/types.h>  
#include <netinet/in.h>  
#include <unistd.h>  
#include <linux/if_ether.h>  
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
  
#define SRC_IP "172.25.124.227" //源IP  
#define SRC_PORT 6666  //源端口号  

#define DST_IP "112.74.189.66"  //目的IP  
#define DST_PORT 80    //目的端口  
  
struct iphead{            //IP首部  
    uint8_t ip_hl:4, ip_version:4;  
    uint8_t ip_tos;  
    uint16_t ip_len;  
    uint16_t ip_id;  
    uint16_t ip_off;  
    uint8_t ip_ttl;  
    uint8_t ip_pro;  
    uint16_t ip_sum;  
    uint32_t ip_src;  
    uint32_t ip_dst;  
};  
  
struct tcphead{      //TCP首部  
    uint16_t tcp_sport;  
    uint16_t tcp_dport;  
    uint32_t tcp_seq;  
    uint32_t tcp_ack;  
    uint8_t tcp_off:4, tcp_len:4;  
    uint8_t tcp_flag;  
    uint16_t tcp_win;  
    uint16_t tcp_sum;  
    uint16_t tcp_urp;  
};  
  
struct psdhead{ //TCP伪首部  
    uint32_t saddr; //源地址  
    uint32_t daddr; //目的地址  
    uint8_t mbz;//置空  
    uint8_t ptcl; //协议类型  
    uint16_t tcpl; //TCP长度  
};  
  

/*
uint16_t checksum(uint8_t packet[], uint16_t len){   //校验函数  
    unsigned long sum = 0;  
    uint16_t * temp;  
    uint16_t answer;  
    temp = (uint16_t *)packet;  
    for( ; temp < packet+len; temp += 1)  
        sum += *temp;  
    sum = (sum >> 16) + (sum & 0xffff);  
    sum += (sum >> 16);  
    answer = ~sum;  
    return answer;  
    //长度可能奇数，此处需完善  
}   */ 


uint16_t checksum(uint16_t *buffer, int size) 
{ 
  unsigned long chksum=0; 
  while (size > 1) 
  { 
    chksum += *buffer++; 
    size -= sizeof(uint16_t); 
  } 
  if (size) 
  { 
    chksum += *(uint8_t*)buffer; 
  } 
  chksum = (chksum >> 16) + (chksum & 0xffff); 
  chksum += (chksum >>16); 
  return (uint16_t)(~chksum); 
} 
  
int conn(int sendsockfd, /* int recsockfd,  */struct sockaddr_in seraddr){  // 三次握手  
    uint8_t packet[sizeof(struct iphead) + sizeof(struct tcphead)];  

    struct iphead* ip;  
    struct tcphead* tcp;  
    ip = (struct iphead*)packet;  
    tcp = (struct tcphead*)(packet+sizeof(struct iphead));  
    memset(packet, 0, sizeof(packet));  
    /*以下分别设置IP，和TCP的首部，然后发送SYN报文段*/  
    /*设置IP首部*/  
    ip->ip_hl = 5;  
    ip->ip_version = 4;  
    ip->ip_tos = 0;  
    ip->ip_len = htons(sizeof(struct iphead) + sizeof(struct tcphead));  
    //TODO.
    ip->ip_id = htons(13542); // random()  
    ip->ip_off = htons(0x4000);  
    //TODO
    ip->ip_ttl = 64;  
    ip->ip_pro = IPPROTO_TCP;  
    ip->ip_src = inet_addr(SRC_IP);  
    ip->ip_dst = inet_addr(DST_IP);  
    ip->ip_sum = checksum((uint16_t*)packet, 20);  //计算IP首部的校验和，必须在其他字段都赋值后再赋值该字段，赋值前为0  
  
    /*设置TCP首部*/  
    int my_seq = 0; //TCP序号  
    tcp->tcp_sport = htons(SRC_PORT);  
    tcp->tcp_dport = htons(DST_PORT);  
    tcp->tcp_seq = htonl(my_seq);  
    tcp->tcp_ack = htons(0);  
    tcp->tcp_len = 5;  //发送SYN报文段时，设置TCP首部长度为20字节  
    tcp->tcp_off = 0;  
    tcp->tcp_flag = 0x02;  //SYN置位  
    tcp->tcp_win = htons(29200);  
    tcp->tcp_urp = htons(0);  

    /*设置tcp伪首部，用于计算TCP报文段校验和*/  
    struct psdhead psd;  
    psd.saddr = inet_addr(SRC_IP); //源IP地址  
    psd.daddr = inet_addr(DST_IP); //目的IP地址  
    psd.mbz = 0;  
    psd.ptcl = 6;    
    psd.tcpl = htons(20);  
  
    uint8_t buffer[1000]; //用于存储TCP伪首部和TCP报文，计算校验码  
    memcpy(buffer, &psd, sizeof(psd));  
    memcpy(buffer+sizeof(psd), tcp, sizeof(struct tcphead));  
    tcp->tcp_sum = checksum((uint16_t*)buffer, sizeof(psd) + sizeof(struct tcphead));  //计算检验码  
  
    /*发送SYN报文段*/  
    int send = sendto(sendsockfd, packet, htons(ip->ip_len), 0,(struct sockaddr *)&seraddr, sizeof(seraddr));  
    if(send < 0){  
      printf("send failed   sendcode=%d\n", send);  
      return -1;  
    }  
    uint8_t rec[1024];  
    int n = recvfrom(sendsockfd, rec, 1024, 0, NULL, NULL);  //接收SYN和ACK报文  
    printf("receive %d bytes:\n", n);  //将接受的IP数据报输出  
    for(int i=0; i<n; i++){  
        if(i % 16 == 0)  
            printf("\n");  
        printf("%02x ", rec[i]);  
    }  
    printf("\n");  
    /*校验接收到的IP数据报，重新计算校验和，结果应为0*/  
    uint8_t ipheadlen = rec[0]; //取出IP数据包的长度  
    ipheadlen = (ipheadlen & 0x0f);   //IP首部长度字段只占该字节后四位  
    ipheadlen *= 4; //四个字节为单位  
    uint16_t iplength = ntohs(*((uint16_t *)(rec+2))); //获取IP数据报长度  
    uint16_t tcplength = iplength - ipheadlen;  //计算TCP数据报长度  
    printf("ipchecksum: %d\n", checksum((uint16_t*)rec, ipheadlen));  //校验IP首部  
    
  
    /*以下校验TCP报文，同样将伪首部和TCP报文放入buffer中*/  
  
    memset(buffer, 0, sizeof(buffer));  
    for(int i=0; i<8; i++)  
        buffer[i] = rec[i + 12];  //获取源IP和目的IP  
    buffer[8] = 0;  //伪首部的字段，可查阅资料  
    buffer[9] = rec[9];  //IP首部“上层协议”字段，即IPPROTO_TCP  
    buffer[10] = 0; //第10,11字节存储TCP报文长度，此处只考虑报文长度只用一个字节时，不会溢出，根据网络字节顺序存储  
    uint8_t tcpheadlen = rec[32];  //获取TCP报文长度                    
    tcpheadlen = tcpheadlen >> 4;  //因为TCP报文长度只占该字节的高四位，需要取出该四位的值  
    tcpheadlen *= 4;   //以四个字节为单位  
    printf("tcpheadlen:%d\n", tcpheadlen);  
    buffer[11] = tcpheadlen;  //将TCP长度存入  
    for(int i=0; i<tcplength; i++)   //buffer中加入TCP报文  
        buffer[i+12] = rec[i+ipheadlen];   
    printf("tcpchecksum:%d\n", checksum((uint16_t*)buffer, 12+tcplength));  //得到校验和  
      
    /*检验收到的是否是SYN+ACK包，是否与上一个SYN请求包对应*/  
    uint32_t ack = ntohl(*((signed int*)(rec+ipheadlen+8))); //获取TCP首部的确认号  
    printf("ACK:%d\n", ack);  
    if(ack != my_seq + 1){ //判断是否是放一个SYN报的回应  
        printf("该报不是对上一个SYN请求包的回应");  
    }else{  
        uint8_t flag = rec[13+ipheadlen]; //获取标志字段  
        printf("flag:%02x\n", flag);  
        flag = (flag & 0x12);  //只需要ACK和SYN标志的值  
        if(flag != 0x12){  //判断是否为SYN+ACK包  
            printf("不是ACK+SYN包\n");     
        }else{  
            printf("收到ACK+SYN包\n");  
            /*接下来发送ACK确认包*/  
            uint32_t op_seq; //获取接收到的ACK+SYN包的序列号  
            op_seq = ntohl(*((uint32_t*)(rec+ipheadlen+4)));  
            printf("op_seq:%d\n", op_seq);  
  
            memset(packet, 0, sizeof(packet));  //重新赋值为0  
  
            /*以下分别设置IP，和TCP的首部，然后发送ACK报文段*/  
            /*设置IP首部*/  
            ip->ip_hl = 5;  
            ip->ip_version = 4;  
            ip->ip_tos = 0;  
            ip->ip_len = htons(sizeof(struct iphead) + sizeof(struct tcphead));  
            ip->ip_id = htons(13543); // random()  
            ip->ip_off = htons(0x4000);  
            ip->ip_ttl = 64;  
            ip->ip_pro = IPPROTO_TCP;  
            ip->ip_src = inet_addr(SRC_IP);  
            ip->ip_dst = inet_addr(DST_IP);  
            ip->ip_sum = checksum((uint16_t*)packet, 20);  //计算IP首部的校验和，必须在其他字段都赋值后再赋值该字段，赋值前为0  
              
            /*设置TCP首部*/  
            my_seq ++;  
            tcp->tcp_sport = htons(SRC_PORT);  
            tcp->tcp_dport = htons(DST_PORT);  
            tcp->tcp_seq = htonl(my_seq);  
            printf("op_seq:%d\n", op_seq);  
            tcp->tcp_ack = ntohl(op_seq+1);  
            tcp->tcp_len = 5;  //发送SYN报文段时，设置TCP首部长度为20字节  
            tcp->tcp_off = 0;  
            tcp->tcp_flag = 0x10;  //SYN置位  
            tcp->tcp_win = htons(1000);  
            tcp->tcp_urp = htons(0);  
              
            /*设置tcp伪首部，用于计算TCP报文段校验和*/  
            //struct psdhead psd;  
            psd.saddr = inet_addr(SRC_IP); //源IP地址  
            psd.daddr = inet_addr(DST_IP); //目的IP地址  
            psd.mbz = 0;  
            psd.ptcl = 6;    
            psd.tcpl = htons(20);  
            uint8_t buffer[1000]; //用于存储TCP伪首部和TCP报文，计算校验码  
            memcpy(buffer, &psd, sizeof(psd));  
            memcpy(buffer+sizeof(psd), tcp, sizeof(struct tcphead));  
            tcp->tcp_sum = checksum((uint16_t *)buffer, sizeof(psd) + sizeof(struct tcphead));  //计算检验码  
  
            /*发送SYN报文段*/  
            int send = sendto(sendsockfd, packet, htons(ip->ip_len), 0,(struct sockaddr *)&seraddr, sizeof(seraddr));  
            if(send < 0){  
                printf("send failed   sendcode=%d\n", send);  
                return -1;  
            }  
            printf("已发送ACK报文，已创建TCP连接\n");  
              
            n = recvfrom(sendsockfd, rec, 1024, 0, NULL, NULL);  //接收IP数据报  
            printf("receive %d bytes:\n", n);  //将接受的IP数据报输出  
            for(int i=0; i<n; i++){  
                if(i % 16 == 0)  
                    printf("\n");  
                printf("%d ", rec[i]);  
            }   
            printf("\n");  
        }  
    }  
}  
  
int main() {  
    int sendsockfd = -1;//, recsockfd;  
    sendsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  //发送套接字，此处接收发送我分开用了，用一个应该也可以的  
    if(sendsockfd < 0){  
        printf("create sendsocket failed\n");  
        return -1;  
    }  
    //recsockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));  
    /*
    recsockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);  //接收套接字  
    if(recsockfd < 0){  
        printf("create recsockfd failed\n");  
        return -1;  
    }  
    */

    int one = 1;  
    if(setsockopt(sendsockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){   //定义套接字不添加IP首部，代码中手工添加  
        printf("setsockopt failed!\n");  
        return -1;  
    }  

    struct sockaddr_in seraddr;  
    seraddr.sin_family = AF_INET;    
    seraddr.sin_addr.s_addr = inet_addr(DST_IP); //设置接收方IP  
  
    conn(sendsockfd, /*  recsockfd, */seraddr);  //模拟创建TCP连接  
    return 0;  
}  
