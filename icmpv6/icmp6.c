#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

struct ipv6header {
    unsigned char priority:4, version:4;
    unsigned char flow[3];
    unsigned short int length;
    unsigned char nexthdr;
    unsigned char hoplimit;

    unsigned int saddr[4];
    unsigned int daddr[4];
};

struct icmpv6header {
    unsigned char type;
    unsigned char code;
    unsigned short int chk_sum;
    unsigned int body; 
};

int main()
{

    char* packet = (char*) malloc(sizeof(struct ipv6header)+sizeof(struct icmpv6header));
    struct ipv6header* ip = (struct ipv6header*) packet;
    struct icmpv6header* icmp = (struct icmpv6header*) (packet+sizeof(struct ipv6header));

    icmp->type = 128;
    icmp->code = 0;
    icmp->chk_sum = (0x6a13);
    icmp->body = htonl(1234);

    ip->version = 6;
    ip->priority = 0;

    (ip->flow)[0] = 0;
    (ip->flow)[1] = 0;
    (ip->flow)[2] = 0;
    ip->length = ((unsigned short int) sizeof(struct icmpv6header));
    ip->nexthdr = 58;
    ip->hoplimit = 255;

    struct sockaddr_in6 remote;
    remote.sin6_family = AF_INET6;
    remote.sin6_port = 0;
    remote.sin6_flowinfo = 0;
    remote.sin6_scope_id = 0;

    inet_pton(AF_INET6, "1111:2222:3333:4444:5555:6666:7777:8888", &(remote.sin6_addr));
    inet_pton(AF_INET6, "9999:1111:2222:3333:4444:5555:6666:7777", &(ip->saddr));
    inet_pton(AF_INET6, "::1", &(ip->daddr));

    int sock, optval;
    sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

    if(sock == -1)
    {
        printf("Error setting socket\n");
        return -1;
    }

    int ret = setsockopt(sock, IPPROTO_IPV6, IP_HDRINCL, &optval, sizeof(int));

    if(ret != 0) {
        printf("Error setting options %d\n", ret);
        return -1;
    }
    printf("Socket options done\n");

    ret = sendto(sock, packet, ip->length, 0, (struct sockaddr *) &remote, sizeof(remote));

    if(ret != ip->length) {
        printf("Packet not sent : %d (%d)\n",ret,errno);
        return -1;
    }

    printf("Packet sent\n");

    return 0;
}
