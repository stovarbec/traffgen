#include <argp.h>
#include <argz.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
unsigned short in_cksum(unsigned short *, int);

int main(int argc, char **argv){	
	
	char *data=argv[3]; 
	int packet_size, payload_size, sent, sent_size;
	payload_size = strlen(argv[3]);//a.payload);
	packet_size = sizeof (struct ip6_hdr) + sizeof (struct udphdr) + payload_size;
	char *packet = (char *) malloc (packet_size);
	struct ip6_hdr *ip6 = (struct ip6_hdr *) packet;
	struct udphdr *udp;
	udp = (struct udphdr *) (packet + sizeof (struct ip6_hdr));
	
	memset (packet, 0, packet_size);
	
	ip6->ip6_flow	= 0;
	ip6->ip6_vfc	= 0x60;
	ip6->ip6_hlim	= 2;
	ip6->ip6_plen	= htons (packet_size);
	ip6->ip6_nxt	= 17;//a.protocol;
//	ip6->ip6_src	= a.saddr;
//	ip6->ip6_dst	= a.daddr;
	
	if (inet_pton(AF_INET6, argv[1], &(ip6->ip6_src)) == 1){
		puts("Correcto");
	}
	if (inet_pton(AF_INET6, argv[2], &(ip6->ip6_dst)) == 1){
		puts("Correcto");
	}

//	if(a.protocol == UDP){
		udp->source		= htons(50000);//a.sport);
		udp->dest		= htons(80);//a.dport);
		udp->len		= htons(8 + payload_size);
		udp->check		= 0;
		udp->check		= in_cksum((unsigned short *)udp, sizeof(struct udphdr) + payload_size);
		data			= (packet + sizeof(struct ip6_hdr) + sizeof(struct udphdr));	
		//strcpy(data,argv[3]);
//	}
	int sockfd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
	
	if (sockfd < 0){
		perror("could not create socket");
		return (0);
	}
	
	int on = 1;
	
	// We shall provide IP headers
	if (setsockopt (sockfd, IPPROTO_IPV6, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) {
		perror("setsockopt");
		return (0);
	}
	
	//allow socket to send datagrams to broadcast addresses
	/*
	if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) {
		perror("setsockopt");
		return (0);
	}	
	*/		   
	if (!packet) {
		perror("out of memory");
		close(sockfd);
		return (0);
	}
	struct sockaddr_in6 servaddr;
    servaddr.sin6_family	= AF_INET6;
    servaddr.sin6_port		= 0;
    servaddr.sin6_flowinfo	= 0;
    servaddr.sin6_scope_id	= 0;
	servaddr.sin6_addr		= ip6->ip6_dst;
	while (1){
		if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1){
			perror("send failed\n");
			break;
		}
		++sent;
		printf("%d packets sent\r", sent);
		fflush(stdout);
		
		usleep(1000000);	//microseconds
	}
//	int ret = sendto(sock, packet, ip->length, 0, (struct sockaddr *) &remote, sizeof(remote));

}
unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	u_short oddbyte;
	register u_short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char *) & oddbyte) = *(u_char *) ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return (answer);
}

