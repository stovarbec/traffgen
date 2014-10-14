#include <argp.h>
#include <argz.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


#ifndef ICMP
#define ICMP 1
#endif
#ifndef TCP
#define TCP 6
#endif
#ifndef UDP
#define UDP 17
#endif
#ifndef HI_PORT
#define HI_PORT 65535
#endif
#ifndef LO_PORT
#define LO_PORT 32768
#endif
#ifndef HI_ADDR
#define HI_ADDR 4294967295
#endif

typedef unsigned char u8;
typedef unsigned short int u16;

unsigned short in_cksum(unsigned short *ptr, int nbytes);

const char *argp_program_bug_address = "xzamora@seguridad.unam.mx ";
const char *argp_program_version = "version 1.0";

static char doc[]="Simple packet's crafter\vWith great power comes great responsability";
static char args_doc[]="IP_DST";
struct argp_option options[] ={
	{0,0,0,0, "IP Version:\n",1},
	{"ip4"		,'4'	,0			,0,"IPv4 Packet"},
	{"ip6"		,'6'	,0			,0,"IPv6 Packet"},
	
	{0,0,0,0, "Protocols:\n",2},
	{"icmp"		,1111	,0			,0,"ICMP Packet"},
	{"udp"		,2222	,0			,0,"UDP Packet"},
	{"tcp"		,3333	,0			,0,"TCP Packet"},
	
	{0,0,0,0, "The following options could be grouped together after --tcp flag:\n",3},
	{0,'S',0,0,"Set SYNCHRONIZATION Flag"},
	{0,'A',0,0,"Set ACKNOWLEDGE Flag"},
	{0,'F',0,0,"Set FIN Flag"},
	{0,'P',0,0,"Set PUSH Flag"},
	{0,'R',0,0,"Set RESET Flag"},
	{0,'U',0,0,"Set URGENT Flag"},

	{0,0,0,0, "Number of packets:\n",5},
	{"fast"		,1000	,0			,0,"Send 100 packets per second"},
	{"flood"		,1001	,0			,0,"Send many packets as possible"},
	{"count"		,'c'	,"NUM"	,0,"Send NUM packets, one per second"},

	{0,0,0,0, "Customize your packets:\n",4},
	{"sport"		,'x'	,"NUM"	,0,"Source port"},
	{"dport"		,'y'	,"NUM"	,0,"Destination port"},
	{"saddr"		,'s'	,"IP"		,0,"Set a fake source IP address"},
	{"payload"	,'p'	,"STR"	,0,"Include a message in the payload"},
	
	{0,0,0,0, "Miscelaneous:\n",-1},
	{"verbose"	,'v'	,0			,0,"Produce verbose output" },
	{0}
};
struct arguments{
	char ip_ver;						/*IP Version*/
	char protocol;						/*Protocol to send*/
	char *argz;							/*All arguments*/
	unsigned long daddr;			/*Destination ip*/
	unsigned long saddr;			/*Source ip*/
	char *payload;						/*Payload packet*/
	size_t argz_len;					/*# of args*/
	int syn,ack,fin,psh,rst,urg;	/*TCP Flags*/
	int verbose,fast,flood;			/*Boolean options*/
	unsigned int sport,dport;		/*Port number*/
	unsigned int count;				/*Number of packets to send*/
	int proto,port,tcpf;				/*Control flags*/
};
static int parse_opt (int key, char *arg, struct argp_state *state){
	struct arguments *a = state->input;
	switch (key){
		case 1111:/*ICMP Protocol*/
			a->protocol=ICMP;
			a->proto++;
		break;
		case 2222:/*UDP Protocol*/
			a->protocol=UDP;
			a->proto++;
		break;
		case 3333:/*TCP Protocol*/
			a->protocol=TCP;
			a->proto++;
		break;
		case 1000:/*Send fast*/
			a->fast=1;
		break;
		case 1001:/*Send flood*/
			a->flood=1;
		break;
		case '4':/*IPv4*/
			a->ip_ver=4;
		break;
		case '6':/*IPv6*/
			a->ip_ver=6;
		break;
		case 'c':/*Count*/
			a->count=(unsigned int)atoi(arg);
		break;
		case 'p':/*Payload*/
			a->payload=arg;
		break;
		case 's':/*Source IP*/
			a->saddr=inet_addr(arg);
		break;
		case 'v':/*Verbose*/
			a->verbose=1;
		break;
		case 'x':/*SRC Port*/
			a->sport=(unsigned int)atoi(arg);
			a->port++;
		break;
		case 'y':/*DST Port*/
			a->dport=(unsigned int)atoi(arg);
			a->port++;
		break;
		case 'S':/*SYN Flag*/
			a->syn=1;
			a->tcpf++;
		break;
		case 'A':/*ACK Flag*/
			a->ack=1;
			a->tcpf++;
		break;
		case 'F':/*FIN Flag*/
			a->fin=1;
			a->tcpf++;
		break;
		case 'P':/*PSH Flag*/
			a->psh=1;
			a->tcpf++;
		break;
		case 'R':/*RST Flag*/
			a->rst=1;
			a->tcpf++;
		break;
		case 'U':/*URG Flag*/
			a->urg=1;
			a->tcpf++;
		break;
		case ARGP_KEY_ARG:
			argz_add (&a->argz, &a->argz_len, arg);
			a->daddr=inet_addr(arg);
		break;
		case ARGP_KEY_INIT:
			a->argz = 0;
			a->argz_len = 0;
			a->ip_ver=4;
			a->protocol=ICMP;
			a->saddr=0;
			a->daddr=0;
			a->payload=NULL;
			a->count=0;
			a->sport=-1;
			a->dport=-1;
			a->syn=0;
			a->ack=0;
			a->fin=0;
			a->psh=0;
			a->rst=0;
			a->urg=0;
			a->fast=0;
			a->flood=0;
			a->verbose=0;
			a->proto=0;
			a->port=0;
			a->tcpf=0;
		break;
		case ARGP_KEY_END:{
			size_t count = argz_count (a->argz, a->argz_len);
			if (count > 1){
				argp_usage(state);
				argp_failure (state, 1, 0, "too many arguments");
			}
			else if (count < 1){
				argp_usage(state);
				argp_failure (state, 1, 0, "too few arguments");
			}
			if(a->saddr >= HI_ADDR || a->daddr >= HI_ADDR)
				argp_failure (state, 1, 0, "Bad IP address, try again");
			/*More than one protocol specified*/
			if(count == 1)
				a->proto=1;
			if(a->proto>1){
				argp_failure (state, 1, 0, "You must specify only one protocol");
			}
			/*ICMP with port*/
			if(a->protocol==ICMP && a->port>0){
				argp_failure (state, 1, 0, "You can not specify a port for ICMP");
			}
			/*ICMP with tcp flags*/
			if(a->protocol==ICMP && a->tcpf>0){
				argp_failure (state, 1, 0, "You can not specify a tcp flags for ICMP");
			}
			/*UDP with tcp flags*/
			if(a->protocol==UDP && a->tcpf>0){
				argp_failure (state, 1, 0, "You can not specify a tcp flags for UDP");
			}
			/*UDP or TCP without destination port*/
			if(a->dport==-1 && (a->protocol==UDP || a->protocol==TCP)){
				argp_failure (state, 1, 0, "You must specify a destination port");
			}
			/*Destination port number out of range*/
			if((a->protocol==UDP || a->protocol==TCP) && (a->dport < 1 || a->dport > HI_PORT) )
				argp_failure (state, 1, 0, "Port number out of range. It must be between 1 and 65535");
			/*Source port number out of range*/
			if((a->protocol==UDP || a->protocol==TCP) && (a->sport < 1 || a->sport > HI_PORT) ){
				srand(time(NULL));
				a->sport=(rand()%(HI_PORT-LO_PORT))+LO_PORT;
			}
		}
		break;
	}
	return 0;
}
struct argp argp = { options, parse_opt, args_doc, doc};

int main(int argc, char **argv){
	
	struct arguments a;
	if (argp_parse (&argp, argc, argv, 0, 0, &a) == 0){
		printf("IP version:\t%i\nProtocol:\t%i\nDestination IP:\t%lu\nSource IP:\t%lu\nPayload:\t%s\nSYN:\t%i\nACK:\t%i\nFIN:\t%i\nPSH:\t%i\nRST:\t%i\nURG:\t%i\nVerbose:\t%i\nFast:\t%i\nFlood:\t%i\nSport:\t%i\nDport:\t%i\nCount:%i\n",
			a.ip_ver,
			a.protocol,
			a.daddr,
			a.saddr,
			a.payload,
			a.syn,
			a.ack,
			a.fin,
			a.psh,
			a.rst,
			a.urg,
			a.verbose,
			a.fast,
			a.flood,
			a.sport,
			a.dport,
			a.count
		);
	}

	char *data; 
	int packet_size, payload_size, sent, sent_size;
	payload_size = strlen(a.payload);
	
	/*Check protocol*/
	if(a.protocol == UDP)
		packet_size = sizeof (struct iphdr) + sizeof (struct udphdr) + payload_size;
	else if(a.protocol == TCP)
		packet_size = sizeof (struct iphdr) + sizeof (struct tcphdr) + payload_size;
	else
		packet_size = sizeof (struct iphdr) + sizeof (struct icmphdr) + payload_size;
	/*Allocating memory*/
	char *packet = (char *) malloc (packet_size);
	
	//ip header
	struct iphdr *ip = (struct iphdr *) packet;
	struct udphdr *udp;
	struct tcphdr *tcp;
	struct icmphdr *icmp;
	if(a.protocol == UDP){
		udp = (struct udphdr *) (packet + sizeof (struct iphdr));
	}
	else 
	if(a.protocol == TCP){
		tcp = (struct tcphdr *) (packet + sizeof (struct iphdr));
	}
	else{
		icmp = (struct icmphdr *) (packet + sizeof (struct iphdr));
	}
	
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

	ip->version = a.ip_ver;
	ip->ihl = 5;
	ip->tos = 0;
	ip->tot_len = htons (packet_size);
	ip->id = rand ();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = a.protocol;
	ip->saddr = a.saddr;
	ip->daddr = a.daddr;

	if(a.protocol == UDP){
		udp->source		= htons(a.sport);
		udp->dest		= htons(a.dport);
		udp->len		= htons(8 + payload_size);
		udp->check		= 0;
		udp->check		= in_cksum((unsigned short *)udp, sizeof(struct udphdr) + payload_size);
		data			= (packet + sizeof(struct iphdr) + sizeof(struct udphdr));
	}
	else if(a.protocol == TCP){
		tcp->source	= a.sport;
		tcp->dest	= a.dport;
		tcp->fin	= a.fin;
		tcp->syn	= a.syn;
		tcp->rst	= a.rst;
		tcp->psh	= a.psh;
		tcp->ack	= a.ack;
		tcp->urg	= a.urg;
		tcp->check	= in_cksum((unsigned short *)tcp, sizeof(struct tcphdr) + payload_size);
		data		= (packet + sizeof(struct iphdr) + sizeof(struct tcphdr));
	}
	else{
		icmp->type			= ICMP_ECHO;
		icmp->code			= 0;
		icmp->un.echo.sequence = 0;
		icmp->un.echo.id	= rand();
		icmp->checksum		= 0;
		icmp->checksum		= in_cksum((unsigned short *)icmp, sizeof(struct icmphdr) + payload_size);
		data				= (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
	}
	
	struct sockaddr_in servaddr;
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = a.daddr;
	memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));
	strcpy(data,a.payload);
	puts("flooding...");
	
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

