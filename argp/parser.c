#include <argp.h>
#include <argz.h>
#include <stdlib.h>
#include <arpa/inet.h>

#ifndef HI_PORT
#define HI_PORT 65535
#endif
#ifndef LO_PORT
#define LO_PORT 32768
#endif

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
	int syn,ack,fin,psh,rst,urg;	/*IPPROTO_TCP Flags*/
	int verbose,fast,flood;			/*Boolean options*/
	unsigned int sport,dport;		/*Port number*/
	unsigned int count;				/*Number of packets to send*/
	int proto,port,tcpf;				/*Control flags*/
	unsigned char saddr6[sizeof(struct in6_addr)];
	unsigned char daddr6[sizeof(struct in6_addr)];
	char *sa,*da;
};
static int parse_opt (int key, char *arg, struct argp_state *state){
	struct arguments *a = state->input;
	switch (key){
		case 1111:/*IPPROTO_ICMP Protocol*/
			a->protocol=IPPROTO_ICMP;
			a->proto++;
		break;
		case 2222:/*IPPROTO_UDP Protocol*/
			a->protocol=IPPROTO_UDP;
			a->proto++;
		break;
		case 3333:/*IPPROTO_TCP Protocol*/
			a->protocol=IPPROTO_TCP;
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
			a->sa=arg;
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
			a->da=arg;
		break;
		case ARGP_KEY_INIT:
			a->argz = 0;
			a->argz_len = 0;
			a->ip_ver=4;
			a->protocol=IPPROTO_ICMP;
			a->saddr=0;
			a->daddr=0;
			a->sa=NULL;
			a->da=NULL;
			a->payload="";
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
			/*Check only one argument*/
			if (count > 1){
				argp_usage(state);
				argp_failure (state, 1, 0, "too many arguments");
			}
			else if (count < 1){
				argp_usage(state);
				argp_failure (state, 1, 0, "too few arguments");
			}
			/*Check IPv4 address(es)*/
			if(a->ip_ver == 4){
				if(a->sa != NULL)
					if (inet_pton(AF_INET, a->sa, &(a->saddr)) != 1)
						argp_failure (state, 1, 0, "Bad source IP address, try again");
				if (inet_pton(AF_INET, a->da, &(a->daddr)) != 1)
					argp_failure (state, 1, 0, "Bad destination IP address, try again");
			}
			/*Check IPv6 address(es)*/
			if(a->ip_ver == 6){
				if(a->sa != NULL)
					if (inet_pton(AF_INET6, a->sa, &(a->saddr6)) != 1)
						argp_failure (state, 1, 0, "Bad source IP address, try again");
				if (inet_pton(AF_INET6, a->da, &(a->daddr6)) != 1)
					argp_failure (state, 1, 0, "Bad destination IP address, try again");
			}
			/*More than one protocol specified*/
			if(a->proto>1)
				argp_failure (state, 1, 0, "You must specify only one protocol");
			/*IPPROTO_ICMP with port*/
			if(a->protocol==IPPROTO_ICMP && a->port>0)
				argp_failure (state, 1, 0, "You can not specify a port for IPPROTO_ICMP");
			/*IPPROTO_ICMP with tcp flags*/
			if(a->protocol==IPPROTO_ICMP && a->tcpf>0)
				argp_failure (state, 1, 0, "You can not specify a tcp flags for IPPROTO_ICMP");
			/*IPPROTO_UDP with tcp flags*/
			if(a->protocol==IPPROTO_UDP && a->tcpf>0)
				argp_failure (state, 1, 0, "You can not specify a tcp flags for IPPROTO_UDP");
			/*IPPROTO_UDP or IPPROTO_TCP without destination port*/
			if(a->dport==-1 && (a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP))
				argp_failure (state, 1, 0, "You must specify a destination port");
			/*Destination port number out of range*/
			if((a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP) && (a->dport < 1 || a->dport > HI_PORT) )
				argp_failure (state, 1, 0, "Port number out of range. It must be between 1 and 65535");
			/*Source port number out of range, set random*/
			if((a->protocol==IPPROTO_UDP || a->protocol==IPPROTO_TCP) && (a->sport < 1 || a->sport > HI_PORT) ){
				srand(time(NULL));
				a->sport=(rand()%(HI_PORT-LO_PORT))+LO_PORT;
			}
		}
		break;
//		default:
//			argp_usage(state);
	}
	return 0;
}
	struct argp argp = { options, parse_opt, args_doc, doc};

int main (int argc, char **argv){
	struct arguments arguments;
	if (argp_parse (&argp, argc, argv, 0, 0, &arguments) == 0){
		if(arguments.ip_ver==4){
		printf("IP version:\t%i\nProtocol:\t%i\nDestination IP:\t%lu\nSource IP:\t%lu\nPayload:\t%s\nSYN:\t%i\nACK:\t%i\nFIN:\t%i\nPSH:\t%i\nRST:\t%i\nURG:\t%i\nVerbose:\t%i\nFast:\t%i\nFlood:\t%i\nSport:\t%i\nDport:\t%i\nCount:%i\n",
			arguments.ip_ver,
			arguments.protocol,
			arguments.daddr,
			arguments.saddr,
			arguments.payload,
			arguments.syn,
			arguments.ack,
			arguments.fin,
			arguments.psh,
			arguments.rst,
			arguments.urg,
			arguments.verbose,
			arguments.fast,
			arguments.flood,
			arguments.sport,
			arguments.dport,
			arguments.count
		);
		}
		if(arguments.ip_ver==6){
		printf("IP version:\t%i\nProtocol:\t%i\nDestination IP:\t%s\nSource IP:\t%s\nPayload:\t%s\nSYN:\t%i\nACK:\t%i\nFIN:\t%i\nPSH:\t%i\nRST:\t%i\nURG:\t%i\nVerbose:\t%i\nFast:\t%i\nFlood:\t%i\nSport:\t%i\nDport:\t%i\nCount:%i\n",
			arguments.ip_ver,
			arguments.protocol,
			arguments.da,
			arguments.sa,
			arguments.payload,
			arguments.syn,
			arguments.ack,
			arguments.fin,
			arguments.psh,
			arguments.rst,
			arguments.urg,
			arguments.verbose,
			arguments.fast,
			arguments.flood,
			arguments.sport,
			arguments.dport,
			arguments.count
		);
	}
	}
	return 0;
}

