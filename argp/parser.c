#include <stdio.h>
#include <argp.h>
#include <argz.h>
#include <stdlib.h>
#include <stdbool.h>
const char *argp_program_bug_address = "xzamora@seguridad.unam.mx ";
const char *argp_program_version = "version 1.0";
static char doc[]="Simple packet's crafter\v"
      				"With great power comes great responsability";/*Little description*/
static char args_doc[]="IP_DST";/*Usage*/
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
	//{"daddr"	,'d'	,0			,0,"Destination IP address"},
};
struct arguments{
	char ip_ver;						/*IP Version*/
	char protocol;						/*Protocol to send*/
	char *argz;							/*All arguments*/
	char *dst_ip;						/*Destination ip*/
	char *src_ip;						/*Source ip*/
	char *payload;						/*Payload packet*/
	size_t argz_len;					/*# of args*/
	bool syn,ack,fin,psh,rst,urg;	/*TCP Flags*/
	bool verbose,fast,flood;		/*Boolean options*/
	unsigned int sport,dport;		/*Port number*/
	unsigned int count;				/*Number of packets to send*/
	
	
};
static int parse_opt (int key, char *arg, struct argp_state *state){
	struct arguments *a = state->input;
	switch (key){
		case 1111:/*ICMP Protocol*/
			a->protocol=1;
		break;
		case 2222:/*UDP Protocol*/
			a->protocol=17;
		break;
		case 3333:/*TCP Protocol*/
			a->protocol=6;
		break;
		case 1000:/*Send fast*/
			a->fast=true;
		break;
		case 1001:/*Send flood*/
			a->flood=true;
		break;
		case '4':/*IPv4*/
			a->ip_ver=4;
		break;
		case '6':/*IPv6*/
			a->ip_ver=6;
		break;
		case 'c':/*Count*/
			a->count=atoi(arg);
		break;
		case 'p':/*Payload*/
			a->payload=arg;
		break;
		case 's':/*Source IP*/
			a->src_ip=arg;
		break;
		case 'v':/*Verbose*/
			a->verbose=true;
		break;
		case 'x':/*SRC Port*/
			a->sport=atoi(arg);
		break;
		case 'y':/*DST Port*/
			a->dport=atoi(arg);
		break;
		case 'S':/*SYN Flag*/
			a->syn=true;
		break;
		case 'A':/*ACK Flag*/
			a->ack=true;
		break;
		case 'F':/*FIN Flag*/
			a->fin=true;
		break;
		case 'P':/*PSH Flag*/
			a->psh=true;
		break;
		case 'R':/*RST Flag*/
			a->rst=true;
		break;
		case 'U':/*URG Flag*/
			a->urg=true;
		break;
		case ARGP_KEY_ARG:
			argz_add (&a->argz, &a->argz_len, arg);
			a->dst_ip=arg;
		break;
		case ARGP_KEY_INIT:
			a->argz = 0;
			a->argz_len = 0;
			a->ip_ver=4;
			a->protocol=1;
			a->src_ip=NULL;
			a->payload=NULL;
			a->sport=0;
			a->dport=80;
			a->syn=false;
			a->ack=false;
			a->fin=false;
			a->psh=false;
			a->rst=false;
			a->urg=false;
			a->fast=false;
			a->flood=false;
			//a->syn=a->ack=a->fin=a->psh=a->rst=a->urg=false;	/*TCP Flags*/
		break;
		case ARGP_KEY_END:{
			size_t count = argz_count (a->argz, a->argz_len);
			if (count > 1)
				argp_failure (state, 1, 0, "too many arguments");
			else if (count < 1)
				argp_failure (state, 1, 0, "too few arguments");
		}
		break;
	}
	return 0;
}
int main (int argc, char **argv){
	struct argp argp = { options, parse_opt, args_doc, doc};
	struct arguments arguments;
	if (argp_parse (&argp, argc, argv, 0, 0, &arguments) == 0){
		//printf("%s");
		/*
		const char *prev = NULL;
		char *word;
		while ((word = argz_next (arguments.argz, arguments.argz_len, prev))){
			printf (" %s", word);
			prev = word;
		}
		printf ("\n");
		free (arguments.argz);
		*/
		printf("%i %s %s %i %s\n",arguments.syn,arguments.src_ip,arguments.payload,arguments.ip_ver,arguments.dst_ip);
	}
	return 0;
}
