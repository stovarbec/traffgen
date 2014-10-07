#include <stdio.h>
#include <argp.h>
#include <argz.h>
#include <stdlib.h>
const char *argp_program_bug_address = "xzamora@seguridad.unam.mx";
const char *argp_program_version = "version 1.0";
static char doc[]="Simple packet's crafting\v"
      				"With great power comes great responsability";/*Little description*/
static char args_doc[]="IP_DST";/*Usage*/
struct arguments{
	char *argz;
	size_t argz_len;
};
static int parse_opt (int key, char *arg, struct argp_state *state){
	struct arguments *a = state->input;
	switch (key){
		case 1111:/*ICMP Protocol*/
			printf("%s",arg);
		break;
		case 2222:/*UDP Protocol*/
			printf("%s",arg);
		break;
		case 3333:/*TCP Protocol*/
			printf("%s",arg);
		break;
		case 'x':/*SRC Port*/
			printf("%s",arg);
		break;
		case 'y':/*DST Port*/
			printf("%s",arg);
		break;
		case 'S':/*SYN Flag*/
			printf("%s",arg);
		break;
		case 'A':/*ACK Flag*/
			printf("%s",arg);
		break;
		case 'F':/*FIN Flag*/
			printf("%s",arg);
		break;
		case 'P':/*PSH Flag*/
			printf("%s",arg);
		break;
		case 'R':/*RST Flag*/
			printf("%s",arg);
		break;
		case 'U':/*URG Flag*/
			printf("%s",arg);
		break;
		case ARGP_KEY_ARG:
			argz_add (&a->argz, &a->argz_len, arg);
		break;
		case ARGP_KEY_INIT:
			a->argz = 0;
			a->argz_len = 0;
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
	struct argp_option options[] ={
		{"icmp"		,1111	,0			,0,"ICMP Packet"},
		{"udp"		,2222	,0			,0,"UDP Packet"},
		{"tcp"		,3333	,0			,0,"TCP Packet"},
		{"ip4"		,'4'	,0			,0,"IPv4 Packet"},
		{"ip6"		,'6'	,0			,0,"IPv6 Packet"},
		{"sport"		,'x'	,"NUM"	,0,"Source port"},
		{"dport"		,'y'	,"NUM"	,0,"Destination port"},
		{"saddr"		,'s'	,"IP"		,0,"Set a spoffed source IP address"},
		//{"daddr"	,'d'	,0			,0,"Destination IP address"},
		{"fast"		,1000	,0			,0,"Send 100 packets per second"},
		{"flood"		,1001	,0			,0,"Send many packets as possible"},
		{"count"		,'c'	,"NUM"	,0,"Send NUM packets, one per second"},
		{"payload"	,'p'	,"STR"	,0,"Include a message in the payload"},
		{"verbose"	,'v'	,0			,0,"Produce verbose output" },
	
		{0,0,0,0, "The following options could be grouped together after --tcp flag:\n" },
	
		{0,'S',0,0,"Set SYNCHRONIZATION Flag"},
		{0,'A',0,0,"Set ACKNOWLEDGE Flag"},
		{0,'F',0,0,"Set FIN Flag"},
		{0,'P',0,0,"Set PUSH Flag"},
		{0,'R',0,0,"Set RESET Flag"},
		{0,'U',0,0,"Set URGENT Flag"},
		{ 0 }
	};
	struct argp argp = { options, parse_opt, args_doc, doc};
	struct arguments arguments;
	if (argp_parse (&argp, argc, argv, 0, 0, &arguments) == 0){
		const char *prev = NULL;
		char *word;
		while ((word = argz_next (arguments.argz, arguments.argz_len, prev))){
			printf (" %s", word);
			prev = word;
		}
		printf ("\n");
		free (arguments.argz);
	}
	return 0;
}
