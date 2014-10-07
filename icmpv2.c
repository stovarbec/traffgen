#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define MTU 1400 // The data padding length of the ICMP packet

struct icmp_echo{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned short identifier;
	unsigned short sequence;
	char data[MTU]; /* we're going to send data MTU bytes at a time */
};

struct ip_header{
	unsigned int	hl:4,		/* 4 bit header length */
						ver:4;	/* 4 bit version */
	unsigned char	tos;		/* type of service */
	unsigned short totl;		/* total length of datagram */
	unsigned short	id;		/* identifier */
	unsigned short notused;	/* this is were flags and fragment offset would go */
	unsigned char 	ttl;		/* time to live */
	unsigned char	prot;		/* protocol */
	unsigned short	csum;		/* our checksum */
	unsigned long 	saddr;	/* source address */
	unsigned long 	daddr;	/* destination address */
};

/* our checksum function */
unsigned short calcsum(unsigned short *buffer, int length);

int main(int argc, char **argv){
	struct ip_header* ipheader;
	struct icmp_echo* icmp;
	struct sockaddr_in connection;
	char *packet;
	int sockfd, value=1, i;
	int finishedreadingfile=0, waittime=0;
	unsigned short key = 0xAABB; 	/* our xor encryption/decryption key */

	/* must be root to use this program */
	if (getuid() != 0){
		fprintf(stderr, "You must be root to run this program\n");
		exit(-1);
	}
	
	/* set our wait time */
	//waittime=atoi(argv[4]);
	waittime=1;

	/* Let's allocate enough memory for our packet */
	if ( (packet = malloc(sizeof(struct ip_header) + sizeof(struct icmp_echo))) == NULL){
		fprintf(stderr, "Could not allocate memory for packet\n");
		exit(-1);
	}

	/* Now we're going to point our iphdr and icmp_echo pointers to the proper places 
	 * so we can edit our packet
	 */
	ipheader = (struct ip_header*)packet;
	icmp = (struct icmp_echo*)(packet+sizeof(struct ip_header));

	/* seed random and throw the first value out which appears to be less random (for our id number) */
	srand(time(NULL));
	random();

	/* Now we'll begin setting up the IP packet */
	ipheader->ver 		= 4; 	/*IPv4*/
	ipheader->hl		= 5; 	/* This is the smallest possible value, our IP header is only 20 bytes */
	ipheader->tos		= 0;
	ipheader->totl		= sizeof(struct ip_header)+sizeof(struct icmp_echo);
	ipheader->id		= htons(0x1337);
	ipheader->notused	= 0;	/* make sure this is set to zero since we're not using it */
	ipheader->ttl		= 255;  /* we're just making this largest possible value */
	ipheader->prot		= 1;	/* protocol 1 says ICMP is next header */
	ipheader->csum		= 0;	/* initialize this to zero to properly calculate checksum */
	ipheader->saddr 	= inet_addr(argv[1]);	/* our spoofed address */
	ipheader->daddr	= inet_addr(argv[2]);	/* where our packets are going */
	ipheader->csum		= calcsum((unsigned short*)ipheader, sizeof(struct ip_header));

	/* Alright, on to the ICMP part */
	icmp->type			= 8;		/* icmp echo */
	icmp->code			= 0;		/* only valid value for echo or echo reply */
	icmp->identifier	= 0x1337;	/* the id we'll be using to distinguish our data from other icmp packets */
	icmp->sequence		= 0;		/* our initial sequence will be zero */

	/* let's go ahead and create our socket before we enter the main loop for reading the file */
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
		free(packet);
		fprintf(stderr, "Could not initialize socket\n");
		exit(-1);
	}
	
	/* if IP_HDRINCL isn't set, the kernel will try to put it's own header on our packet */
	if( setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(int)) ){
		printf("Could not use custom header.\n");
	}

	/* connection is just a variable used to define who we're sending to for sendto() */
	connection.sin_family		= AF_INET;
	connection.sin_addr.s_addr	= ipheader->daddr;

	while(!finishedreadingfile){
		/* zero out data before we load it */
		//bzero(icmp->data, MTU);
		int ctr=0;		// Counter to stay under MTU
		icmp->data[ctr] = argv[3][ctr];
		while( icmp->data[ctr] != '\0' && ctr < MTU){
			icmp->data[++ctr] = argv[3][ctr];
		}
		/* just like IP we have to zero the checksum before we calculate it */
		icmp->checksum = 0;
		/* now we can calculate the checksum */
		icmp->checksum = calcsum((unsigned short*)icmp, sizeof(struct icmp_echo));
		/* now let's send it out! */
		//sendto(sockfd, packet, ipheader->totl, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
		/* uncomment for debugging
		 * printf("Sent %s block\n", icmp->data);
		 */
		sleep(waittime);

		if(icmp->data[ctr] == '\0'){ finishedreadingfile = 1; }
	}

	/* to signal to the listener that we're done sending data, we'll send an icmp packet with 
	 * identifier 0x2600
	 */
	//bzero(icmp->data, MTU);
	ipheader->id = 0x2600;
	//icmp->identifier= 0x2600;
	icmp->checksum = 0;
	icmp->checksum = calcsum((unsigned short*)icmp, sizeof(struct icmp_echo));

	sendto(sockfd, packet, ipheader->totl, 0, (struct sockaddr *)&connection, sizeof(struct sockaddr));
	
	printf("Now leaving\n");
	/* Clean up after ourselves */
//	fclose(file);
	close(sockfd);
	free(packet);

	return 0;
}

/* calcsum - used to calculate IP and ICMP header checksums using
 * one's compliment of the one's compliment sum of 16 bit words of the header
 */
unsigned short calcsum(unsigned short *buffer, int length){
	unsigned long sum; 	

	// initialize sum to zero and loop until length (in words) is 0 
	for (sum=0; length>1; length-=2) // sizeof() returns number of bytes, we're interested in number of words 
		sum += *buffer++;	// add 1 word of buffer to sum and proceed to the next 
	// we may have an extra byte 
	if (length==1)
		sum += (char)*buffer;

	sum = (sum >> 16) + (sum & 0xFFFF);  // add high 16 to low 16 
	sum += (sum >> 16);		     // add carry 
	return ~sum;
}
