#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<net/if.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<sys/ioctl.h>

#define BUFLEN 512	//Max length of buffer
#define PORT 8888	//The port on which to send data

int main(void){
	struct sockaddr_in si_other;
	struct ifreq ifr;
	int s;//, slen=sizeof(si_other);
	char buf[BUFLEN];
	char message[BUFLEN];
	char iface[] = "eth0";
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
		puts("socket");
	}
	memset((char *) &si_other, 0, sizeof(si_other));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	ioctl(s, SIOCGIFADDR, &ifr);
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	si_other.sin_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	printf("Enter message : ");
	gets(message);
	if(sendto(s, message, strlen(message), 0, (struct sockaddr *)&si_other,sizeof(si_other))==-1){
			puts("sendto()");
	}
	close(s);
	return 0;
}
