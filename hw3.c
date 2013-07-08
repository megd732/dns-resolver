/*
	Megan Davis - CSCI342 Computer Networks
	Assignment 3 - DNS

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "dns.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#define BUFLEN 4096

static int debug=0, nameserver_flag=0, reverse_flag=0;
char *hostname=0, *curQuery=0;	// hostname = original, curquery = current hostname we're querying
char *root_servers;

const uint8_t RECTYPE_A=1;
const uint8_t RECTYPE_NS=2;
const uint8_t RECTYPE_CNAME=5;
const uint8_t RECTYPE_SOA=6;
const uint8_t RECTYPE_PTR=12;
const uint8_t RECTYPE_AAAA=28;

void usage() {
	printf("Usage: hw2 [-d] -n nameserver -i domain/ip_address\n\t-d: debug\n");
	exit(1);
}

/* Count the number of newlines here. Useful more than once, so modular. */
int ncounter(char *servers) {
	int ncounter = 0;
	int i = 0;
	while(servers[i] != '\0') {
		if(servers[i] == '\n')
			ncounter++;
		i++;
	} return ncounter; 
}

/* Pick and return a random starting point from an array of servers */
int randStart(char* servers) {
	int count = ncounter(servers);
	int i = 0;
	srand( time(NULL) );
	int r = rand() % count; // might never generate last server as a possibility
	int startPt = 0, tempctr = 0;
	i = 0;
	while(tempctr < r) {
		if(servers[i] == '\n')
			tempctr++;
		i++;
		if(tempctr == r)
			startPt = i;
	} return startPt;
}

/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname) {
	memset(query,0,max_query);

	in_addr_t rev_addr=inet_addr(hostname);
	if(rev_addr!=INADDR_NONE) {
		static char reverse_name[255];		
		sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
						(rev_addr&0xff000000)>>24,
						(rev_addr&0xff0000)>>16,
						(rev_addr&0xff00)>>8,
						(rev_addr&0xff));
		hostname=reverse_name;
	}

	// first part of the query is a fixed size header
	struct dns_hdr *hdr = (struct dns_hdr*)query;

	// generate a random 16-bit number for session
	uint16_t query_id = (uint16_t) (random() & 0xffff);
	hdr->id = htons(query_id);
	// set header flags to request recursive query
	hdr->flags = htons(0x0000);	
	// 1 question, no answers or other records
	hdr->q_count=htons(1);

	// add the name
	int query_len = sizeof(struct dns_hdr); 
	int name_len=to_dns_style(hostname,query+query_len);
	query_len += name_len; 
	
	// now the query type: A or PTR. 
	uint16_t *type = (uint16_t*)(query+query_len);
	if(rev_addr!=INADDR_NONE)
		*type = htons(12);
	else
		*type = htons(1);
	query_len+=2;

	// finally the class: INET
	uint16_t *class = (uint16_t*)(query+query_len);
	*class = htons(1);
	query_len += 2;
 
	return query_len;	
}

char* resolve(char* potentials, char* current, char* querying) {
	if(!current) { // if there's no current server for some reason, pick one randomly
		int i = randStart(potentials);
		int j = 0;
		char server[256];
		memset(&server, 0, sizeof(server));
		while(potentials[i] != '\n') {
			server[j] = potentials[i];
			i++, j++;
		} server[j] = '\0'; 	// null terminate the server string
		current = server;
	}

	/* Initial debug statement */
	if(debug) {
		printf("How about nameserver %s?\n", current);
		int count = ncounter(potentials);
		printf("\nResolving %s using server %s out of %d.\n", querying, current, count);
	}

	// Create a socket
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock < 0) {
		perror("Creating socket failed: "); 
		exit(1);
	}
	//int optval = 1; // set socket to time out on recv
	//setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&optval, sizeof optval);
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));


	/* Send the query */
	in_addr_t nameserver_addr  = inet_addr(current); 
	// construct the query message
	uint8_t query[1500];
	int query_len=construct_query(query,1500,querying);	

	struct sockaddr_in addr; 	// internet socket address data structure
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53); // port 53 for DNS
	addr.sin_addr.s_addr = nameserver_addr; // destination address (any local for now)
	
	int send_count = sendto(sock, query, query_len, 0,
													(struct sockaddr*)&addr,sizeof(addr));
	if(send_count<0) { perror("Send failed");	exit(1); }	

	// await the response 
	uint8_t answerbuf[1500];
	int rec_count = recv(sock,answerbuf,1500,0);
	if (rec_count < 1) {			// this is not properly resolving a time out; just blocks forever
		if((errno == EAGAIN) || (errno == EWOULDBLOCK)) 
			return resolve(root_servers, NULL, querying); // if we timed out, call the function again w/ a NULL server, pick random.
	}
	
	// parse the response to get our answer
	struct dns_hdr *ans_hdr=(struct dns_hdr*)answerbuf;
	uint8_t *answer_ptr = answerbuf + sizeof(struct dns_hdr);
	
	// now answer_ptr points at the first question. 
	int question_count = ntohs(ans_hdr->q_count);
	int answer_count = ntohs(ans_hdr->a_count);
	int auth_count = ntohs(ans_hdr->auth_count);
	int other_count = ntohs(ans_hdr->other_count);

	int total = answer_count + auth_count + other_count;

	if(debug) {
		printf("Got %d+%d+%d=%d resource records total.\n", answer_count, auth_count, other_count, total);
	}

	// skip past all questions
	int q;
	for(q=0;q<question_count;q++) {
		char string_name[255];
		memset(string_name,0,255);
		int size=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr+=size;
		answer_ptr+=4; //2 for type, 2 for class
	}

	// ANSWER AND AUTHORITY SECTIONS
	int a;
	char *nsrecords[512];
	int nsCount = 0;
	for(a=0;a<answer_count+auth_count;a++) {
		// first the name this answer is referring to 
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*)answer_ptr;
		answer_ptr+=sizeof(struct dns_rr);

		// A record in answer section - we're done, return the name
		if(htons(rr->type)==RECTYPE_A) {
			if(debug)
				printf("The name %s resolves to IP addr: %s\n",
						 	string_name,
							 inet_ntoa(*((struct in_addr *)answer_ptr)));
			return inet_ntoa(*((struct in_addr *)answer_ptr));
		}
		// CNAME record
		else if(htons(rr->type)==RECTYPE_CNAME) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s is also known as %s.\n",
							 string_name, ns_string);
			querying = ns_string;

			/* If we just queried with the basic nameserver, populate the list w/ root servers
				and reset the nameserver_flag so we don't do this again */
			if(nameserver_flag) {
				potentials = root_servers;
				nameserver_flag = 0;
			}
			// pick a random server to query next, from the list
			int i = randStart(potentials);
			int j = 0;
			char server[256];
			memset(&server, 0, sizeof(server));
			while(potentials[i] != '\n') {
				server[j] = potentials[i];
				i++, j++;
			} server[j] = '\0'; 
			return resolve(potentials, server, querying);		 // recursively continue to query!					
		}
		// NS record
		else if(htons(rr->type)==RECTYPE_NS) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s can be resolved by NS: %s\n",
							 string_name, ns_string);
			// Put these in an array to use if there's nothing else.
			nsrecords[nsCount] = malloc(25*sizeof(char));
			nsrecords[nsCount] = strdup(ns_string);
			nsCount++;
		}
		// PTR record (reverse lookup, ip to domain name -- if we were looking for this, also done)
		else if(htons(rr->type)==RECTYPE_PTR) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The host at %s is also known as %s.\n",
						 	string_name, ns_string);	
			if(reverse_flag)
				return strdup(ns_string);			// if this was a reverse lookup, we're done! otherwise whatever							
		}
		// SOA record (ignore)
		else if(htons(rr->type)==RECTYPE_SOA) {
			if(debug)
				printf("Ignoring SOA record\n");
		}
		// AAAA record (ignore)
		else if(htons(rr->type)==RECTYPE_AAAA)  {
			if(debug)
				printf("Ignoring IPv6 record\n");
		}
		else {
			if(debug)
				printf("got unknown record type %hu\n",htons(rr->type));
			return NULL;
		} 

		answer_ptr+=htons(rr->datalen);
	}

	// if nothing in additional section, preemptively check the NS records
	if(other_count == 0) {
		char *nsips = malloc(BUFLEN);
		int counter = 0;
		int k;
		if(nsCount==0)
			return NULL;
		for(k=0; k<nsCount; k++) {
			char *tempStr = resolve(root_servers, NULL, nsrecords[k]);
			int i=0;
			while(tempStr[i] != '\0') {
				nsips[counter] = tempStr[i];
				counter++, i++;
			} nsips[counter] = '\n'; // newline termination
			counter++;
		}
		return resolve(nsips, NULL, querying); // now try to resolve the query using these IPs
	}	

	// ADDITIONAL SECTION (if there wasn't an answer or a PTR)
	char *returnArray = malloc(BUFLEN);
	for(a=answer_count+auth_count;a<answer_count+auth_count+other_count;a++){
		char string_name[255];
		int dnsnamelen=from_dns_style(answerbuf,answer_ptr,string_name);
		answer_ptr += dnsnamelen;

		// then fixed part of the RR record
		struct dns_rr* rr = (struct dns_rr*)answer_ptr;
		answer_ptr+=sizeof(struct dns_rr);

		// take these and query these next create an array of ptrs to push into the resolve query
		if(htons(rr->type)==RECTYPE_A) {
			char ipaddr[256];
			memset(&ipaddr, 0, sizeof(ipaddr));
			char *temp = inet_ntoa(*((struct in_addr *)answer_ptr));
			int i = 0;
			while(temp[i] != '\0') {
				ipaddr[i] = temp [i];
				i++;
			} ipaddr[i] = '\n';
			strcat(returnArray, ipaddr);
			if(debug)
				printf("The name %s resolves to IP addr: %s\n",
						 string_name,
						 inet_ntoa(*((struct in_addr *)answer_ptr)));
		}
		// NS record
		else if(htons(rr->type)==RECTYPE_NS) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s can be resolved by NS: %s\n",
							 string_name, ns_string);					
		}
		// CNAME record
		else if(htons(rr->type)==RECTYPE_CNAME) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The name %s is also known as %s.\n",
							 string_name, ns_string);								
		}
		// PTR record (reverse lookup, ip to domain name -- if we were looking for this, also done)
		else if(htons(rr->type)==RECTYPE_PTR) {
			char ns_string[255];
			int ns_len=from_dns_style(answerbuf,answer_ptr,ns_string);
			if(debug)
				printf("The host at %s is also known as %s.\n",
						 string_name, ns_string);								
		}
		// SOA record (ignore)
		else if(htons(rr->type)==RECTYPE_SOA) {
			if(debug)
				printf("Ignoring SOA record\n");
		}
		// AAAA record (ignore)
		else if(htons(rr->type)==RECTYPE_AAAA)  {
			if(debug)
				printf("Ignoring IPv6 record\n");
		}
		else {
			if(debug)
				printf("got unknown record type %hu\n",htons(rr->type));
		} 

		answer_ptr+=htons(rr->datalen);
	}

	// Iterate through all possible servers.
	int k;
	int i = 0;
	for(k=0; k < ncounter(potentials); k++) {
		int j = 0;
		char server[256];
		memset(&server, 0, sizeof(server));
		while(potentials[i] != '\n') {
			server[j] = potentials[i];
			i++, j++;
		} server[j] = '\0';
		i++; // so it starts at the next character
		char *retStr;
		if((retStr = resolve(returnArray, server, querying)) != NULL) // if we got a response, give it!
			return retStr;
	}

	shutdown(sock,SHUT_RDWR);
	close(sock);
	return NULL; 		// if nothing else worked
}

int main(int argc, char** argv)
{
	if(argc<2) usage();
	
	char *nameserver=0;
	
	char *optString = "-d-n:-i:";
 	int opt = getopt( argc, argv, optString );
	
	/* Process command line arguments */
	while( opt != -1 ) {
		switch( opt ) {      
		case 'd':
			debug = 1; 
			break;
		case 'n':
			nameserver_flag = 1; 
			nameserver = optarg;
			break;	 		
		case 'i':
			hostname = optarg;
			break;	
		case '?':
			usage();
			exit(1);               
		default:
			usage();
			exit(1);
		}
		opt = getopt( argc, argv, optString );
	}
		
	if(!hostname) {
		usage();
		exit(1);
	}

	/* Process the hostname to determine if we're doing a reverse lookup (is IP?) */
	int d1, d2, d3, d4;
	sscanf(hostname, "%3d.%3d.%3d.%3d", &d1, &d2, &d3, &d4);
	if(d1 && d2 && d3 && d4) { // this will do it for anything with 3 periods, which is annoying
		reverse_flag = 1; 
	} 

	/* Initial steps pre-loop: if there no nameserver specified, pick something random from root-servers.txt */
	char *servers = malloc(BUFLEN);	// array for storing the server names
	int fd = open("root-servers.txt", O_RDWR);	// open the file for reading and writing
	if (fd == -1) 
		perror("Error opening file: ");

	int ret = read(fd, servers, BUFLEN);
	if(ret == -1) 
		perror("Error reading from file.\n");

	root_servers = servers; // global pointer

	char *answer = 0 ;
	if(!nameserver) {
		answer = resolve(servers, NULL, hostname); // just feed it the list of servers, it'll pick sth. random
	} else { 				// otherwise just use the default nameserver
		char start[300];
		sprintf(start, "%s\n", nameserver); // construct a "starting" list out of... this
		answer = resolve(start, nameserver, hostname);
	}

	if(!answer) {
		printf("The hostname %s could not be resolved.\n", hostname);
	} else {
		printf("The hostname %s resolved to %s.\n", hostname, answer); 
	}
}
