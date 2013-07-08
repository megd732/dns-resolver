#include <stdint.h>

/* DNS header structure. Most of the message is variable
	 size, which means we can't declare them in this C struct */
struct dns_hdr {
	uint16_t id,flags,q_count,a_count,auth_count,other_count;	
	// variable number of questions
	// variable number of answer resource records
	// variable number of authoritative server records
	// variable number of other resource records
} __attribute__((packed));

struct dns_rr {
	// first a variable sized name, then
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t datalen;
	// and then a variable sized data field
} __attribute__((packed));

/* converts between the normal www.cs.uic.edu format to
	 the DNS-style 3www2cs3uic3edu format. Returns the
   length of the string written to dns_name. */

int to_dns_style(char* str_name, uint8_t* dns_name)
{
	int part_len=0;
	int i;
	for(i=0;i<strlen(str_name);i++) {
		if(str_name[i]!='.') {
			dns_name[i+1]=str_name[i];
			part_len++;
		}
		else {
			dns_name[i-part_len]=part_len;
			part_len=0;
		}
	}
	dns_name[strlen(str_name)-part_len]=part_len;
	dns_name[strlen(str_name)+1]=0;
	return strlen(str_name)+2;
}

/* converts between DNS-style format to normal host name format.
	 Also supports DNS-style name compression: message should point to
	 the first byte of the DNS message.
	 
	 Returns the number of bytes of dns_name read.
 */
int from_dns_style(uint8_t *message, uint8_t* dns_name, char* str_name) {
	uint8_t part_remainder=0;
	int len=0;
	int return_len=0;
	uint8_t* orig_name = dns_name;
	while(*dns_name) {
		if(part_remainder==0) {
			// this condition checks for message compression, see RFC 1035 4.1.4
			if((*dns_name)>=0xc0) { 
				if(return_len==0)
					return_len = (dns_name-orig_name)+2;
				dns_name=message+(((*dns_name)&0x3f)<<8)+*(dns_name+1);
				continue;
			}
			else {
				part_remainder=*dns_name;
				if(len>0)
					str_name[len++]='.';
			}
		}
		else {
			str_name[len++]=*dns_name;
			part_remainder--;
		}
		dns_name++;
	}
	str_name[len]=0;
	return (return_len?return_len:dns_name-orig_name+1);
}
