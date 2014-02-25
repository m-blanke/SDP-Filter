#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <linux/types.h>
#include <linux/netfilter.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void init();
void end();
struct nfq_handle* h;
struct nfq_q_handle* qh;
struct nfnl_handle* nh;
int fd;
int rv;
int callback(struct nfq_q_handle *qh_,struct nfgenmsg* nfmsg, struct nfq_data *nfa, void* customData);
char buf[4096];

//bool parse_XYZ(int lengthOfXYZ, uint32_t* dataXYZ);
//default policy is to pass everything
bool parse_ipv4(int length,uint32_t* data);
bool parse_udp(int length,uint32_t* data);
bool parse_sap(int length,uint32_t* data);
bool parse_sdp(int length,uint32_t* data);

struct saphdr {//endianness probably compensated (too tired to check more then version)
	uint8_t compressed:1;
	uint8_t encrypted:1;
	uint8_t type:1;
	uint8_t reserved:1;
	uint8_t address_type:1;
	uint8_t version:3;

	uint8_t auth_len;
	
	uint16_t msg_id_hash;
	
	uint32_t source;
	
};


int main(int argc, char** argv){
	init();
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h,buf,rv);
	}
	end();
	return 0;
}

bool parse_sdp(int length, uint32_t* data){//Parse SDP
/*	int strc = 0;
	//for(int i = 0; i < length; i++){
	int i = 0;
	while(((char*)data)[i+1] != 0x00){
		if((((char*)data)[i] == 0x0D) && (((char*)data)[i+1] == 0x0A)){
			((char*)data)[i]=0x00;
			((char*)data)[i+1]=0x00;
			strc++;
		}
		i++;
	}*/
	
	//printf("SDP Packet with %d description:%d\n",strc);
	printf("%s\n",(char*)data);

	return true;
}

bool parse_sap(int length, uint32_t* data){//Parse SAP, false for an unaccepted annoucement, true for everything else (including parsing errors)
	struct saphdr* header = (struct saphdr*)data;
	if(header->version != 1){
		fprintf(stderr,"Version 0x%x unsuported!\n",header->version);
		return true;
	}
/*	fprintf(stderr,"C: %d\n",header->compressed);	
	fprintf(stderr,"E: %d\n",header->encrypted);	
	fprintf(stderr,"T: %d\n",header->type);
	fprintf(stderr,"R: %d\n",header->reserved);	
	fprintf(stderr,"A: %d\n",header->address_type);
	fprintf(stderr,"V: %d\n",header->version);	
	fprintf(stderr,"auth: %d\n",header->auth_len);	
	fprintf(stderr,"msgid: %d\n",ntohs(header->msg_id_hash));*/

	data = (uint32_t*)(((unsigned long)data) + 8 + 4*(header->encrypted) + 4*(header->auth_len)); 
	length -= (8 +4*(header->encrypted) + 4*(header->auth_len));
	if(((char*)(data))[1] != '='){//got MIME-Type/payloadType 
		data = (uint32_t*)((unsigned long)data + strlen((char*)data) + 1);
		length -= (strlen((char*)data) + 1);
	}
	
	return parse_sdp(length,data);
}	

bool parse_udp(int length, uint32_t* data){//Parse udp header, false for an unaccepted announcement, true for everything else (including wrong port) 
	struct udphdr* header = (struct udphdr*)data;
	if(ntohs(header->dest) != 9875){//destionation port
		fprintf(stderr,"Port is not 9875 but %d!\n",ntohs(header->dest));
		return true;
	}
	//Again ignoring checksum	
	return parse_sap(length-8,data+2);
}

bool parse_ipv4(int length, uint32_t* data){//parse ipv4 header, false for an unaccepted announcement, true for everything else (including wrong protocol)
	struct ip* header = (struct ip*)data;
	if(header->ip_v != 4){//Version
		fprintf(stderr,"No IPv4!\n");
		return true;
	} 

	if(header->ip_hl != 5){//IP Header Length
		fprintf(stderr,"I don't know how to parse a header this size!\n");
		return true;
	}
	//Ignoring a lot of stuff right here
	if(header->ip_p != IPPROTO_UDP){//Checking Protocol for UDP
		fprintf(stderr,"No UDP %d!\n",header->ip_p);
		return true;
	}	
	//Ignoring more stuff, e.g. checksum and source-/destinationaddress
	return parse_udp(length-20,data+5);
}

int callback(struct nfq_q_handle *qh_,struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* customData){//gets calles by nfq_handle_packet
	int id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);//packet id
	unsigned char* data;
	int len = nfq_get_payload(nfa, &data);//obtain payload
	return nfq_set_verdict(qh,id,parse_ipv4(len,(uint32_t*)data)?NF_ACCEPT:NF_DROP,0,NULL);
}

void end(){
	if(nfq_close(h) != 0){
		fprintf(stderr, "error during nfq_close()\n");
		exit(1);
	}
}


void init(){
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '42'\n");
	qh = nfq_create_queue(h,  42, &callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	
	fd = nfq_fd(h);
}
