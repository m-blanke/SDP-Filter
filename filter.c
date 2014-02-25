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


/**
*Configuration:
*   BLACKLIST true/false for default policy
*
**/
#define BLACKLIST false
/**
*   VERDICT,"attribute",FILTER,"string"
*   for example:
*   ALLOW,"a=x-plgroup:",BEGINS-WITH,"KaWo1-"
*   VERDICT := ALLOW || DISALLOW
*   FILTER := IS || BEGINS_WITH || ENDS_WITH || CONTAINS
*   
*   RULESC _must_ be the number of rules, or compiler mayhem is going to happen
**/
#define RULESC 3
#define RULES \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Tuerme-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Hilton-"}, \
	{ALLOW,"a=x-plgroup:",BEGINS_WITH,"RWTH"}, \






#ifdef DEBUG
	#define DBG printf
#else
	#define DBG(...) ;
#endif

void init();
void end();
struct nfq_handle* h;
struct nfq_q_handle* qh;
struct nfnl_handle* nh;
int fd;
int rv;
char buf[4096];

enum verdict_t {ALLOW=1,DISALLOW=0};
enum filter_t {IS,BEGINS_WITH, ENDS_WITH,CONTAINS};

struct rule_t {
	enum verdict_t verdict;
	char* attribute;
	enum filter_t filter;
	char* string;
};

//bool parse_XYZ(int lengthOfXYZ, uint32_t* dataXYZ);
//default policy is to pass everything unknown || BLACKLIST
int callback(struct nfq_q_handle *qh_,struct nfgenmsg* nfmsg, struct nfq_data *nfa, void* customData);

bool parse_ipv4(int length,uint32_t* data);
bool parse_udp(int length,uint32_t* data);
bool parse_sap(int length,uint32_t* data);
bool parse_sdp(int length,uint32_t* data);

bool check_attribute(char*);
bool str_begins_with(const char* string, const char* prefix);
bool str_ends_with(const char* string, const char* suffix);


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

bool str_begins_with(const char* string, const char* prefix){
//	printf("String: %s Prefix: %s",string,prefix);
	while(*prefix){
		if(*prefix++ != *string++){
//			printf(" does not contain\n");
			return false;
		}
	}
//	printf(" does contain\n");
	return true;
}

bool str_ends_with(const char* string, const char* suffix){
	return strcmp(string + (strlen(string) - strlen(suffix)),suffix);
}

bool str_contains(const char* string, const char* infix){
	bool contains = false;;
	for(int i = 0;i < strlen(string);i++){
		if(str_begins_with(string+i,infix)){
			contains = true;
			break;
		}
	}
	return contains;
}

bool check_attribute(char* attribute){
	//{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Turme-"}, 
	// verdict attribute filter string	
	struct rule_t rules[RULESC] = {
		RULES
	};
	
	bool verdict = BLACKLIST;//Default policy

	for(int i = 0; i < RULESC; i++){
		if(!str_begins_with(attribute,rules[i].attribute)) continue;//Not the attribute we have to check
		char* attrValue = attribute + strlen(rules[i].attribute);
		switch(rules[i].filter){
			case IS:
				if(strcmp(attrValue,rules[i].string) == 0){
					verdict = rules[i].verdict;
				}
				break;
			case BEGINS_WITH:
				if(str_begins_with(attrValue,rules[i].string)){
					verdict = rules[i].verdict;
				}
				break;
			case ENDS_WITH:
				if(str_ends_with(attrValue,rules[i].string)){
					verdict = rules[i].verdict;
				}
				break;
			case CONTAINS:
				if(str_contains(attrValue,rules[i].string) == 0){
					verdict = rules[i].verdict;
				}
				break;
		}
	}

	return verdict;
}

bool parse_sdp(int length, uint32_t* data){//Parse SDP
	DBG("Length sdp:%d\n",length);
	int attrc = 0;
	char* attributes[50];//to be safe
	attributes[0] = (char*) data;//we have at least 5	
	
	int remLength = length;
	while(remLength--){
		if(((char*)data)[length-remLength] == 0x0A){
			((char*)data)[length-remLength] = 0x00;
			attrc++;
			attributes[attrc] = (char*)data + (length-remLength) + 1;
		}
		if(((char*)data)[length-remLength] == 0x0D){//some only have 0x0a
			((char*)data)[length-remLength] = 0x00;
		}
	}

	DBG("SDP Packet with %d attributes:\n\n",attrc);


	for(int i = 0; i < attrc;i++){
		DBG("\tAttribute: %s\n",attributes[i]);
		bool verdict = check_attribute(attributes[i]);
		if(BLACKLIST && !verdict){
			return false;
		} else if(!BLACKLIST && verdict){
			return true;
		}
	}	
	DBG("\n\n\n");
	

	return BLACKLIST;//Default policy
}

bool parse_sap(int length, uint32_t* data){//Parse SAP, false for an unaccepted annoucement, true for everything else (including parsing errors)
	DBG("Length sap:%d\n",length);
	struct saphdr* header = (struct saphdr*)data;
	if(header->version != 1){
		fprintf(stderr,"Version 0x%x unsuported!\n",header->version);
		return true;
	}

	if(header->type == 1) return true;

	data = (uint32_t*)(((unsigned long)data) + 8 + 4*(header->encrypted) + 4*(header->auth_len)); 
	length -= (8 +4*(header->encrypted) + 4*(header->auth_len));
	DBG("Length sap without flags:%d\n",length);
	if(((char*)(data))[1] != '='){//got MIME-Type/payloadType 
		length -= (strlen((char*)data) + 1);
		data = (uint32_t*)((unsigned long)data + strlen((char*)data) + 1);
		DBG("Length sap without mime:%d\n",length);
	}
	
	return parse_sdp(length,data);
}	

bool parse_udp(int length, uint32_t* data){//Parse udp header, false for an unaccepted announcement, true for everything else (including wrong port) 
	DBG("Length udp:%d\n",length);
	struct udphdr* header = (struct udphdr*)data;
	if(ntohs(header->dest) != 9875){//destionation port
		fprintf(stderr,"Port is not 9875 but %d!\n",ntohs(header->dest));
		return true;
	}
	//Again ignoring checksum	
	return parse_sap(length-8,data+2);
}

bool parse_ipv4(int length, uint32_t* data){//parse ipv4 header, false for an unaccepted announcement, true for everything else (including wrong protocol)
	DBG("Length ipv4:%d\n",length);
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
	DBG("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	DBG("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	DBG("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	DBG("binding this socket to queue '42'\n");
	qh = nfq_create_queue(h,  42, &callback, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	DBG("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	
	fd = nfq_fd(h);
}
