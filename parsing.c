#include "sdp-filter.h"
#include "config.h"

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

