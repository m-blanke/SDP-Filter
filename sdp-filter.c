#include "sdp-filter.h"
#include "config.h"

int main(int argc, char** argv){
	init();
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h,buf,rv);
	}
	end();
	return 0;
}

bool check_attribute(char* attribute){
	//{ALLOW,"a=x-plgroup:",BEGINS_WITH,"Turme-"}, 
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
