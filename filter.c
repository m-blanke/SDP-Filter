#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdbool.h>

void init();
void end();
struct nfq_handle* h;
struct nfq_q_handle* qh;
struct nfnl_handle* nh;
int fd;
int rv;
int callback(struct nfq_q_handle *qh_,struct nfgenmsg* nfmsg, struct nfq_data *nfa, void* data);
char buf[4096];

int main(int argc, char** argv){
	init();
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		printf("Got packet\n");
		nfq_handle_packet(h,buf,rv);
	}
	end();
	return 0;
}

//nfq_set_verdict(qh,packetID,NF_ACCEPT/NF_DROP,0,NULL);
int callback(struct nfq_q_handle *qh_,struct nfgenmsg* nfmsg, struct nfq_data* nfa, void* data){//gets calles by nfq_handle_packet
	int id = ntohl(nfq_get_msg_packet_hdr(nfa)->packet_id);


	return nfq_set_verdict(qh,id,NF_ACCEPT,0,NULL);
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

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &callback, NULL);
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
