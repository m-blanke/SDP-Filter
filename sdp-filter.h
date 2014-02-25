#ifndef __SDP_FILTER_H__
#define __SDP_FILTER_H__
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
bool str_contains(const char* string, const char* infix);

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

#endif
