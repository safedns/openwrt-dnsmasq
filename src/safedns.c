// for my_syslog()
#include "dnsmasq.h"
#include "safedns.h"

#include <uci.h>
#include <stdio.h>
#include <inttypes.h>


#define CONFIG_FILENAME     "safedns"
#define CONFIG_SECTION_MAIN "safedns"

#define MAX_mac2token_count 1000


uint8_t  SAFEDNS_enabled;
uint32_t default_token;
uint16_t proxy_port;

struct
{
	uint64_t mac;
	uint32_t token;
}   mac2token_table[MAX_mac2token_count];
int mac2token_count = 0;





static void load_enabled(struct uci_context *c);
static void load_default_token(struct uci_context *c);
static void load_proxy_port(struct uci_context *c);
static void load_mac2token(struct uci_context *c);

void SAFEDNS_load_config()
{
	struct uci_context *c = uci_alloc_context();

	load_enabled(c);
	load_default_token(c);
	load_proxy_port(c);
	load_mac2token(c);

	uci_free_context(c);
}

// sizeof() * CHAR_BIT
static void load_enabled(struct uci_context *c)
{
	SAFEDNS_enabled = 0;

	struct uci_ptr data;
	char str[] = CONFIG_FILENAME"."CONFIG_SECTION_MAIN".enabled";
	if(uci_lookup_ptr(c, &data, str, false) != UCI_OK)
		my_syslog(LOG_INFO, "can't read 'enabled'");
	else if(data.o && data.o->v.string)
		sscanf(data.o->v.string, "%"SCNu8, &SAFEDNS_enabled);

	#ifdef SAFEDNS_log
	my_syslog(LOG_INFO, "'enabled' = %"PRIu8, SAFEDNS_enabled);
	#endif // SAFEDNS_log
}

static void load_default_token(struct uci_context *c)
{
	default_token = 0;

	struct uci_ptr data;
	char str[] = CONFIG_FILENAME"."CONFIG_SECTION_MAIN".default_token";
	if(uci_lookup_ptr(c, &data, str, false) != UCI_OK)
		my_syslog(LOG_INFO, "can't read 'default_token'");
	else if(data.o && data.o->v.string)
		sscanf(data.o->v.string, "%"SCNu32, &default_token);

	#ifdef SAFEDNS_log
	my_syslog(LOG_INFO, "'default_token' = %"PRIu32, default_token);
	#endif // SAFEDNS_log
}

static void load_proxy_port(struct uci_context *c)
{
	proxy_port = 1253;

	struct uci_ptr data;
	char str[] = CONFIG_FILENAME"."CONFIG_SECTION_MAIN".proxy_port";
	if(uci_lookup_ptr(c, &data, str, false) != UCI_OK)
		my_syslog(LOG_INFO, "can't read 'proxy_port'");
	else if(data.o && data.o->v.string)
		sscanf(data.o->v.string, "%"SCNu16, &proxy_port);

	#ifdef SAFEDNS_log
	my_syslog(LOG_INFO, "'proxy_port' = %"PRIu16, proxy_port);
	#endif // SAFEDNS_log
}

static void load_mac2token(struct uci_context *c)
{
	mac2token_count = 0;

	int i;
	for(i = 0; i < MAX_mac2token_count; ++i)
	{
		struct uci_ptr data;
		char str[200];
		sprintf(str, CONFIG_FILENAME".@mac2token[%d]", i);

		if(uci_lookup_ptr(c, &data, str, true) != UCI_OK || data.s == NULL)
			break;

		struct uci_ptr mac, token;
		char str_mac[200], str_token[200];
		sprintf(str_mac,   CONFIG_FILENAME".@mac2token[%d].mac",   i);
		sprintf(str_token, CONFIG_FILENAME".@mac2token[%d].token", i);

		if(uci_lookup_ptr(c, &mac,   str_mac,   true) != UCI_OK ||   mac.o == NULL ||   mac.o->v.string == NULL
		|| uci_lookup_ptr(c, &token, str_token, true) != UCI_OK || token.o == NULL || token.o->v.string == NULL
		)
			continue;

		uint8_t mac_bytes[6];
		if(6 == sscanf(mac.o->v.string, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
		               &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5])
		&& 1 == sscanf(token.o->v.string, "%"SCNu32, &mac2token_table[mac2token_count].token)
		)
			mac2token_table[mac2token_count++].mac = ((uint64_t)mac_bytes[0]<<40) | ((uint64_t)mac_bytes[1]<<32)
			                                       | ((uint64_t)mac_bytes[2]<<24) | ((uint64_t)mac_bytes[3]<<16)
			                                       | ((uint64_t)mac_bytes[4]<<8)  |  (uint64_t)mac_bytes[5];
	}

	#ifdef SAFEDNS_log
	my_syslog(LOG_INFO, "mac2token_count = %d", mac2token_count);
	#endif // SAFEDNS_log
}





static uint64_t ip2mac(uint32_t ip);
static uint32_t mac2token(uint64_t mac);
static size_t change_packet(uint8_t *packet, size_t packet_len, uint32_t token);

size_t SAFEDNS_change_packet_and_port(char *proto_str, uint32_t ip, uint8_t *packet, size_t packet_len, unsigned short *port)
{
	if((ip>>24) == 127)
	{
		*port = htons(53);
		#ifdef SAFEDNS_log
		my_syslog(LOG_INFO, "%s [127.x.x.x] -> don't change packet", proto_str);
		#endif // SAFEDNS_log
		return packet_len;
	}

	uint64_t mac   = ip2mac(ip);
	uint32_t token = mac2token(mac);
	#ifdef SAFEDNS_log
	my_syslog(LOG_INFO, "%s [%d.%d.%d.%d]->[%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8"]->[token=%d]",
	          proto_str,
	          (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF,
	          (int)(mac>>40)&0xFF, (int)(mac>>32)&0xFF, (int)(mac>>24)&0xFF, (int)(mac>>16)&0xFF, (int)(mac>>8)&0xFF, (int)mac&0xFF,
	          token);
	#endif // SAFEDNS_log

	if(token)
	{
		packet_len = change_packet(packet, packet_len, token);
		*port = htons(proxy_port);
	}

	return packet_len;
}

static uint64_t ip2mac(uint32_t ip)
{
	FILE *fp = fopen("/proc/net/arp", "rt");
	if(fp == NULL)
	{
		#ifdef SAFEDNS_log
		my_syslog(LOG_INFO, "can't read arp-table");
		#endif // SAFEDNS_log
		return 0;
	}

	uint64_t mac = 0;
	char line[100];
	while(fgets(line, sizeof(line), fp) != NULL)
	{
		uint8_t  ip_bytes[4];
		uint8_t mac_bytes[6];
		if(4 + 6 == sscanf(line, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8" %*s %*s " \
								 "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
							&ip_bytes[0],  &ip_bytes[1],  &ip_bytes[2],  &ip_bytes[3],
						   &mac_bytes[0], &mac_bytes[1], &mac_bytes[2], &mac_bytes[3], &mac_bytes[4], &mac_bytes[5])
		)
		{
			uint32_t scanned_ip = (ip_bytes[0]<<24) | (ip_bytes[1]<<16) | (ip_bytes[2]<<8) | ip_bytes[3];
			if(ip == scanned_ip)
			{
				mac = ((uint64_t)mac_bytes[0]<<40) | ((uint64_t)mac_bytes[1]<<32)
					| ((uint64_t)mac_bytes[2]<<24) | ((uint64_t)mac_bytes[3]<<16)
					| ((uint64_t)mac_bytes[4]<<8)  |  (uint64_t)mac_bytes[5];
				break;
			}
		}
	}

	fclose(fp);
	return mac;
}

static uint32_t mac2token(uint64_t mac)
{
	int i;
	if(mac != 0)
		for(i = 0; i < mac2token_count; ++i)
			if(mac2token_table[i].mac == mac)
				return mac2token_table[i].token;
	return default_token;
}

static size_t change_packet(uint8_t *packet, size_t packet_len, uint32_t token)
{
//	packet[11] = 1;
	((struct dns_header *)packet)->arcount = htons(1);

	uint8_t        *limit = NULL;	//packet + PACKETSZ;
	uint8_t *after_packet = packet + packet_len;

	char *name = NULL;
	unsigned short type  = 0xFFED;
	unsigned short class = 0x0001;
	unsigned long  ttl   = 0;

	add_resource_record(NULL, limit, NULL, 0, &after_packet, ttl, NULL, type, class, "l", name, token);
	return after_packet - packet;
/*
	char tail[] = {
		0x00,                   // name
		0xFF, 0xED,             // Type
		0x00, 0x01,             // Class
		0x00, 0x00, 0x00, 0x00, // TTL
		0x00, 0x04,             // RDLEN
		(token>>24) & 0xFF,     // RDATA
		(token>>16) & 0xFF,     //
		(token>> 8) & 0xFF,     //
		(token>> 0) & 0xFF      //
	};
*/
//	size_t tail_len = sizeof(tail);
//	memcpy(packet + packet_len, tail, tail_len);
//	return packet_len + tail_len;
//	return resize_packet((struct dns_header *)packet, packet_len, tail, sizeof(tail));
}
