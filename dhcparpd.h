#ifndef DHCPARPD_H
#define DHCPARPD_H 1
#include <syslog.h>
#include <stdbool.h>
#include "libconfig.h"
#include "dhcp.h"

struct mapping_t {
	struct ether_addr_t ether;
	struct proto_addr_t ip;
};

extern struct mapping_t *internal_mapping;
extern int internal_mappings;
extern bool spoof_source;
extern bool sendarp;

void Log(int prio, char *format, ...);

#endif
