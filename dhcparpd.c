/*    Main program
 *    Copyright (C) 2005  Perry Lorier
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include "dhcparpd.h"
#include "arp.h"
#include <libconfig.h>
#include "event.h"
#include "daemons.h"
#include "netlink.h"
#include <pcap.h>
#include <string.h>
#include <getopt.h>

struct mapping_t *internal_mapping;
int internal_mappings = 0;

char *interface = NULL;
char *servername = NULL;
char *key = NULL;
int port = 7911;
char *name = NULL;
conf_array_t mappings = { 0, 0 };
bool spoof_source = true;
char *pidfile = NULL;
int do_daemonise = 1;
bool sendarp = true; 
enum { 
	LOG_D_DEFAULT = 0,
	LOG_D_SYSLOG = 1, 
	LOG_D_STDOUT = 2
} logging_style;

config_t config[] = {
	{ "interface", 		TYPE_STR|TYPE_NOTNULL, &interface },
	{ "server", 		TYPE_STR|TYPE_NOTNULL, &servername },
        { "key",		TYPE_STR	     , &key },
        { "port",		TYPE_INT             , &port },
	{ "name",		TYPE_STR             , &name },
	{ "mapping",		TYPE_STR|TYPE_MULTI  , &mappings },
	{ "spoofsource",	TYPE_BOOL	     , &spoof_source },
        { "pidfile",            TYPE_STR             , &pidfile },
        { "daemonise",          TYPE_INT             , &do_daemonise },
	{ "log",		TYPE_INT	     , &logging_style },
	{ "sendarp",		TYPE_BOOL	     , &sendarp },
	{ NULL, 0, NULL }
};

void parse_mappings(void)
{
	int i;
	for(i=0;i<mappings.items;++i) {
		int m1,m2,m3,m4,m5,m6,i1,i2,i3,i4;
		struct ether_addr_t eth;
		struct proto_addr_t ip;
		int matches=sscanf(mappings.data[i].s,
				"%x:%x:%x:%x:%x:%x %i.%i.%i.%i",
				&m1,&m2,&m3,&m4,&m5,&m6,
				&i1,&i2,&i3,&i4);
		eth.addr[0]=m1; eth.addr[1]=m2; eth.addr[2]=m3;
		eth.addr[3]=m4; eth.addr[4]=m5; eth.addr[5]=m6;
		ip.addr[0]=i1; ip.addr[1]=i2; ip.addr[2]=i3; ip.addr[3]=i4;
		if (matches!=10) {
			Log(LOG_WARNING, "Failed to parse %s... ignoring",
					(char*)mappings.data[i].s);
			continue;
		}
		internal_mapping=realloc(internal_mapping,(internal_mappings+1)*sizeof(struct mapping_t));
		internal_mapping[internal_mappings].ether=eth;
		internal_mapping[internal_mappings].ip=ip;
		internal_mappings++;
	}
}

void Log(int prio,char *msg,...)
{
        va_list va;
        va_start(va,msg);
	if (logging_style==LOG_D_STDOUT 
			|| (!daemonised && logging_style == LOG_D_DEFAULT) ) {
		vprintf(msg,va);
		printf("\n");
	} else
		vsyslog(prio,msg,va);
        va_end(va);
}

/* pcap stuff */
static pcap_t *pcap;

void process_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes)
{
	arp_process(bytes,h->caplen);
}


void pcap_cb(struct fdcb_t *handle, enum eventtype_t ev)
{
	pcap_dispatch(pcap,1,process_packet,NULL);
}

struct fdcb_t pcap_fdcb;

int pcap_init(void *interface)
{
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap = pcap_open_live(interface,65536,1,0,errbuf);

	if (!pcap) {
		Log(LOG_CRIT, "can't sniff the interface: %s",errbuf);
		return 1;
	}

	pcap_fdcb.fd=pcap_get_selectable_fd(pcap);
	pcap_fdcb.flags=EV_READ;
	pcap_fdcb.callback=pcap_cb;

	add_event(&pcap_fdcb);
	

	return 0;
}

void usage(char *name)
{
	printf("Usage: %s [-c configfile] [-d] [-h]\n\n", name);
	printf("Spoofs arp replies learned via OMAPI from DHCP.\n\n");
	printf("Options:\t-d\tDon't daemonise\n");
	printf("        \t-h\tDisplay this help\n\n");
}

int main(int argc, char *argv[])
{
	dhcpctl_handle conn = NULL;
	char *conffile=NULL;
	char ch;
	
	name = strdup("OMAPI");
	    
	openlog("dhcparpd", LOG_PID, LOG_DAEMON);

	/* Parse Commandline Options */
	while((ch = getopt(argc, argv, "c:dh")) != -1) {
		switch(ch){
			case 'c':
				conffile = strdup(optarg);
				break;
			case 'd':
				do_daemonise=0;
				break;
			case 'h':
				usage(argv[0]);
				return 0;
			default:
				fprintf(stderr, "Unknown option '%c'!", ch);
				usage(argv[0]);
				return 1;
		}
	}

	/* Try a default configfile if non specified */
	if (conffile==NULL) {
		conffile = strdup("/etc/dhcparpd.conf");
	}
	if (parse_config(config,conffile)) {
		fprintf(stderr,"Unable to parse configfile: %s\n", 
				conffile);
		return 1;
	}
	free(conffile);

	/* Daemonise */
	if (do_daemonise) {
		daemonise(argv[0]);
		put_pid(pidfile);
	}
	
	parse_mappings();

	conn = dhcpd_connect(servername, port, name, key);

	if (!conn) {
		Log(LOG_CRIT, "failed to connect to dhcp server");
		return 1;
	}

	arp_init(interface,conn);

	init_event();
	init_netlink();

	if (pcap_init(interface))
		return 1;

        Log(LOG_NOTICE, "Ready for action! Lets Go...");
	run();

	return 0;
}
