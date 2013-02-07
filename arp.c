/*    arp processing module
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
#define _GNU_SOURCE
#include "arp.h"
#include <stdint.h>
#include <assert.h>
#include "dhcp.h"
#include "dhcparpd.h"
#include <netinet/in.h>
#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <libnet.h>
#include <stdarg.h>
#include <time.h>

enum arp_op_t {
	ARP_REQUEST=1,
	ARP_REPLY=2,
	ARP_RREQUEST=3,
	ARP_RREPLY=4,
	ARP_InREQUEST=8,
	ARP_InREPLY=9,
	ARP_NAK=10
};


__attribute__((packed))
struct arp_ether_t {
	struct ether_addr_t dest;	/*  6    */
	struct ether_addr_t src;	/*  6 12 */
	uint16_t type;			/*  2 14 */
	uint16_t hwtype;		/*  2 16 */
	uint16_t prototype;		/*  2 18 */
	uint8_t hwlen;			/*  1 19 */
	uint8_t protolen;		/*  1 20 */
	uint16_t opcode;
	struct ether_addr_t hwsrc;
	struct proto_addr_t protosrc;
	struct ether_addr_t hwdest;
	struct proto_addr_t protodest;
};

dhcpctl_handle conn=NULL;
libnet_t *ctx;

static void arp_log(const struct arp_ether_t *arp,const char *msg, ...)
{
	char *buffer=NULL;
	char *buffer2=NULL;
	va_list va;
	char macstr[20];
	char ipstr[20];

	va_start(va,msg);

	vasprintf(&buffer,msg,va);

	if (arp) { 
		ether_ntoa_r((struct ether_addr*)&arp->src,macstr);
		inet_ntop(AF_INET,&arp->protosrc,ipstr,sizeof(ipstr));
	}
	else {
		strcpy(macstr,"?");
		strcpy(ipstr,"?");
	}
	asprintf(&buffer2,"%s/%s: %s",macstr,ipstr,buffer);

        Log(LOG_INFO, buffer2);
	free(buffer);
	free(buffer2);

	va_end(va);

}

void arp_init(const char *interface, dhcpctl_handle hdl)
{
	char errbuf[LIBNET_ERRBUF_SIZE];

	conn=hdl;

	ctx = libnet_init(LIBNET_LINK_ADV, interface, errbuf);

	return; 
}

void arp_process(const char *data,unsigned int len)
{
	struct arp_ether_t *arp=(struct arp_ether_t*)data;
	struct arp_ether_t reply;
	struct ether_addr_t mac;

	assert(data);
	assert(len<65535);
	/* Can't be an arp */
	if (len<sizeof(struct arp_ether_t)) {
		/*
		arp_log(NULL,
			"too small (%u/%lu)",len,sizeof(struct arp_ether_t));
		*/
		return;
	}

	/* Wrong type for arp */
	if (arp->type != htons(0x0806))  {
		return;
	}

	/* Only do ethernet */
	if (arp->hwtype != htons(0x0001)) {
		arp_log(arp,"Unknown hwtype: %04x",htons(arp->hwtype));
		return;
	}

	/* Only do IPv4 */
	if (arp->prototype != htons(0x0800)) {
		arp_log(arp,"Unknown prototype: %04x",htons(arp->prototype));
		return;
	}

	/* Ethernet's hardware length is 6 */
	if (arp->hwlen!=6) {
		arp_log(arp,"Invalid hwlen: %i (should be %i)",
				arp->hwlen, 6);
		return;
	}
	
	/* IP's protocol length is 4! */
	if (arp->protolen!=4) {
		arp_log(arp,"Invalid protolen: %i (should be %i)",
				arp->protolen, 4);
		return;
	}

	/* Check to see if the source mac and the hwsrc are the same */
	if (arp->src.addr[0] != arp->hwsrc.addr[0]
	  ||arp->src.addr[1] != arp->hwsrc.addr[1]
	  ||arp->src.addr[2] != arp->hwsrc.addr[2]
	  ||arp->src.addr[3] != arp->hwsrc.addr[3]
	  ||arp->src.addr[4] != arp->hwsrc.addr[4]
	  ||arp->src.addr[5] != arp->hwsrc.addr[5]) {
		arp_log(arp,"hwsrc does not match (%s)",
				ether_ntoa((struct ether_addr *)&reply.hwsrc));
	}

	/* Now figure out how to answer this arp */
	switch(htons(arp->opcode)) {
		/* Arp request! Look up their MAC in the DHCP tables
		 * and send back the reply
		 */
		case ARP_REQUEST:

			reply.dest = arp->src;
			reply.type = arp->type;

			reply.hwtype = arp->hwtype;
			reply.prototype = arp->prototype;
			reply.hwlen = arp->hwlen;
			reply.protolen = arp->protolen;
			reply.opcode = htons(ARP_REPLY);

			reply.protosrc = arp->protodest;

			reply.hwdest = arp->hwsrc;
			reply.protodest = arp->protosrc;
			
			if (!lookup_ip( *(uint32_t*)&arp->protodest,&reply.hwsrc)) {
				arp_log(arp,"? => %s",
					inet_ntoa(*(struct in_addr *)&reply.protosrc));
				return;
			}

			/* ignore hosts with 00:00:00:00:00 */
			if (reply.hwsrc.addr[0] == 0 
				&& reply.hwsrc.addr[1] == 0
				&& reply.hwsrc.addr[2] == 0
				&& reply.hwsrc.addr[3] == 0
				&& reply.hwsrc.addr[4] == 0
				&& reply.hwsrc.addr[5] == 0)
				return;

			if (spoof_source) {
				reply.src = reply.hwsrc;
			} else {
				memcpy(&reply.src,libnet_get_hwaddr(ctx),sizeof(reply.src));
			}

			if (memcmp(&reply.dest,&reply.hwsrc,sizeof(reply.src))==0) {
			/*	arp_log(arp,"%s DAD",
					inet_ntoa(*(struct in_addr *)&reply.protosrc));
			*/
				/* DON'T SEND THE REPLY! */
				break;
			}
			else { /*
				arp_log(arp,"%s => %s",
						ether_ntoa((struct ether_addr *)&reply.src),
						inet_ntoa(*(struct in_addr *)&reply.protosrc));
				*/
			}
			if (sendarp) { 
				if (-1==libnet_adv_write_link(ctx,&reply,sizeof(reply))){
					Log(LOG_ERR, "failed to write: %s",
							libnet_geterror(ctx));
				}
			}
			
			break;

		/* We can ignore these */
		case ARP_REPLY:
			/* Check the source of the arp */
			if (!lookup_ip( *(uint32_t*)&arp->protosrc, &mac)){
				arp_log(arp,"Arp reply from unknown host %s/%s",
					ether_ntoa((struct ether_addr*)&arp->src),
					inet_ntoa(*(struct in_addr*)&arp->protosrc)
					);
				return;
			} 
			/* ignore hosts with 00:00:00:00:00 */
			if (mac.addr[0] == 0 
				&& mac.addr[1] == 0
				&& mac.addr[2] == 0
				&& mac.addr[3] == 0
				&& mac.addr[4] == 0
				&& mac.addr[5] == 0)
				return;
			if (memcmp(&mac,&arp->hwsrc,sizeof(mac))!=0) {
				arp_log(arp,"*** FORGED ARP REPLY *** %s",
					ether_ntoa((struct ether_addr*)&mac)
					);
				return;
			} 
			if (memcmp(&arp->hwsrc,&arp->src,sizeof(arp->src))!=0) {
				arp_log(arp,"Correct reply from wrong source %s",
						ether_ntoa((struct ether_addr*)&mac));
				return;
			} 

			/* Check the destination of the arp */
			if (!lookup_ip( *(uint32_t*)&arp->protodest,&mac)){
				arp_log(arp,"Reply to unknown destination %s",
					ether_ntoa((struct ether_addr*)&arp->hwdest));
				return;
			} 
			/* ignore hosts with 00:00:00:00:00 */
			if (mac.addr[0] == 0 
				&& mac.addr[1] == 0
				&& mac.addr[2] == 0
				&& mac.addr[3] == 0
				&& mac.addr[4] == 0
				&& mac.addr[5] == 0)
				return;
			if (memcmp(&mac,&arp->hwdest,sizeof(mac))!=0) {
				arp_log(arp,"Reply to wrong destination %s (%s != %s)",
					inet_ntoa(*(struct in_addr*)&arp->protodest),
					ether_ntoa((struct ether_addr*)&arp->hwdest),
					ether_ntoa((struct ether_addr*)&mac));
				return;
			}
			/*
			arp_log(arp,"Valid Arp reply");
			*/
			return;

		/* Dunno/don't care what this is, ignore it */
		default:
			arp_log(arp,"Unknown opcode: %04x",htons(arp->opcode));
			return;
	}

	return;
}
