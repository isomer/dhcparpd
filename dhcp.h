/*    DHCP omapi interface header file
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
#ifndef DHCP_H
#define DHCP_H 1
#include <stdlib.h>
#include <stdarg.h>
#include <dhcpctl.h>
#include <stdint.h>

enum { ETH_HW_LEN=6 };
enum { IP_PROTO_LEN=4 };

__attribute__((packed))
struct ether_addr_t {
	uint8_t addr[ETH_HW_LEN];
};

__attribute__((packed))
struct proto_addr_t {
	uint8_t addr[IP_PROTO_LEN];
};

/* Connect to (and authenticate with) the dhcp server */
dhcpctl_handle dhcpd_connect(const char *hostname, int port,
		const char* username, const unsigned char *key);

int lookup_ip(uint32_t ip, struct ether_addr_t *addr);

#endif
