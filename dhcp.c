/*    DHCP omapi interface
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
#include "dhcp.h"
#include "dhcparpd.h"
#include <stdlib.h>
#include <stdarg.h>
#include <dhcpctl.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include <isc-dhcp/result.h>

static dhcpctl_handle conn;

typedef unsigned char uchar_t;

void base64_decode(const uchar_t *in, uchar_t **out, int *outlen);

static void dhcpctl_error(const char *msg, isc_result_t result)
{
	Log(LOG_CRIT, "%s: %s\n",msg,isc_result_totext(result));
	exit(1);
}

static dhcpctl_handle dhcpd_connect_with_auth( const char *hostname, int port,
			const char* username, const unsigned char *key)
{
	dhcpctl_handle auth = NULL;
	unsigned char *keydata = NULL;
	int keylen = 0;
	dhcpctl_status status;

	/* Set authentication */
	base64_decode(key,&keydata,&keylen);

	if ((status = dhcpctl_new_authenticator(&auth, username, "hmac-md5",
					keydata, keylen))) 
		dhcpctl_error("Can't load authentication information",status);

	/* Connect */
	if ((status = dhcpctl_connect (&conn, hostname, port, auth)))
		dhcpctl_error ("Can't connect to dhcp server with auth",
				status);
	else
		Log(LOG_NOTICE, "Connected to server with auth\n");
	return conn;
}

/* Connect to (and authenticate with) the dhcp server */
dhcpctl_handle dhcpd_connect(const char *hostname, int port,
		const char* username, const unsigned char *key)
{
	dhcpctl_handle conn;
	dhcpctl_status status;

	status = dhcpctl_initialize();
	omapi_init();

	if (key) {
		conn = dhcpd_connect_with_auth(hostname,port,username,key);
	} else {
		if ((status = dhcpctl_connect (&conn, hostname, port, 
						dhcpctl_null_handle)))
			dhcpctl_error ("Can't connect to dhcp server",
					status);
		else
			Log(LOG_INFO, "Connected to server without auth\n");
	}

	return conn;
}

int lookup_ip(uint32_t ip, struct ether_addr_t *addr)
{
	dhcpctl_status status;
	dhcpctl_status status2;
	dhcpctl_handle hp = NULL;
	dhcpctl_data_string result = NULL;
	dhcpctl_data_string ds = NULL;

	if ((status = dhcpctl_new_object(&hp, conn, "lease")))
		dhcpctl_error("lease create failed", status);

	omapi_data_string_new(&ds, sizeof(ip), __FILE__, __LINE__);
	memcpy(ds->value,&ip,sizeof(ip));
	
	if ((status = dhcpctl_set_value(hp, ds, "ip-address")))
		dhcpctl_error("Failed to set ip-address",status);

	if ((status = dhcpctl_open_object(hp, conn, 0)))
		dhcpctl_error("Failed to refresh query",status);

	if ((status = dhcpctl_wait_for_completion(hp, &status2)))
		dhcpctl_error("Completion failed",status);

	if (status2) {
		int i;
		omapi_object_dereference(&hp,__FILE__,__LINE__);
		for (i=0;i<internal_mappings;++i) {
			if (memcmp(&ip,&internal_mapping[i].ip,sizeof(ip))==0){
				*addr=internal_mapping[i].ether;
				return 1;
			}
		}
		return 0;
	}

	if ((status = dhcpctl_get_value(&result, hp, "hardware-address"))) {
		omapi_object_dereference(&hp,__FILE__,__LINE__);
		return 0;
	}

	memcpy(addr,result->value,sizeof(*addr));

	omapi_object_dereference(&hp,__FILE__,__LINE__);

	return 1;
}

