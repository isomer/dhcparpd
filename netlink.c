#include "netlink.h"
#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <netinet/in.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "event.h"
#include "dhcp.h"

struct hrd_t {
	char len;
	char *hrd;
};

struct msgnames_t {
	int id;
	char *msg;
} typenames[] = {
#define MSG(x) { x, #x }
	MSG(RTM_NEWROUTE),
	MSG(RTM_DELROUTE),
	MSG(RTM_GETROUTE),
	MSG(RTM_NEWNEIGH),
	MSG(RTM_DELNEIGH),
	MSG(RTM_GETNEIGH),
#ifdef RTM_NEWPREFIX
	MSG(RTM_NEWPREFIX),
	MSG(RTM_GETPREFIX),
#endif
	MSG(RTM_NEWADDR),
	MSG(RTM_DELADDR),
	MSG(RTM_GETADDR),
#undef MSG
	{0,0}
};

struct msgnames_t familynames[] = {
#define MSG(x) { x, #x }
	MSG(AF_INET),
	MSG(AF_INET6),
#undef MSG
	{0,0}
};

struct msgnames_t attributetypenames[] = {
#define MSG(x) { x, #x }
	MSG(NDA_UNSPEC),
	MSG(NDA_DST),
	MSG(NDA_LLADDR),
	MSG(NDA_CACHEINFO),
#ifdef NDA_PROBES
	MSG(NDA_PROBES),
#else
	{4, "NDA_PROBES" },
#endif
#undef MSG
	{0,0}
};

char *lookup_name(struct msgnames_t *db,int id)
{
	static char name[512];
	struct msgnames_t *msgnamesiter;
	for(msgnamesiter=db;msgnamesiter->msg;++msgnamesiter) {
		if (msgnamesiter->id == id) {
			snprintf(name,sizeof(name),"%s (%i)",
					msgnamesiter->msg,
					id);
			return name;
		}
	}
	snprintf(name,sizeof(name),"#%i",id);
	return name;
}

static int sock;

static void netlink_dump(struct nlmsghdr *nlh,unsigned char *buffer,int len)
{
	struct ndmsg *ndmsg = (struct ndmsg *)buffer;
	struct rtattr *parse;
	len-=sizeof(struct ndmsg);

	printf("Type: %s\n",lookup_name(typenames,nlh->nlmsg_type));
	printf("Flag:");
#define FLAG(x) if (nlh->nlmsg_flags & x) printf(" %s",#x)
	FLAG(NLM_F_REQUEST);
	FLAG(NLM_F_MULTI);
	FLAG(NLM_F_ACK);
	FLAG(NLM_F_ECHO);
	FLAG(NLM_F_REPLACE);
	FLAG(NLM_F_EXCL);
	FLAG(NLM_F_CREATE);
	FLAG(NLM_F_APPEND);
#undef FLAG
	printf(" (%x)\n",nlh->nlmsg_flags);

	printf("Seq : %i\n",nlh->nlmsg_seq);
	printf("Pid : %i\n",nlh->nlmsg_pid);
	printf("- message:\n");
	printf("Type: %i\n",ndmsg->ndm_type);
	printf("Family: %s\n",lookup_name(familynames,ndmsg->ndm_family));
	printf("IF# : %i\n",ndmsg->ndm_ifindex);
	printf("State:");
#define FLAG(x) if (ndmsg->ndm_state & NUD_##x) printf(" %s",#x)
	FLAG(INCOMPLETE);
	FLAG(REACHABLE);
	FLAG(STALE);
	FLAG(DELAY);
	FLAG(PROBE);
	FLAG(FAILED);
	FLAG(NOARP);
	FLAG(PERMANENT);
#undef FLAG
	printf("(%02x)\n",ndmsg->ndm_state);

	printf("Flags:");
#define FLAG(x) if (ndmsg->ndm_flags & NTF_##x) printf(" %s",#x)
	FLAG(PROXY);
	FLAG(ROUTER);
#undef FLAG
	printf(" (%02x)\n",ndmsg->ndm_flags);
	printf("Type: %i\n",ndmsg->ndm_type);
	parse=(struct rtattr *)(buffer+sizeof(*ndmsg));

	while (RTA_OK(parse,len)) {
		unsigned int i;
		printf("%s:",lookup_name(attributetypenames,(parse)->rta_type));
		for(i=0;
			i<RTA_PAYLOAD(parse);
			++i) {
			printf(" %02x",((unsigned char*)RTA_DATA(parse))[i]);
			if (i%16==15)
				printf("\n");
		}
		if (i%16!=15) printf("\n");
		parse=RTA_NEXT(parse,len);
	}
}

typedef struct dst_tlv_t {
	unsigned short rta_len;
	unsigned short rta_type;
	char ip[4];
} dst_tlv_t;

typedef struct lladdr_tlv_t {
	unsigned short rta_len;
	unsigned short rta_type;
	char lladdr[6];
	char pad[2];
} lladdr_tlv_t;

typedef struct new_msg_t {
	struct nlmsghdr nlh;
	struct ndmsg ndmsg;
	dst_tlv_t dst;
	lladdr_tlv_t lladdr;
} __attribute__((packed)) new_msg_t;

static void netlink_getneigh(int fd,struct nlmsghdr *nlh,unsigned char *buffer,int len)
{
	struct ndmsg *ndmsg = (struct ndmsg *)buffer;
	struct new_msg_t newmsg;
	struct rtattr *parse;
	char ifname[64];
	char cmdline[256];
	parse=(struct rtattr *)(buffer+sizeof(*ndmsg));
	len-=sizeof(struct ndmsg);
	if (nlh->nlmsg_type != RTM_GETNEIGH) {
		printf("not get neigh?\n");
		return;
	}
	if (ndmsg->ndm_family != AF_INET) {
		printf("not ip!\n");
		return;
	}
	/* Find the NDA_DST */
	while (RTA_OK(parse,len)) {
		if (parse->rta_type==NDA_DST) {
			printf("found it\n");
			break;
		}
		parse=RTA_NEXT(parse,len);
	}
	/* couldn't find the NDA_DST? */
	if (!RTA_OK(parse,len) || parse->rta_type!=NDA_DST) {
		printf("can't find ip\n");
		return;
	}

	lookup_ip(*(uint32_t*)RTA_DATA(parse),(struct ether_addr_t*)&newmsg.lladdr.lladdr);

	if_indextoname(ndmsg->ndm_ifindex,ifname);
	snprintf(cmdline,sizeof(cmdline),"/sbin/ip neigh replace %i.%i.%i.%i"
			" lladdr %02x:%02X:%02x:%02x:%02x:%02x"
			" nud reachable"
			" dev %s",
			((unsigned char*)RTA_DATA(parse))[0],
			((unsigned char*)RTA_DATA(parse))[1],
			((unsigned char*)RTA_DATA(parse))[2],
			((unsigned char*)RTA_DATA(parse))[3],
			(unsigned char)newmsg.lladdr.lladdr[0], 
			(unsigned char)newmsg.lladdr.lladdr[1],
			(unsigned char)newmsg.lladdr.lladdr[2],
			(unsigned char)newmsg.lladdr.lladdr[3],
			(unsigned char)newmsg.lladdr.lladdr[4],
			(unsigned char)newmsg.lladdr.lladdr[5],
			ifname);
	//printf("# %s\n",cmdline);
	system(cmdline);
#if 0
	newmsg.ndmsg = *ndmsg;
	newmsg.ndmsg.ndm_state=NUD_PERMANENT;

	/* build the netlink header */
	newmsg.nlh.nlmsg_len=NLMSG_LENGTH(sizeof(newmsg));
	newmsg.nlh.nlmsg_type=RTM_NEWNEIGH;
	newmsg.nlh.nlmsg_flags=NLM_F_REQUEST|NLM_F_CREATE|NLM_F_EXCL;
	newmsg.nlh.nlmsg_seq=0;
	newmsg.nlh.nlmsg_pid=getpid();


	/* And the tlv's */
	memcpy(&newmsg.dst,parse,parse->rta_len);
	newmsg.lladdr.rta_type = NDA_LLADDR;
	newmsg.lladdr.rta_len=4+6;
	printf("looking up %08x\n",*(uint32_t*)RTA_DATA(parse));

	printf("%02x\n",newmsg.nlh.nlmsg_flags);
	netlink_dump(
			&newmsg.nlh,
			((char *)&newmsg)+sizeof(newmsg.nlh),
			sizeof(newmsg)-sizeof(newmsg.nlh));
	if (write(fd,&newmsg,sizeof(newmsg))==-1)
		printf("write(NETLINK) failed\n");
#endif
}

static void netlink_callback(struct fdcb_t *evcb,enum eventtype_t ev)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov[2];
	struct nlmsghdr nlh;
	unsigned char buffer[65536];
	int ret;
	iov[0].iov_base = (void *)&nlh;
	iov[0].iov_len = sizeof(nlh);
	iov[1].iov_base = (void *)buffer;
	iov[1].iov_len = sizeof(buffer);
	msg.msg_name = (void *)&(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = iov;
	msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);
	ret=recvmsg(evcb->fd, &msg, 0);
	if (ret<0) {
		perror("recvmsg(NETLINK)");
		return;
	}
	//netlink_dump(&nlh,buffer,ret-sizeof(nlh));
	netlink_getneigh(evcb->fd,&nlh,buffer,ret-sizeof(nlh));
}

static struct fdcb_t netlink_events;

int init_netlink()
{
	struct sockaddr_nl addr;
	sock = socket(AF_NETLINK,SOCK_DGRAM,NETLINK_ROUTE);
	if (sock<0)
		return sock;
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();
	addr.nl_groups = RTMGRP_NEIGH; 
	if (bind(sock,(struct sockaddr *)&addr,sizeof(addr))<0)
		return -1;
	netlink_events.fd = sock;
	netlink_events.flags = EV_READ;
	netlink_events.callback = netlink_callback;
	add_event(&netlink_events);
	return 1;
}

