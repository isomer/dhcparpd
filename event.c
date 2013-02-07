/* select() event loop */
#include <sys/select.h>
#include <assert.h>
#include <stdlib.h>
#include "event.h"

static fd_set rfd,wfd,xfd;
static struct fdcb_t **events;
static int maxfd=-1;
bool running;

int init_event()
{
	FD_ZERO(&rfd);
	FD_ZERO(&wfd);
	FD_ZERO(&xfd);
	events=NULL;
	maxfd=-1;
	running=true;
	return 1;
}

void add_event(struct fdcb_t *evcb)
{
	assert(evcb->fd>=0);
	assert(evcb->fd>=maxfd || events[evcb->fd]==NULL); /* can't add twice*/
	
	if (evcb->fd>maxfd) {
		events=realloc(events,sizeof(struct fdcb_t)*(evcb->fd+1));
		/* FIXME: Deal with OOM */
		while(maxfd<evcb->fd) {
			events[++maxfd]=NULL;
		}
		maxfd=evcb->fd;
	}
	events[evcb->fd]=evcb;
	if (evcb->flags & EV_READ)   FD_SET(evcb->fd,&rfd);
	if (evcb->flags & EV_WRITE)  FD_SET(evcb->fd,&wfd);
	if (evcb->flags & EV_EXCEPT) FD_SET(evcb->fd,&xfd);
}

void del_event(struct fdcb_t *evcb)
{
	assert(evcb->fd>=0);
	assert(evcb->fd<maxfd && events[evcb->fd]!=NULL);
	events[evcb->fd]=NULL;
	if (evcb->flags & EV_READ)   FD_SET(evcb->fd,&rfd);
	if (evcb->flags & EV_WRITE)  FD_SET(evcb->fd,&wfd);
	if (evcb->flags & EV_EXCEPT) FD_SET(evcb->fd,&xfd);
}

void run()
{
	while (running) {
		fd_set xrfd = rfd;
		fd_set xwfd = wfd;
		fd_set xxfd = xfd;
		int fd;
		select(maxfd+1,&xrfd,&xwfd,&xxfd,NULL);
		/* TODO: check select's return */
		for(fd=0;fd<=maxfd;++fd) {
			/* Skip fd's we don't have events for */
			if (!events[fd])
				continue;
			assert(events[fd]->fd==fd);
			/* This code makes me feel dirty */
			if ((events[fd]->flags & EV_READ) 
					&& FD_ISSET(fd,&xrfd))
				events[fd]->callback(events[fd],EV_READ);
			if ((events[fd]->flags & EV_WRITE) 
					&& FD_ISSET(fd,&xwfd))
				events[fd]->callback(events[fd],EV_WRITE);
			if ((events[fd]->flags & EV_EXCEPT) 
					&& FD_ISSET(fd,&xxfd))
				events[fd]->callback(events[fd],EV_EXCEPT);
		}
	}
}
