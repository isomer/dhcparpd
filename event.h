#ifndef EVENT_H
#define EVENT_H
#include <stdbool.h>

enum eventtype_t { 
	EV_READ   = 1, 
	EV_WRITE  = 2, 
	EV_EXCEPT = 4
};


struct fdcb_t {
	int fd;
	int flags;
	void (*callback)(struct fdcb_t *handle, enum eventtype_t ev);
};

int init_event(void);
void add_event(struct fdcb_t *);
void del_event(struct fdcb_t *);
void run(void);

extern bool running;

#endif
