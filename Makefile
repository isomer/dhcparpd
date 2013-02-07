CFLAGS=-g -Wall -W -DAUTH=1 -Ilibconfig 

LDLIBS=-ldhcpctl -lomapi -lpcap -ldst -lnet -lfl
SHELL=sh -e
REV := $(shell for i in *; do svn info $$i | grep "Changed Rev:" | awk '{print $$4}'; done | sort -rn | head -n1)
PWD := $(shell basename `pwd`)

all: dhcparpd

dhcparpd: dhcparpd.o base64.o dhcp.o arp.o daemons.o event.o \
		netlink.o \
		libconfig/.libs/libconfig.a 

libconfig/.libs/libconfig.a:
	cd libconfig && ./configure && cd ..
	$(MAKE) -C libconfig all

install:
	install -d -m 755 -o root -g root $(DESTDIR)/usr/sbin
	install -m 755 -o root -g root dhcparpd $(DESTDIR)/usr/sbin/dhcparpd
			
clean:
	rm -f dhcparpd *.o core
	-$(MAKE) -C libconfig clean
					
release: clean
	tar -C .. -cjf ../dhcparpd-r$(REV).tar.bz2 --exclude=CVS --exclude=.svn \
		--exclude=debian --exclude=autom4te.cache --exclude=pyomapi $(PWD)
	tar -C .. -czf ../dhcparpd-r$(REV).tar.gz --exclude=CVS --exclude=.svn \
		--exclude=debian --exclude=autom4te.cache --exclude=pyomapi $(PWD)
