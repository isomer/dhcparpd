CFLAGS=-g -Wall -W -fPIC -I/usr/include/python2.4
LDLIBS=-ldhcpctl -lomapi -ldst
DESTDIR?=/
SHELL=sh -e
REV := $(shell for i in *; do svn info $$i | grep "Changed Rev:" | awk '{print $$4}'; done | sort -rn | head -n1)
PWD := $(shell basename `pwd`)

all: shared
	python2.4 /usr/lib/python2.4/compileall.py .

shared: omapi_wrap.o base64.o
	gcc -shared omapi_wrap.o base64.o $(LDLIBS) -o _omapi.so

install: all
	python2.4 setup.py install --root $(DESTDIR)
	
omapi_wrap.c: omapi.i
	swig -python omapi.i

clean:
	rm -f *.so *.pyc *.o omapi_wrap.c omapi.py
	python2.4 setup.py clean
	rm -rf build
	
release: clean
	tar -C .. -cjf ../pyomapi-r$(REV).tar.bz2 --exclude=CVS \
		--exclude=.svn --exclude=debian $(PWD)
	tar -C .. -czf ../pyomapi-r$(REV).tar.gz --exclude=CVS \
		--exclude=.svn --exclude=debian $(PWD)

