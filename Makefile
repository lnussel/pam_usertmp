CPPFLAGS =
CFLAGS = -g3 -Wall -O0 -Werror-implicit-function-declaration -MD
LDLIBS = -lpam -lpam_misc
LIB = /lib

CPPFLAGS += -DHAVE_GCCVISIBILITY
CFLAGS += -fvisibility=hidden

VERSION=0.0
ifeq ($(wildcard .svn),.svn)
  SVN_VERSION=$(VERSION)_SVN$(shell LANG=C svnversion .)
else
  SVN_VERSION=$(VERSION)
endif

all: pam_usertmp.so

pam_usertmp.o: pam_usertmp.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -fPIC -c -o $@ $<

pam_usertmp.so: pam_usertmp.o
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -o $@ -fPIC -shared -Wl,-z,defs $? $(LDLIBS)

install: all
	install -d -m 755 $(DESTDIR)/etc/security
	install -d -m 755 $(DESTDIR)/etc/pam.d
	install -d -m 755 $(DESTDIR)$(LIB)/security
	#install -m 644 etc/pam.d/* $(DESTDIR)/etc/pam.d
	#install -m 644 etc/security/*.conf $(DESTDIR)/etc/security
	install -m 755 pam_usertmp.so $(DESTDIR)$(LIB)/security

clean:
	rm -f -- *.o *.d *.so* tags

-include *.d

dist:
	rm -rf pam_usertmp-$(SVN_VERSION)
	svn export . pam_usertmp-$(SVN_VERSION)
	tar --owner=root --group=root --force-local -cjf pam_usertmp-$(SVN_VERSION).tar.bz2 pam_usertmp-$(SVN_VERSION)
	rm -rf pam_usertmp-$(SVN_VERSION)

.PHONY: clean dist
